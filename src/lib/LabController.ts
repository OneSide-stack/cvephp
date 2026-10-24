import type { V86, V86Options } from "v86";
import type {
  AssetManifest,
  BuildObservation,
  EvidenceRecord,
  ExerciseFacts,
  ExerciseStepId,
  LabState,
  MachineId,
  ProbeObservation,
  ResourceMode,
  SessionInfo,
  SnapshotMeta,
  TargetAsset,
  Telemetry,
  TargetHealth,
  ViewId,
} from "../types";
import { initialState, NETWORK_CHECKS } from "./initialState";
import { loadManifest, loadVerifiedAsset } from "./assets";
import { SerialChannel, type CommandResult } from "./SerialChannel";
import {
  deleteSnapshot as deleteStoredSnapshot,
  getSnapshot,
  listSnapshots,
  saveProgress,
  loadProgress,
  clearProgress,
  saveSnapshot,
  type SnapshotRecord,
} from "./storage";
import { clampText, jsonFromOutput, parseKeyValues, randomToken, sha256Text } from "./utils";
import { ProxyAcceptanceRunner, evidenceRequest, parseProxyEvidence } from "./ProxyAcceptance";
import {
  ADVISORY,
  ADVISORY_GUIDANCE,
  PATCHED_RELEASES,
  PATCH_INI_MARKER,
  PINNED_SOURCES,
} from "./cve";
import {
  SIMULATION_QUESTIONS,
  assessBuild,
  validateReconFacts,
  classifyProbeOutcome,
  emptyExercise,
  evaluateExercise,
  validateGenuineCompletion,
  validateSimulationAnswer,
} from "./exercise";

interface LoadedImages {
  attacker: ArrayBuffer;
  target: ArrayBuffer;
  bios: ArrayBuffer;
  vgaBios: ArrayBuffer;
  wasm: ArrayBuffer;
}

interface MachineRuntime {
  emulator: V86;
  serial: SerialChannel;
}

// Package loading in the graphical TinyCore guest can exceed four minutes on
// a software-emulated CPU. Readiness still requires the real shell and checks.
const BOOT_TIMEOUT = 360_000;
// v86 uses net_device.id for both its BroadcastChannel and its internal bus
// topic. Its NE2000 device is net0, so only id=0 connects the two. Serialize
// access to that origin-scoped channel: concurrent labs must fail closed.
const INBROWSER_NETWORK_ID = "0";
const INBROWSER_LOCK = "enterprise-cyber-range-network-0";

const TARGET_PHP_RECON = `/usr/local/bin/php -r 'echo "version=",PHP_VERSION,"\\n","memory_limit=",ini_get("memory_limit"),"\\n","post_max_size=",ini_get("post_max_size"),"\\n","upload_max_filesize=",ini_get("upload_max_filesize"),"\\n","upload_progress=",(ini_get("session.upload_progress.enabled")?"1":"0"),"\\n","hard_limit=",(ini_get("memory_hard_limit_percent")===false?"absent":ini_get("memory_hard_limit_percent")),"\\n";'`;

function freshState(): LabState {
  return {
    ...initialState,
    machines: {
      attacker: { ...initialState.machines.attacker },
      target: { ...initialState.machines.target },
    },
    checks: NETWORK_CHECKS.map((check) => ({ ...check })),
    logs: { ...initialState.logs },
    evidence: [],
    activity: [...initialState.activity],
    snapshots: [],
    exercise: emptyExercise(),
    recovery: null,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class LabController {
  private state: LabState = freshState();
  private listeners = new Set<() => void>();
  private screens: Partial<Record<MachineId, HTMLElement>> = {};
  private runtime: Partial<Record<MachineId, MachineRuntime>> = {};
  private images: LoadedImages | null = null;
  private wasmUrl: string | null = null;
  private V86Class: typeof V86 | null = null;
  private generation = 0;
  // True only for a session whose target has provisioned (or restored) its
  // own flag. The plaintext flag is never retained by this controller.
  private sessionProvisioned = false;
  private networkLockRelease: (() => void) | null = null;
  private telemetryTimer: ReturnType<typeof setInterval> | null = null;
  private telemetryRunning = false;
  private targetSerialSealed = false;
  private serialListeners: Record<MachineId, Set<(text: string) => void>> = { attacker: new Set(), target: new Set() };

  constructor() {
    void this.initialize();
  }

  getState = (): LabState => this.state;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private emit(): void {
    for (const listener of this.listeners) listener();
  }

  private patch(value: Partial<LabState>): void {
    this.state = { ...this.state, ...value };
    this.emit();
  }

  private patchMachine(machine: MachineId, value: Partial<LabState["machines"][MachineId]>): void {
    this.patch({ machines: { ...this.state.machines, [machine]: { ...this.state.machines[machine], ...value } } });
  }

  private patchCheck(id: string, value: Partial<LabState["checks"][number]>): void {
    this.patch({ checks: this.state.checks.map((check) => check.id === id ? { ...check, ...value } : check) });
  }

  private log(message: string, level: LabState["activity"][number]["level"] = "info"): void {
    const line = { id: randomToken(6), timestamp: new Date().toISOString(), level, message };
    this.patch({ activity: [line, ...this.state.activity].slice(0, 100) });
  }

  private evidence(machine: MachineId, category: EvidenceRecord["category"], title: string, source: string, data: string): void {
    const record: EvidenceRecord = {
      id: `${category}-${randomToken(8)}`,
      timestamp: new Date().toISOString(),
      category,
      title,
      source,
      machine,
      data: clampText(data, 1_200_000),
      genuine: true,
    };
    this.patch({ evidence: [record, ...this.state.evidence].slice(0, 500), hasUnsavedProgress: true });
  }

  private async initialize(): Promise<void> {
    try {
      const snapshots = await listSnapshots();
      this.patch({ snapshots });
    } catch (error) {
      this.patch({ notice: `Browser-local snapshot index is unavailable: ${error instanceof Error ? error.message : String(error)}` });
    }
    try {
      const manifest = await loadManifest();
      this.patch({ manifest });
    } catch {
      // Startup presents the descriptive manifest error. The interface remains
      // usable for reading the guide and previously recorded report data.
    }
    try {
      const report = await loadProgress<{ session: SessionInfo; evidence: EvidenceRecord[]; checks: LabState["checks"]; exercise?: ExerciseFacts; completedAs: LabState["completedAs"] } | null>("last-report");
      if (report && report.session && Array.isArray(report.evidence) && Array.isArray(report.checks)) {
        this.patch({
          session: report.session,
          evidence: report.evidence,
          checks: report.checks,
          exercise: report.exercise ?? emptyExercise(),
          completedAs: report.completedAs ?? null,
          hasUnsavedProgress: false,
        });
      }
    } catch {
      // A corrupt or unavailable historical report must not prevent asset
      // preflight, a new lab, or access to explicitly saved VM snapshots.
    }
  }

  setView = (view: ViewId): void => {
    this.patch({ view });
    if (view === "attacker" || view === "target") this.focusMachine(view);
    else this.focusMachine(null);
    if (view === "target" && ["ready", "testing", "completed"].includes(this.state.status)) void this.refreshTarget(true);
  };

  setResourceMode = (resourceMode: ResourceMode): void => {
    if (this.runtime.attacker || this.runtime.target) {
      this.patch({ notice: "Resource mode applies to the next cold boot; running VM RAM is unchanged." });
    }
    this.patch({ resourceMode });
  };

  selectTarget = (selectedTarget: string): void => {
    if (this.runtime.target || this.runtime.attacker) {
      this.patch({ notice: "Stop or reset the lab before changing the target build." });
      return;
    }
    this.patch({ selectedTarget });
  };

  clearMessages = (): void => this.patch({ error: null, notice: null });

  registerScreen = (machine: MachineId, element: HTMLElement | null): void => {
    if (element) this.screens[machine] = element;
    else delete this.screens[machine];
  };

  focusMachine = (selected: MachineId | null): void => {
    for (const machine of ["attacker", "target"] as const) {
      const emulator = this.runtime[machine]?.emulator;
      if (!emulator) continue;
      const active = selected === machine && this.state.view === machine;
      emulator.keyboard_set_enabled(active);
      emulator.mouse_set_enabled(active);
    }
  };

  subscribeSerial = (machine: MachineId, listener: (text: string) => void): (() => void) => {
    this.serialListeners[machine].add(listener);
    return () => this.serialListeners[machine].delete(listener);
  };

  getSerialTranscript = (machine: MachineId): string => this.runtime[machine]?.serial.getTranscript() ?? this.state.machines[machine].serial;

  sendSerial = (machine: MachineId, text: string): void => {
    if (this.state.operation) throw new Error("Wait for the current guest operation to finish before typing on the shared serial console.");
    if (machine === "target" && !this.targetSerialSealed) throw new Error("Target serial input is locked until root provisioning has sealed this boot to the unprivileged lab user.");
    const serial = this.runtime[machine]?.serial;
    if (!serial) throw new Error(`${machine} guest is not running.`);
    serial.sendRaw(text);
  };

  fullscreen = (machine: MachineId): void => {
    this.runtime[machine]?.emulator.screen_go_fullscreen();
  };

  private assertCurrent(generation: number): void {
    if (generation !== this.generation) throw new Error("Operation superseded by a lab reset");
  }

  private async acquireNetworkLock(): Promise<string> {
    if (!navigator.locks) {
      throw new Error("Web Locks are unavailable, so exclusive ownership of the BroadcastChannel network cannot be guaranteed. Boot was refused (fail closed). Use a current Chrome, Edge, or Firefox browser.");
    }
    let signal!: (available: boolean) => void;
    const signalled = new Promise<boolean>((resolve) => { signal = resolve; });
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const request = navigator.locks.request(INBROWSER_LOCK, { ifAvailable: true }, async (lock) => {
      if (!lock) {
        signal(false);
        return;
      }
      signal(true);
      await held;
    });
    const available = await signalled;
    if (!available) {
      await request;
      throw new Error("Another lab in this browser origin already owns v86-inbrowser-0. Concurrent boot was refused to prevent cross-session Ethernet traffic.");
    }
    this.networkLockRelease = () => {
      release();
      void request.catch(() => undefined);
    };
    return INBROWSER_NETWORK_ID;
  }

  private releaseNetworkLock(): void {
    this.networkLockRelease?.();
    this.networkLockRelease = null;
  }

  startLab = async (): Promise<void> => {
    if (this.state.operation) return;
    const generation = ++this.generation;
    this.patch({ operation: "Starting lab", status: "loading-emulator", error: null, notice: null });
    try {
      await this.startInternal(generation, null);
    } catch (error) {
      if (generation === this.generation) this.handleFailure(error, "Lab startup failed");
    } finally {
      if (generation === this.generation) this.patch({ operation: null, assetProgress: null });
    }
  };

  restoreSnapshot = async (id: string): Promise<void> => {
    if (this.state.operation) return;
    const generation = ++this.generation;
    this.patch({ operation: "Restoring VM states", status: "loading-emulator", error: null, notice: null });
    try {
      await this.startInternal(generation, id);
    } catch (error) {
      if (generation === this.generation) this.handleFailure(error, "State restore failed");
    } finally {
      if (generation === this.generation) this.patch({ operation: null, assetProgress: null });
    }
  };

  private async startInternal(generation: number, snapshotId: string | null): Promise<void> {
    await this.destroyRuntimes();
    this.assertCurrent(generation);
    this.patch({
      checks: NETWORK_CHECKS.map((check) => ({ ...check })),
      telemetry: null,
      health: null,
      completedAs: null,
      error: null,
    });
    const snapshot = snapshotId ? await getSnapshot(snapshotId) : undefined;
    if (snapshotId && !snapshot) throw new Error("The requested snapshot no longer exists in browser storage.");
    if (snapshot && snapshot.meta.v86Version !== "0.5.472") {
      throw new Error(`Snapshot uses v86 ${snapshot.meta.v86Version}, but this runtime is pinned to 0.5.472. Restore was refused.`);
    }
    const manifest = await loadManifest();
    this.assertCurrent(generation);
    this.patch({ manifest });
    const target = manifest.targets.find((item) => item.id === (snapshot ? snapshot.session.targetBuild : this.state.selectedTarget));
    if (!target) throw new Error("Selected target build is absent from the pinned manifest.");
    if (!snapshot && target.required && !target.image.available) {
      throw new Error(`Required ${target.phpVersion} target image is missing at ${target.image.path}. See docs/IMAGES.md.`);
    }
    if (!snapshot && !target.image.available) throw new Error(`Optional target ${target.phpVersion} has not been provisioned.`);
    if (snapshot) this.patch({ selectedTarget: target.id, resourceMode: snapshot.resourceMode });

    this.log("Loading the pinned v86 module and verifying local firmware/images.");
    if (!this.V86Class) this.V86Class = (await import("v86")).V86;
    const callbacks = {
      onProgress: (label: string, loaded: number, total: number) => this.patch({ assetProgress: { label, loaded, total } }),
      onNotice: (notice: string) => this.patch({ notice }),
    };
    const bios = await loadVerifiedAsset("SeaBIOS", manifest.v86.bios, callbacks);
    const vgaBios = await loadVerifiedAsset("VGA BIOS", manifest.v86.vgaBios, callbacks);
    const wasm = await loadVerifiedAsset("v86 WebAssembly", manifest.v86.wasm, callbacks);
    const attacker = await loadVerifiedAsset("Attacker ISO", manifest.attacker.image, callbacks);
    const targetBuffer = await loadVerifiedAsset(`Target PHP ${target.phpVersion} ISO`, target.image, callbacks);
    this.assertCurrent(generation);
    this.images = { bios, vgaBios, wasm, attacker, target: targetBuffer };
    this.wasmUrl = URL.createObjectURL(new Blob([wasm], { type: "application/wasm" }));

    let session: SessionInfo;
    if (snapshot) {
      session = { ...snapshot.session, networkId: "", proof: undefined };
      this.sessionProvisioned = true;
    } else if (this.state.session && this.sessionProvisioned) {
      session = { ...this.state.session, networkId: "", proof: undefined, flagSubmittedAt: undefined };
    } else {
      // A persisted report has no live target provisioning context. A new cold
      // session must never inherit its evidence under a different identifier.
      this.patch({ evidence: [], hasUnsavedProgress: false, exercise: emptyExercise(), completedAs: null });
      this.sessionProvisioned = false;
      session = {
        id: randomToken(8),
        networkId: "",
        startedAt: new Date().toISOString(),
        targetBuild: target.id,
        phpVersion: target.phpVersion,
        // Filled from the target's digest-only provisioning response. The
        // plaintext flag is generated and stored inside the target guest.
        flagSha256: "",
        challenge: randomToken(24),
      };
    }
    session.networkId = await this.acquireNetworkLock();
    this.patch({ session });
    this.log(`Acquired the origin-wide lock for v86-inbrowser-${session.networkId}; concurrent labs are refused, and no relay, NAT, or external backend is configured.`, "success");

    const restoreAttacker = snapshot?.attacker;
    const restoreTarget = snapshot?.target;
    await this.bootMachine("attacker", target, manifest, restoreAttacker, generation);
    this.assertCurrent(generation);
    await this.bootMachine("target", target, manifest, restoreTarget, generation);
    this.assertCurrent(generation);

    this.patch({ status: "initializing-network" });
    await this.verifyNetwork(generation);
    await this.refreshTarget(false);
    await this.checkRceEvidence();
    if (this.state.status !== "completed") this.patch({ status: "ready" });
    this.startTelemetryTimer();
    this.log("Guest boot, static addressing, HTTP, response headers, and Apache log checks all passed.", "success");
    this.patch({ notice: snapshot ? "Snapshots restored. Networking and services were revalidated against the running guests." : "Both real guests are ready on the isolated 192.168.10.0/24 network." });
    await this.persistReport();
  }

  private async bootMachine(machine: MachineId, target: TargetAsset, manifest: AssetManifest, restore: ArrayBuffer | undefined, generation: number): Promise<void> {
    if (!this.images || !this.V86Class || !this.wasmUrl || !this.state.session) throw new Error("Emulator assets are not initialized");
    const screen = this.screens[machine];
    if (!screen) throw new Error(`${machine} screen container is not mounted; refusing headless substitution`);
    const ram = machine === "attacker"
      ? manifest.attacker.memory[this.state.resourceMode === "low" ? "lowMiB" : "standardMiB"]
      : target.memory[this.state.resourceMode === "low" ? "lowMiB" : "standardMiB"];
    this.patch({ status: machine === "attacker" ? "booting-attacker" : "booting-target" });
    if (machine === "target") this.targetSerialSealed = false;
    this.patchMachine(machine, { status: "booting", ramMiB: ram, error: undefined, detail: "v86 is booting the prepared ISO", lastBootAt: new Date().toISOString(), serial: "" });
    const options: V86Options = {
      wasm_path: this.wasmUrl,
      memory_size: ram * 1024 * 1024,
      vga_memory_size: 8 * 1024 * 1024,
      screen_container: screen,
      bios: { buffer: this.images.bios.slice(0) },
      vga_bios: { buffer: this.images.vgaBios.slice(0) },
      cdrom: { buffer: (machine === "attacker" ? this.images.attacker : this.images.target).slice(0) },
      autostart: true,
      fastboot: true,
      disable_speaker: true,
      mac_address_translation: true,
      net_device: { relay_url: "inbrowser", type: "ne2k", id: Number(this.state.session.networkId) },
      initial_state: restore ? { buffer: restore.slice(0) } : undefined,
    };
    let readyResolve!: () => void;
    let readyReject!: (error: Error) => void;
    const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    const readyTimer = setTimeout(() => readyReject(new Error(`${machine} v86 initialization timed out`)), 60_000);
    let emulator: V86;
    try {
      emulator = new this.V86Class(options);
    } catch (error) {
      clearTimeout(readyTimer);
      throw new Error(`${machine} emulator rejected its configuration or image: ${error instanceof Error ? error.message : String(error)}`);
    }
    const serial = new SerialChannel(emulator, (text) => {
      const previous = this.state.machines[machine].serial;
      this.patchMachine(machine, { serial: clampText(previous + text, 64_000) });
      for (const listener of this.serialListeners[machine]) listener(text);
    });
    this.runtime[machine] = { emulator, serial };
    emulator.add_listener("emulator-ready", () => {
      clearTimeout(readyTimer);
      readyResolve();
    });
    emulator.add_listener("download-error", (event) => {
      readyReject(new Error(`${machine} asset read failed: ${event.file_name}`));
    });
    emulator.keyboard_set_enabled(false);
    emulator.mouse_set_enabled(false);
    await ready;
    this.assertCurrent(generation);
    this.log(`${machine === "attacker" ? "Attacker" : "Target"} emulator initialized with ${ram} MiB RAM and an NE2000 NIC.`);

    try {
      if (!restore) await serial.waitFor(/[$#] /, BOOT_TIMEOUT);
      if (machine === "target" && !restore) await this.provisionTarget(serial);
      await this.waitGuestReady(machine, restore !== undefined);
      if (machine === "target") this.targetSerialSealed = true;
      this.patchMachine(machine, { status: "ready", detail: restore ? "State restored; guest checks pending" : "Guest boot and local service checks passed" });
    } catch (error) {
      let detail = error instanceof Error ? error.message : String(error);
      const serialTail = this.state.machines[machine].serial.slice(-8000).trim();
      if (serialTail) detail += `\nRecent ${machine} serial output:\n${serialTail}`;
      this.patchMachine(machine, { status: "failed", error: detail });
      throw new Error(detail, { cause: error });
    }
  }

  private async provisionTarget(serial: SerialChannel): Promise<void> {
    if (!this.state.session) throw new Error("No active session is available for target provisioning");
    // SerialChannel suppresses and restores TTY echo around every command.
    const result = await serial.exec(`labctl provision '${this.state.session.challenge}'`, 15_000);
    const digest = result.output.match(/CYBER_RANGE_FLAG_PROVISIONED\s+sha256=([0-9a-f]{64})/)?.[1];
    if (result.exitCode !== 0 || !digest) {
      throw new Error(`Target rejected flag provisioning or returned no digest: ${result.output}`);
    }
    this.patch({ session: { ...this.state.session, flagSha256: digest } });
    // The lab account must be able to traverse this directory to verify the
    // public provisioning/sealing markers after root access is sealed. The
    // challenge remains 0600 root-only; this grants no flag or root access.
    const markerPermissions = await serial.exec("chown root:lab /run/cyber-range && chmod 0750 /run/cyber-range", 10_000);
    if (markerPermissions.exitCode !== 0) {
      throw new Error(`Target rejected provisioning-marker permissions: ${markerPermissions.output}`);
    }
    // Seal the hidden root control shell. The visible target and subsequent
    // telemetry commands run as the unprivileged Alpine 'lab' account.
    serial.sendRaw("labctl seal\n");
    await serial.waitFor(/[$] /, 15_000, false);
    const identity = await serial.exec("id -un", 10_000);
    if (identity.exitCode !== 0 || identity.output.trim() !== "lab") {
      throw new Error(`Target serial seal did not produce the unprivileged lab context: ${identity.output}`);
    }
    this.sessionProvisioned = true;
    this.log("Target generated the session flag internally with root:apache 0640 permissions; only its digest left the guest. Hidden boot shell sealed to the lab user.");
  }

  private async waitGuestReady(machine: MachineId, restored: boolean): Promise<void> {
    const runtime = this.runtime[machine];
    if (!runtime) throw new Error(`${machine} is not running`);
    let last: unknown;
    // A refused management connection returns immediately. Python imports can
    // be slow under x86 emulation, so poll real readiness for up to five
    // minutes while retaining twenty attempts for slower command timeouts.
    const readinessStarted = Date.now();
    for (let attempt = 0; attempt < 200; attempt += 1) {
      try {
        const result = await runtime.serial.exec("labctl ready", 25_000);
        const info = jsonFromOutput<Record<string, string>>(result.output);
        if (result.exitCode !== 0) throw new Error(`labctl ready exited ${result.exitCode}: ${result.output}`);
        this.patchMachine(machine, {
          guestOs: info.os,
          architecture: info.arch,
          address: info.address,
          detail: restored ? "Restored guest responded to actual readiness checks" : "Guest-reported boot and service checks passed",
        });
        if (machine === "attacker") {
          this.patch({ proxyStatus: info.proxy === "running" ? "running" : "failed" });
          const tools = await runtime.serial.exec("labctl tools", 15_000);
          this.patch({ attackerTools: tools.output.split("\n").map((line) => line.split("\t")[0]).filter((name): name is string => Boolean(name)) });
        }
        this.evidence(machine, "system", `${machine} readiness`, `${machine} guest: labctl ready`, result.output);
        return;
      } catch (error) {
        last = error;
        if (attempt >= 19 && Date.now() - readinessStarted >= 300_000) break;
        await sleep(1_500);
      }
    }
    let detail = last instanceof Error ? last.message : String(last);
    const diagnosticCommand = machine === "attacker"
      ? "printf '%s\\n' '--- proxy processes ---'; ps; netstat -ltn 2>&1 || ss -ltn 2>&1; for p in $(pidof python3); do grep -E '^(Name|State|VmRSS)' /proc/$p/status 2>&1; done; printf '%s\\n' '--- proxy log ---'; cat /tmp/range-proxy.log 2>&1; printf '%s\\n' '--- proxy files ---'; ls -ld /home/tc/lab /home/tc/lab-evidence /tmp/range-proxy.log 2>&1; printf '%s\\n' '--- graphical display ---'; ls -l /tmp/.X11-unix /tmp/cyber-range-x.log 2>&1; cat /tmp/cyber-range-x.log 2>&1; tail -n 60 /home/tc/.xsession-errors 2>&1"
      : "printf '%s\\n' '--- OpenRC services ---'; rc-status --all 2>&1; rc-service apache2 status 2>&1; id; ls -ld /run/cyber-range 2>&1; ls -l /run/cyber-range 2>&1; printf '%s\\n' '--- Apache configuration ---'; httpd -t 2>&1; ls -ld /run/apache2 /var/log/apache2 2>&1; printf '%s\\n' '--- Apache error log ---'; tail -n 80 /var/log/apache2/error.log 2>&1; printf '%s\\n' '--- kernel/system log ---'; tail -n 60 /var/log/messages 2>&1";
    try {
      const diagnostics = await runtime.serial.exec(diagnosticCommand, 15_000);
      detail += `\n${machine} service diagnostics:\n${diagnostics.output.slice(-8000)}`;
    } catch {
      // Preserve the original readiness error if diagnostic collection also
      // fails; never replace it with a less useful secondary exception.
    }
    throw new Error(`${machine} did not become ready: ${detail}`);
  }

  private requireSerial(machine: MachineId): SerialChannel {
    const serial = this.runtime[machine]?.serial;
    if (!serial) throw new Error(`${machine} guest is not running`);
    return serial;
  }

  private async command(machine: MachineId, command: string, timeout = 30_000): Promise<CommandResult> {
    const result = await this.requireSerial(machine).exec(command, timeout);
    if (result.exitCode !== 0) throw new Error(`${machine} command exited ${result.exitCode}: ${command}\n${result.output.slice(-1000)}`);
    return result;
  }

  private async verifyNetwork(generation: number): Promise<void> {
    const session = this.state.session;
    if (!session) throw new Error("No lab session");
    const runCheck = async (id: string, action: () => Promise<string>) => {
      this.patchCheck(id, { status: "running", detail: "Executing guest check…", observedAt: new Date().toISOString() });
      try {
        this.assertCurrent(generation);
        const detail = await action();
        this.assertCurrent(generation);
        this.patchCheck(id, { status: "passed", detail, observedAt: new Date().toISOString() });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (generation === this.generation) this.patchCheck(id, { status: "failed", detail, observedAt: new Date().toISOString() });
        throw new Error(`${this.state.checks.find((check) => check.id === id)?.label ?? id}: ${detail}`);
      }
    };

    await runCheck("attacker-ip", async () => {
      const result = await this.command("attacker", "ip -4 -o addr show dev eth0");
      await this.command("attacker", "labctl ready");
      if (!result.output.includes("192.168.10.10/24")) throw new Error(result.output || "address absent");
      return result.output.trim();
    });
    await runCheck("target-ip", async () => {
      const result = await this.command("target", "ip -4 -o addr show dev eth0");
      await this.command("target", "labctl ready");
      if (!result.output.includes("192.168.10.55/24")) throw new Error(result.output || "address absent");
      return result.output.trim();
    });
    await runCheck("connectivity", async () => {
      const result = await this.command("attacker", "ping -c 2 -W 3 192.168.10.55", 20_000);
      this.evidence("attacker", "network", "Guest-to-guest ICMP", "attacker: ping 192.168.10.55", result.output);
      return result.output.split("\n").filter((line) => line.includes("received") || line.includes("packets")).join(" · ") || "ping exited 0";
    });
    await runCheck("listener", async () => {
      const result = await this.command("target", "ss -ltn");
      if (!/:80\s/.test(result.output)) throw new Error(`No TCP port 80 listener in guest socket table: ${result.output}`);
      return result.output.split("\n").find((line) => /:80\s/.test(line))?.trim() ?? "port 80 listening";
    });
    const requestId = `boot-${session.id}`;
    let headers = "";
    await runCheck("http", async () => {
      const result = await this.command("attacker", `curl --noproxy '*' --max-time 20 -sS -D /tmp/range-headers -o /tmp/range-body 'http://192.168.10.55/health.php?evidence=${requestId}' && cat /tmp/range-headers`, 30_000);
      headers = result.output;
      if (!/HTTP\/1\.[01] 200/.test(headers)) throw new Error(`Unexpected target response: ${headers}`);
      const body = await this.command("attacker", "cat /tmp/range-body");
      jsonFromOutput<TargetHealth>(body.output);
      this.evidence("attacker", "http", "Boot verification HTTP transaction", `attacker → http://192.168.10.55/health.php?evidence=${requestId}`, `${headers}\n${body.output}`);
      return headers.split("\n")[0] ?? "HTTP 200";
    });
    await runCheck("headers", async () => {
      const lines = headers.split("\n").filter(Boolean);
      if (lines.length < 3 || !/Content-Type: application\/json/i.test(headers)) throw new Error(`Incomplete response headers: ${headers}`);
      return lines.slice(0, 6).join(" · ");
    });
    await runCheck("logs", async () => {
      const result = await this.command("target", "labctl logs access");
      if (!result.output.includes(`evidence=${requestId}`)) throw new Error(`Request ${requestId} was not found in the real access log`);
      this.patch({ logs: { ...this.state.logs, access: result.output } });
      this.evidence("target", "log", "Apache recorded the boot request", "target: /var/log/apache2/access.log", result.output);
      return result.output.split("\n").find((line) => line.includes(`evidence=${requestId}`))?.trim() ?? "request found";
    });
    await runCheck("isolation", async () => {
      const attackerRoutes = await this.command("attacker", "ip route");
      const targetRoutes = await this.command("target", "ip route");
      const combined = `${attackerRoutes.output}\n${targetRoutes.output}`;
      if (/^default\s/m.test(combined)) throw new Error(`A guest default route is present: ${combined}`);
      return `v86-inbrowser-${session.networkId}; origin-wide exclusive Web Lock held; no default guest route`;
    });
  }

  verifyNetworkNow = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.patch({ operation: "Revalidating isolated network", status: "initializing-network", error: null });
    try {
      await this.verifyNetwork(generation);
      this.patch({ status: this.state.completedAs ? "completed" : this.state.session?.proof ? "testing" : "ready", notice: "All network and HTTP checks were repeated against the running guests." });
      this.log("Manual network revalidation passed.", "success");
    } catch (error) {
      if (generation === this.generation) this.handleFailure(error, "Network revalidation failed");
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  refreshTarget = async (background = false): Promise<void> => {
    if (!this.runtime.target || this.telemetryRunning) return;
    const generation = this.generation;
    this.telemetryRunning = true;
    try {
      const telemetryResult = await this.command("target", "labctl telemetry", 20_000);
      if (generation !== this.generation) return;
      const telemetry = jsonFromOutput<Telemetry>(telemetryResult.output);
      this.patch({ telemetry });
      if (!background) {
        const [health, build, access, errors, php] = await Promise.all([
          this.command("target", "labctl health", 20_000),
          this.command("target", "labctl build", 20_000),
          this.command("target", "labctl logs access", 20_000),
          this.command("target", "labctl logs error", 20_000),
          this.command("target", "labctl logs php", 20_000),
        ]);
        if (generation !== this.generation) return;
        const parsedHealth = jsonFromOutput<TargetHealth>(health.output);
        this.patch({
          health: parsedHealth,
          buildInfo: build.output,
          logs: { access: access.output, error: errors.output, php: php.output },
        });
        this.patchMachine("target", { guestOs: "Alpine Linux x86", architecture: "x86", address: "192.168.10.55/24", detail: `${parsedHealth.apache ?? "Apache"} · PHP ${parsedHealth.php_version} · ${parsedHealth.php_sapi}` });
      }
      if (telemetry.apache_state !== "running" || telemetry.apache_worker_count < 1) {
        this.patchMachine("target", { status: "degraded", detail: "Guest telemetry reports no running Apache workers" });
      } else if (this.state.machines.target.status === "degraded") {
        this.patchMachine("target", { status: "ready", detail: "Guest telemetry reports Apache and mod_php running" });
      }
      await this.checkRceEvidence();
    } catch (error) {
      if (generation !== this.generation) return;
      if (!background) throw error;
      this.log(`Background target telemetry failed: ${error instanceof Error ? error.message : String(error)}`, "warning");
    } finally {
      if (generation === this.generation) this.telemetryRunning = false;
    }
  };

  refreshTargetNow = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.patch({ operation: "Reading target telemetry and logs", error: null });
    try {
      // A periodic telemetry-only read may still own the target serial queue.
      // Never turn its early return into a false "all logs refreshed" notice.
      const idleDeadline = Date.now() + 45_000;
      while (this.telemetryRunning) {
        if (generation !== this.generation) return;
        if (Date.now() >= idleDeadline) throw new Error("Background target telemetry did not finish within 45s; manual log refresh was not claimed");
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      await this.refreshTarget(false);
      if (generation !== this.generation) return;
      this.patch({ notice: "Target status, PHP health, process memory, and all three log files were refreshed from the guest." });
    } catch (error) {
      if (generation === this.generation) this.patch({ error: error instanceof Error ? error.message : String(error) });
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  private startTelemetryTimer(): void {
    if (this.telemetryTimer) clearInterval(this.telemetryTimer);
    this.telemetryTimer = setInterval(() => {
      if (["ready", "testing", "completed"].includes(this.state.status)) void this.refreshTarget(true);
    }, 20_000);
  }

  private async checkRceEvidence(): Promise<void> {
    const session = this.state.session;
    const generation = this.generation;
    if (!session || !this.runtime.target) return;
    try {
      const result = await this.requireSerial("target").exec(`labctl evidence '${session.challenge}'`, 15_000);
      if (generation !== this.generation || session.id !== this.state.session?.id) return;
      const proof = jsonFromOutput<{ rce_evidence: boolean; owner: string; path: string }>(result.output);
      if (result.exitCode !== 0 || !proof.rce_evidence || session.proof) return;
      const observedAt = new Date().toISOString();
      this.patch({ session: { ...this.state.session!, proof: { observedAt, owner: proof.owner, path: proof.path, data: result.output } } });
      this.evidence("target", "rce-proof", "Apache-worker execution proof observed", "target: labctl evidence (ownership + challenge + session mtime)", result.output);
      this.log("Fresh target-owned execution proof observed. Matching flag submission is still required.", "success");
      if (session.flagSubmittedAt) {
        this.patch({ status: "completed", completedAs: "genuine-rce" });
      } else if (this.state.status !== "completed") {
        this.patch({ status: "testing", notice: "Genuine target-side proof is present. Submit the flag read through that execution context to complete the lab." });
      }
    } catch {
      // Absence of proof is an ordinary incomplete state, not an emulator error.
    }
  }

  launchAttackerTool = async (tool: "browser" | "proxy" | "terminal"): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    const required = tool === "terminal"
      ? (this.state.attackerTools.includes("aterm") ? "aterm" : "xterm")
      : (this.state.attackerTools.includes("dillo-beta") ? "dillo-beta" : "dillo");
    if (!this.state.attackerTools.includes(required)) {
      this.patch({ error: `${required} was not found by the attacker guest's tool inventory. No launcher was created.` });
      return;
    }
    const command = tool === "browser"
      ? `DISPLAY=:0 ${required} http://192.168.10.55/ >/tmp/range-browser.log 2>&1 &`
      : tool === "proxy"
        ? `DISPLAY=:0 ${required} http://127.0.0.1:8081/ >/tmp/range-proxy-ui.log 2>&1 &`
        : `DISPLAY=:0 ${required} >/tmp/range-terminal.log 2>&1 &`;
    this.patch({ operation: `Launching ${required} in attacker guest` });
    try {
      await this.command("attacker", command, 10_000);
      if (generation !== this.generation) return;
      this.patch({ notice: `${required} launched inside the attacker guest. Interact with it on the actual guest display.` });
    } catch (error) {
      if (generation === this.generation) this.patch({ error: error instanceof Error ? error.message : String(error) });
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  runBaseline = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.patch({ operation: "Sending baseline request", status: "testing", error: null });
    try {
      const id = `learner-${randomToken(6)}`;
      const result = await this.command("attacker", `curl --noproxy '*' --max-time 20 -sS -i 'http://192.168.10.55/?evidence=${id}'`, 30_000);
      if (generation !== this.generation) return;
      if (!/HTTP\/1\.[01] 200/.test(result.output)) throw new Error(`Baseline did not return HTTP 200: ${result.output}`);
      this.evidence("attacker", "http", "Learner baseline request", `attacker: curl -i http://192.168.10.55/?evidence=${id}`, result.output);
      const logs = await this.command("target", "labctl logs access");
      if (generation !== this.generation) return;
      this.patch({ logs: { ...this.state.logs, access: logs.output }, notice: `Baseline ${id} captured from the target and corroborated by its guest access log.` });
      if (!logs.output.includes(id)) throw new Error("Baseline request was not corroborated by Apache's access log");
      this.log("Learner baseline completed with real response and target log evidence.", "success");
      this.patch({ status: this.state.completedAs ? "completed" : this.state.session?.proof ? "testing" : "ready" });
      await this.persistReport();
    } catch (error) {
      if (generation === this.generation) this.patch({ status: this.state.completedAs ? "completed" : "ready", error: error instanceof Error ? error.message : String(error) });
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  runProxyBaseline = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    let restoreIntercept = false;
    const restoreInterceptMode = async () => {
      if (!restoreIntercept || generation !== this.generation || !this.runtime.attacker) return;
      try {
        await this.command("attacker", "curl --noproxy '*' --max-time 5 -sS -X POST -d '' http://127.0.0.1:8081/toggle >/dev/null", 10_000);
        restoreIntercept = false;
      } catch (error) {
        this.log(`Could not restore the prior RangeProxy intercept setting: ${error instanceof Error ? error.message : String(error)}`, "warning");
      }
    };
    this.patch({ operation: "Reading RangeProxy state", status: "testing", error: null });
    try {
      const stateResult = await this.command("attacker", "labctl proxy-state", 10_000);
      const proxyState = jsonFromOutput<{ intercept: boolean }>(stateResult.output);
      restoreIntercept = proxyState.intercept === true;
      if (restoreIntercept) {
        this.patch({ operation: "Temporarily disabling RangeProxy intercept" });
        await this.command("attacker", "curl --noproxy '*' --max-time 5 -sS -X POST -d '' http://127.0.0.1:8081/toggle >/dev/null", 10_000);
      }
      const id = `proxy-${randomToken(6)}`;
      this.patch({ operation: "Sending guest curl through RangeProxy" });
      const result = await this.command("attacker", `curl -x http://127.0.0.1:8080 --max-time 20 -fsS -i 'http://192.168.10.55/health.php?evidence=${id}'`, 30_000);
      if (generation !== this.generation) return;
      if (!/HTTP\/1\.[01] 200/.test(result.output)) throw new Error(`RangeProxy did not return HTTP 200: ${result.output}`);
      this.evidence("attacker", "http", "RangeProxy baseline response", `attacker: curl -x http://127.0.0.1:8080 http://192.168.10.55/health.php?evidence=${id}`, result.output);
      const logs = await this.command("target", "labctl logs access");
      if (generation !== this.generation) return;
      this.patch({ logs: { ...this.state.logs, access: logs.output } });
      if (!logs.output.includes(id)) throw new Error("RangeProxy response was not corroborated by Apache's access log");
      await restoreInterceptMode();
      this.log("RangeProxy baseline returned a real response and matching target log evidence.", "success");
      this.patch({
        status: this.state.completedAs ? "completed" : this.state.session?.proof ? "testing" : "ready",
        notice: `RangeProxy request ${id} returned HTTP 200 and was corroborated by the target access log.`,
      });
      await this.persistReport();
    } catch (error) {
      if (generation === this.generation) this.patch({ status: this.state.completedAs ? "completed" : "ready", error: error instanceof Error ? error.message : String(error) });
    } finally {
      await restoreInterceptMode();
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  runRealProxyAcceptance = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    let pausedTarget: MachineRuntime | null = null;
    if (this.telemetryTimer) {
      clearInterval(this.telemetryTimer);
      this.telemetryTimer = null;
    }
    this.patch({ operation: "Starting real proxy acceptance", status: "testing", error: null, proxyAcceptance: null });
    const pauseTarget = async () => {
      if (generation !== this.generation) throw new Error("Proxy acceptance was cancelled");
      const runtime = this.runtime.target;
      if (!runtime) throw new Error("Target guest is not running");
      await runtime.emulator.stop();
      if (runtime.emulator.is_running()) throw new Error("Target v86 did not stop for the bounded unavailable-target test");
      pausedTarget = runtime;
    };
    const resumeTarget = async () => {
      if (!pausedTarget) return;
      const runtime = pausedTarget;
      if (generation !== this.generation || this.runtime.target !== runtime) {
        pausedTarget = null;
        return;
      }
      await runtime.emulator.run();
      if (!runtime.emulator.is_running()) throw new Error("Target v86 did not resume after the unavailable-target test");
      pausedTarget = null;
    };
    try {
      const runner = new ProxyAcceptanceRunner({
        execute: (machine, command, timeout) => this.requireSerial(machine).exec(command, timeout),
        pauseTarget,
        resumeTarget,
        onProgress: (proxyAcceptance) => {
          if (generation !== this.generation) return;
          const current = proxyAcceptance.gates.find((gate) => gate.status === "RUNNING");
          this.patch({ proxyAcceptance, operation: current ? `Proxy acceptance: ${current.label}` : "Finishing proxy acceptance" });
        },
        capture: (name, machine, data) => {
          if (generation !== this.generation) return;
          this.evidence(machine, "proxy", `Proxy acceptance ${name}`, `${machine} guest / real proxy acceptance`, data);
        },
      });
      const report = await runner.run();
      if (generation !== this.generation) return;
      const passed = report.status === "PASS";
      this.patch({
        proxyAcceptance: report,
        status: this.state.completedAs ? "completed" : "ready",
        hasUnsavedProgress: true,
        proxyStatus: report.gates.find((gate) => gate.id === "process")?.status === "PASS" ? "running" : this.state.proxyStatus,
        notice: passed
          ? "Real Dillo interception/editing/forwarding, Repeater, target-log corroboration, and bounded failure recovery all passed."
          : "Real proxy acceptance failed. Inspect the individual gate and guest artifacts; no proxy capability is inferred from readiness alone.",
        error: passed ? null : report.error,
      });
      this.log(passed ? "Real browser proxy and Repeater acceptance passed with target-side corroboration." : "Real proxy acceptance failed; see its per-gate report.", passed ? "success" : "error");
      await this.persistReport();
    } catch (error) {
      if (generation === this.generation) {
        this.patch({ status: this.state.completedAs ? "completed" : "ready", error: error instanceof Error ? error.message : String(error) });
      }
    } finally {
      if (pausedTarget && generation === this.generation) {
        try { await resumeTarget(); } catch (error) {
          this.log(`Target resume after proxy acceptance needs attention: ${error instanceof Error ? error.message : String(error)}`, "warning");
        }
      }
      if (generation === this.generation) {
        this.patch({ operation: null });
        this.startTelemetryTimer();
      }
    }
  };

  syncGuestEvidence = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.patch({ operation: "Collecting attacker evidence", error: null });
    try {
      const result = await this.command("attacker", "labctl evidence", 30_000);
      if (generation !== this.generation) return;
      if (!result.output.trim()) {
        this.patch({ notice: "No RangeProxy records yet. Send a browser, intercept, or repeater request inside the attacker guest first." });
        return;
      }
      let imported = 0;
      for (const line of result.output.split("\n")) {
        if (!line.trim().startsWith("{")) continue;
        try {
          const item = JSON.parse(line) as { sequence: number; timestamp: string; kind: string; source: string; request_base64: string; response?: unknown; error?: string };
          const id = `range-proxy-${item.sequence}-${item.timestamp}`;
          if (this.state.evidence.some((record) => record.id === id)) continue;
          const request = atob(item.request_base64 ?? "");
          const record: EvidenceRecord = {
            id,
            timestamp: item.timestamp,
            category: "proxy",
            title: `RangeProxy ${item.kind} #${item.sequence}`,
            source: `attacker guest / ${item.source}`,
            machine: "attacker",
            data: JSON.stringify({ request, response: item.response, error: item.error }, null, 2),
            genuine: true,
          };
          this.patch({ evidence: [record, ...this.state.evidence].slice(0, 500) });
          imported += 1;
        } catch {
          this.log("Skipped a malformed or truncated proxy evidence line; it was not counted as verified.", "warning");
        }
      }
      this.patch({ hasUnsavedProgress: true, notice: `Imported ${imported} new guest proxy record(s); existing records were deduplicated.` });
      if (generation !== this.generation) return;
      await this.persistReport();
    } catch (error) {
      if (generation === this.generation) this.patch({ error: error instanceof Error ? error.message : String(error) });
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  private patchExercise(value: Partial<ExerciseFacts>): void {
    this.patch({ exercise: { ...this.state.exercise, ...value } });
  }

  private setStepFailure(step: ExerciseStepId, message: string): void {
    this.patchExercise({ failures: { ...this.state.exercise.failures, [step]: message } });
  }

  private clearStepFailure(step: ExerciseStepId): void {
    const failures = { ...this.state.exercise.failures };
    delete failures[step];
    this.patchExercise({ failures });
  }

  private settleExerciseStatus(): void {
    this.patch({
      status: this.state.completedAs === "genuine-rce"
        ? "completed"
        : this.state.session?.proof || this.state.completedAs === "simulated-exercise"
          ? "testing"
          : "ready",
    });
  }

  /**
   * Step 1: read the target's own configuration. Every value comes from the
   * guest (HTTP health endpoint, PHP CLI, /proc, stat) and is cross-checked
   * before it becomes exercise evidence.
   */
  runRecon = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.clearStepFailure("reconnaissance");
    this.patch({ operation: "Reading the target's real configuration", status: "testing", error: null });
    const marker = `recon-${randomToken(6)}`;
    try {
      const healthResponse = await this.command("attacker", `curl --noproxy '*' --max-time 20 -sS -D /tmp/range-recon-headers -o /tmp/range-recon-body 'http://192.168.10.55/health.php?evidence=${marker}' && cat /tmp/range-recon-headers && cat /tmp/range-recon-body`, 45_000);
      if (generation !== this.generation) return;
      if (!/HTTP\/1\.[01] 200/.test(healthResponse.output)) throw new Error(`The target did not return HTTP 200 for /health.php: ${healthResponse.output.slice(-800)}`);
      const health = jsonFromOutput<TargetHealth>(healthResponse.output);
      if (!/apache2handler/i.test(health.php_sapi)) throw new Error(`The target reported PHP SAPI "${health.php_sapi}", not Apache mod_php. The exercise refuses to classify a different SAPI.`);
      const flagStatus = await this.command("attacker", "curl --noproxy '*' --max-time 15 -sS -o /dev/null -w '%{http_code}' 'http://192.168.10.55/flag.txt'", 25_000);
      if (generation !== this.generation) return;
      const php = await this.command("target", TARGET_PHP_RECON, 25_000);
      if (generation !== this.generation) return;
      const telemetryResult = await this.command("target", "labctl telemetry", 25_000);
      const build = await this.command("target", "labctl build", 25_000);
      const listeners = await this.command("target", "ss -ltn; printf 'httpd_pids '; pidof httpd || true", 25_000);
      const flagStat = await this.command("target", "stat -c '%U %G %a %s %n' /var/www/html/flag.txt; ls -l /usr/lib/apache2/libphp.so; sha256sum /usr/lib/apache2/libphp.so", 25_000);
      if (generation !== this.generation) return;
      const telemetry = jsonFromOutput<Telemetry>(telemetryResult.output);
      const phpValues = parseKeyValues(php.output);
      const flagMode = flagStat.output.split("\n").find((line) => line.includes("flag.txt"))?.trim() ?? "not reported";
      const httpFlagStatus = flagStatus.output.trim().split("\n").pop()?.trim() ?? "";
      const problems = validateReconFacts({
        httpStatus: /HTTP\/1\.[01]\s+(\d{3})/.exec(healthResponse.output)?.[1] ?? "",
        httpFlagStatus,
        flagMode,
        listeners: listeners.output,
        sapi: health.php_sapi,
        phpCli: php.output,
      });
      const observation: BuildObservation = {
        phpVersion: health.php_version,
        sapi: health.php_sapi,
        memoryLimit: health.memory_limit,
        postMaxSize: health.post_max_size,
        uploadMaxFilesize: health.upload_max_filesize,
        uploadProgress: health.upload_progress,
        hardLimitDirective: phpValues.hard_limit === "absent" || !phpValues.hard_limit ? null : phpValues.hard_limit,
        libphpSha256: telemetry.php_binary_sha256,
        workerCount: telemetry.apache_worker_count,
        buildInfo: build.output.trim(),
        flagMode: `${flagMode} · HTTP ${httpFlagStatus}`,
        observedAt: new Date().toISOString(),
        raw: [healthResponse.output.slice(0, 4000), php.output, flagStat.output, listeners.output].join("\n---\n"),
      };
      const assessment = assessBuild(observation);
      this.patchExercise({ build: assessment });
      this.evidence("attacker", "http", "Reconnaissance: real target health response", `attacker: curl http://192.168.10.55/health.php?evidence=${marker}`, healthResponse.output);
      this.evidence("target", "telemetry", "Reconnaissance: target PHP and patch marker", "target: /usr/local/bin/php + labctl build + stat", observation.raw);
      this.evidence("target", "telemetry", "Reconnaissance: guest telemetry", "target: labctl telemetry", telemetryResult.output);
      if (problems.length) throw new Error(problems.join(" · "));
      this.patch({
        error: null,
        notice: `Reconnaissance complete: ${assessment.classification}. ${assessment.basis}`,
      });
      this.log(`Target configuration observed and cross-checked: ${assessment.classification}.`, "success");
      this.settleExerciseStatus();
      await this.persistReport();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.setStepFailure("reconnaissance", message);
      this.patch({ error: `Reconnaissance failed: ${message}` });
      this.settleExerciseStatus();
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /** Step 2: ordinary HTTP traffic from the attacker guest, corroborated by the target. */
  runBaselineSuite = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.clearStepFailure("baseline");
    this.patch({ operation: "Sending baseline requests from the attacker", status: "testing", error: null });
    const id = randomToken(5);
    const markers: [string, string, string] = [`base-get-${id}`, `base-login-${id}`, `base-post-${id}`];
    try {
      const plan = [
        { marker: markers[0], method: "GET", path: `/?evidence=${markers[0]}`, command: `curl --noproxy '*' --max-time 20 -sS -i 'http://192.168.10.55/?evidence=${markers[0]}'`, expect: "HTTP/1." },
        { marker: markers[1], method: "GET", path: `/wp-login.php?evidence=${markers[1]}`, command: `curl --noproxy '*' --max-time 20 -sS -i 'http://192.168.10.55/wp-login.php?evidence=${markers[1]}'`, expect: "HTTP/1." },
        { marker: markers[2], method: "POST", path: `/wp-login.php?evidence=${markers[2]}`, command: `curl --noproxy '*' --max-time 20 -sS -i -X POST -d 'log=analyst&pwd=range' 'http://192.168.10.55/wp-login.php?evidence=${markers[2]}'`, expect: "Training credentials accepted" },
      ];
      const requests: { method: string; path: string; status: string; marker: string }[] = [];
      for (const item of plan) {
        const result = await this.command("attacker", item.command, 35_000);
        if (generation !== this.generation) return;
        if (!result.output.includes(item.expect)) throw new Error(`${item.method} ${item.path} did not produce the expected response marker "${item.expect}": ${result.output.slice(-800)}`);
        const status = /HTTP\/1\.[01]\s+(\d{3})/.exec(result.output)?.[1] ?? "unknown";
        requests.push({ method: item.method, path: item.path, status, marker: item.marker });
        this.evidence("attacker", "http", `Baseline ${item.method} ${item.marker}`, `attacker: ${item.command}`, result.output);
      }
      const logs = await this.command("target", "labctl logs access", 25_000);
      if (generation !== this.generation) return;
      const corroborated = markers.filter((marker) => logs.output.includes(marker));
      this.patch({ logs: { ...this.state.logs, access: logs.output } });
      this.evidence("target", "log", "Baseline requests corroborated by Apache", "target: /var/log/apache2/access.log", logs.output);
      if (corroborated.length !== markers.length) {
        throw new Error(`Only ${corroborated.length}/${markers.length} baseline markers appeared in the target access log: ${markers.join(", ")}`);
      }
      this.patchExercise({
        baseline: { markers, corroborated, requests, observedAt: new Date().toISOString() },
      });
      this.patch({ notice: `${requests.length} baseline exchanges returned real responses and every marker was corroborated by the target access log.` });
      this.log("Baseline traffic completed with target-log corroboration.", "success");
      this.settleExerciseStatus();
      await this.persistReport();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.setStepFailure("baseline", message);
      this.patch({ error: `Baseline testing failed: ${message}` });
      this.settleExerciseStatus();
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /** Step 3: prove the real proxy path, including a body the proxy modified. */
  analyzeProxiedRequests = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.clearStepFailure("request-analysis");
    this.patch({ operation: "Routing requests through RangeProxy", status: "testing", error: null });
    const id = randomToken(5);
    const marker = `analysis-${id}`;
    const modifiedMarker = `repeater-${id}`;
    let restoreIntercept = false;
    const restoreInterceptMode = async () => {
      if (!restoreIntercept || generation !== this.generation || !this.runtime.attacker) return;
      try {
        await this.command("attacker", "curl --noproxy '*' --max-time 5 -sS -X POST -d '' http://127.0.0.1:8081/toggle >/dev/null", 10_000);
        restoreIntercept = false;
      } catch (error) {
        this.log(`Could not restore the prior RangeProxy intercept setting: ${error instanceof Error ? error.message : String(error)}`, "warning");
      }
    };
    try {
      // A held request would never reach the target; use the proxy's own state
      // endpoint rather than assuming interception is off.
      const proxyState = await this.command("attacker", "labctl proxy-state", 15_000);
      restoreIntercept = jsonFromOutput<{ intercept: boolean }>(proxyState.output).intercept === true;
      if (restoreIntercept) {
        this.patch({ operation: "Temporarily disabling RangeProxy intercept" });
        await this.command("attacker", "curl --noproxy '*' --max-time 5 -sS -X POST -d '' http://127.0.0.1:8081/toggle >/dev/null", 10_000);
      }
      const forwarded = await this.command("attacker", `curl -x http://127.0.0.1:8080 --max-time 25 -sS -i 'http://192.168.10.55/health.php?evidence=${marker}'`, 40_000);
      if (generation !== this.generation) return;
      if (!/HTTP\/1\.[01] 200/.test(forwarded.output)) throw new Error(`RangeProxy did not return HTTP 200 for the proxied request: ${forwarded.output.slice(-800)}`);
      const modified = await this.command("attacker", `curl -x http://127.0.0.1:8080 --max-time 25 -sS -i -X POST -d 'log=analyst&pwd=range' 'http://192.168.10.55/wp-login.php?evidence=${modifiedMarker}'`, 40_000);
      if (generation !== this.generation) return;
      const proxyEvidence = await this.command("attacker", "labctl evidence", 35_000);
      if (generation !== this.generation) return;
      const records = parseProxyEvidence(proxyEvidence.output);
      let proxySequence: number | null = null;
      for (const record of records) {
        try {
          if (evidenceRequest(record).includes(marker)) proxySequence = record.sequence;
        } catch {
          // A record whose request cannot be decoded is not counted as evidence.
        }
      }
      if (proxySequence === null) throw new Error(`The attacker guest's proxy record does not contain the marker ${marker}; the request did not demonstrably pass through RangeProxy.`);
      const logs = await this.command("target", "labctl logs access", 25_000);
      if (generation !== this.generation) return;
      const targetLines = logs.output.split("\n").filter((line) => line.includes(marker) || line.includes(modifiedMarker));
      this.patch({ logs: { ...this.state.logs, access: logs.output } });
      if (!targetLines.some((line) => line.includes(marker))) throw new Error(`The target access log has no line for the forwarded marker ${marker}.`);
      if (!targetLines.some((line) => line.includes(modifiedMarker))) throw new Error(`The target access log has no line for the modified marker ${modifiedMarker}.`);
      const modifiedAccepted = modified.output.includes("Training credentials accepted");
      this.patchExercise({
        proxyAnalysis: {
          marker,
          modifiedMarker,
          proxySequence,
          targetLines,
          modifiedAccepted,
          observedAt: new Date().toISOString(),
        },
      });
      this.evidence("attacker", "proxy", "Proxy forwarded request", `attacker: curl -x http://127.0.0.1:8080 http://192.168.10.55/health.php?evidence=${marker}`, forwarded.output);
      this.evidence("attacker", "proxy", "Proxy-modified POST", `attacker: curl -x http://127.0.0.1:8080 -X POST http://192.168.10.55/wp-login.php?evidence=${modifiedMarker}`, modified.output);
      this.evidence("target", "log", "Proxied requests seen by Apache", "target: /var/log/apache2/access.log", targetLines.join("\n"));
      await restoreInterceptMode();
      this.patch({ notice: `RangeProxy record #${proxySequence} forwarded ${marker}; the target accepted the modified POST ${modifiedMarker} and logged both.` });
      this.log("Request analysis completed through the real proxy with target corroboration.", "success");
      this.settleExerciseStatus();
      await this.persistReport();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.setStepFailure("request-analysis", message);
      this.patch({ error: `Request analysis failed: ${message}` });
      this.settleExerciseStatus();
    } finally {
      await restoreInterceptMode();
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /** Step 4: classify the running build and record every applicable condition. */
  investigateVulnerability = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.clearStepFailure("investigation");
    this.patch({ operation: "Classifying the running build", status: "testing", error: null });
    try {
      const config = await this.command("target", "httpd -M 2>&1 | grep -i php_module; printf '\\n'; grep -E '^(memory_limit|post_max_size|upload_max_filesize|max_file_uploads|max_input_vars|max_input_nesting_level|session.upload_progress)' /etc/php/php.ini; printf '\\n'; cat /etc/cyber-range/build-info; printf '\\n'; /usr/local/bin/php -v | head -2", 30_000);
      if (generation !== this.generation) return;
      const current = this.state.exercise.build;
      if (!current) throw new Error("Reconnaissance has not recorded the target configuration yet. Run step 1 first.");
      const refreshed = assessBuild({ ...current.observation, buildInfo: config.output.trim().split("\n").slice(0, 8).join("\n") || current.observation.buildInfo });
      this.patchExercise({ build: refreshed });
      this.evidence("target", "telemetry", "Vulnerability-mode verification", "target: httpd -M, /etc/php/php.ini, /etc/cyber-range/build-info, php -v", config.output);
      if (refreshed.classification === "unknown") throw new Error(`The build could not be classified: ${refreshed.basis}`);
      const unmet = refreshed.conditions.filter((condition) => !condition.met && condition.id !== "parser-cap");
      this.patch({
        notice: `${refreshed.classification}. ${refreshed.basis}`,
        error: null,
      });
      this.log(`Build classified as ${refreshed.classification} from observed values; ${unmet.length} condition(s) not met.`, "success");
      this.settleExerciseStatus();
      await this.persistReport();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.setStepFailure("investigation", message);
      this.patch({ error: `Vulnerability investigation failed: ${message}` });
      this.settleExerciseStatus();
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /** Step 5: one bounded, real request-processing probe with full target observation. */
  runControlledProbe = async (mib = 8, confirmLarge = false): Promise<void> => {
    if (this.state.operation || !this.runtime.attacker || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    if (!Number.isInteger(mib) || mib < 1 || mib > 64) {
      this.patch({ error: "The controlled probe accepts 1–64 MiB only. Larger streams are not part of this exercise." });
      return;
    }
    if (mib > 16 && !confirmLarge) {
      this.patch({ error: `A ${mib} MiB probe can terminate Apache workers. Re-run with explicit confirmation after reading the warning.` });
      return;
    }
    const generation = this.generation;
    this.clearStepFailure("reproduction");
    this.patch({ operation: `Sending a ${mib} MiB multipart probe to the isolated target`, status: "testing", error: null });
    const marker = `probe-${randomToken(6)}`;
    const startedAt = new Date().toISOString();
    try {
      const before = await this.command("target", "pidof httpd || true", 20_000);
      if (generation !== this.generation) return;
      const workerList = (output: string) => output.trim().split(/\s+/).filter(Boolean);
      const workersBeforePids = workerList(before.output);
      const timeout = Math.min(900_000, 180_000 + mib * 45_000);
      // The raw evidence file can hold a 256 KiB response preview. Extract a
      // bounded, valid JSON summary in the guest so serial framing stays intact.
      const probe = await this.requireSerial("attacker").exec(
        `python3 ~/exploit.py oom-probe --mib ${mib}${mib > 32 ? " --i-understand-oom" : ""}; latest=$(ls -t /home/tc/lab-evidence/probe-oom-*.json 2>/dev/null | head -1); echo "EVIDENCE_FILE=$latest"; if [ -n "$latest" ]; then python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));r=d.get("response_preview_latin1","");print("CR_PROBE_JSON "+json.dumps({"response_preview":r[:4000],"response_bytes":d.get("response_bytes"),"transport_error":d.get("transport_error"),"elapsed_ms":d.get("elapsed_ms"),"rce_claimed":d.get("rce_claimed")}))' "$latest"; fi`,
        timeout,
      );
      if (generation !== this.generation) return;
      const evidenceFile = /EVIDENCE_FILE=(\S+)/.exec(probe.output)?.[1] ?? "";
      if (!evidenceFile) throw new Error(`The guest research harness produced no evidence file: ${probe.output.slice(-1200)}`);
      // Take the marked summary line only: the harness also prints the HTTP
      // response, which could itself contain JSON.
      const summaryLine = probe.output.split("\n").find((line) => line.trim().startsWith("CR_PROBE_JSON "));
      if (!summaryLine) throw new Error(`The guest did not return a probe summary: ${probe.output.slice(-800)}`);
      const record = JSON.parse(summaryLine.trim().slice("CR_PROBE_JSON ".length)) as { response_preview?: string; transport_error?: string | null; elapsed_ms?: number; response_bytes?: number; rce_claimed?: boolean };
      const response = record.response_preview ?? "";
      if (record.rce_claimed === true) throw new Error("The guest harness reported an RCE claim; this lab does not accept harness claims as exploitation evidence.");
      const after = await this.command("target", "pidof httpd || true; printf '\\n'; labctl telemetry", 30_000);
      const telemetry = jsonFromOutput<Telemetry>(after.output);
      const phpLog = await this.command("target", "labctl logs php", 25_000);
      const errorLog = await this.command("target", "labctl logs error", 25_000);
      const accessLog = await this.command("target", "labctl logs access", 25_000);
      if (generation !== this.generation) return;
      const workersAfterPids = workerList(after.output.split("\n").slice(0, 1).join(" "));
      const outcome = classifyProbeOutcome({
        response,
        phpLog: phpLog.output,
        errorLog: errorLog.output,
        accessLog: accessLog.output,
        workersBefore: workersBeforePids.length,
        workersAfter: telemetry.apache_worker_count,
        transportError: record.transport_error ?? null,
        marker,
      });
      const observation: ProbeObservation = {
        id: marker,
        marker,
        mib,
        startedAt,
        finishedAt: new Date().toISOString(),
        httpStatus: outcome.httpStatus,
        responsePreview: response.slice(0, 20_000),
        targetPhpLog: phpLog.output.slice(-20_000),
        targetErrorLog: errorLog.output.slice(-20_000),
        targetAccessLog: accessLog.output.slice(-20_000),
        workersBefore: workersBeforePids.length,
        workersAfter: telemetry.apache_worker_count,
        workersBeforePids: workersBeforePids.join(" "),
        workersAfterPids: workersAfterPids.join(" "),
        attackerEvidence: evidenceFile,
        oomObserved: outcome.oomObserved,
        parserCapObserved: outcome.parserCapObserved,
        outcome: outcome.outcome,
        interpretation: outcome.interpretation,
      };
      this.patchExercise({ probe: observation });
      this.patch({ logs: { access: accessLog.output, error: errorLog.output, php: phpLog.output } });
      this.evidence("attacker", "http", `Controlled probe (${mib} MiB) transport record`, `attacker: python3 ~/exploit.py oom-probe --mib ${mib} · ${evidenceFile}`, probe.output);
      this.evidence("target", "log", "Probe result in the target's own logs", "target: /var/log/apache2/{php-error,error,access}.log", [phpLog.output, errorLog.output, accessLog.output].join("\n---\n"));
      this.patch({ notice: `Probe ${marker}: ${outcome.outcome}. ${outcome.interpretation}` });
      this.log(`Controlled probe finished with outcome "${outcome.outcome}" and target-side log capture.`, outcome.outcome === "transport-error" ? "warning" : "success");
      this.settleExerciseStatus();
      await this.persistReport();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.setStepFailure("reproduction", message);
      this.patch({ error: `Controlled reproduction failed: ${message}` });
      this.settleExerciseStatus();
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /** Step 6: check the target's own state and look for genuine execution evidence. */
  verifyTargetSide = async (): Promise<void> => {
    if (this.state.operation || !this.runtime.target || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const session = this.state.session;
    if (!session) return;
    const generation = this.generation;
    this.clearStepFailure("target-verification");
    this.patch({ operation: "Verifying target-side state", status: "testing", error: null });
    try {
      const workers = await this.command("target", "pidof httpd || true; printf '\\n'; labctl telemetry", 30_000);
      const phpLog = await this.command("target", "labctl logs php", 25_000);
      const proofStat = await this.command("target", "stat -c '%U %a %Y %n' /var/www/html/flag.txt; if [ -e /var/www/html/rce-proof.txt ]; then stat -c '%U %a %Y %s %n' /var/www/html/rce-proof.txt; else echo 'rce-proof.txt absent'; fi", 25_000);
      const evidenceCheck = await this.requireSerial("target").exec(`labctl evidence '${session.challenge}'`, 20_000);
      if (generation !== this.generation) return;
      const parsed = (() => {
        try {
          return jsonFromOutput<{ rce_evidence: boolean; owner: string; path: string; challenge_match: boolean }>(evidenceCheck.output);
        } catch {
          return null;
        }
      })();
      const genuineProof = Boolean(parsed && parsed.rce_evidence && parsed.owner === "apache" && parsed.challenge_match);
      if (genuineProof && parsed && !session.proof) {
        this.patch({ session: { ...session, proof: { observedAt: new Date().toISOString(), owner: parsed.owner, path: parsed.path, data: evidenceCheck.output } } });
        this.evidence("target", "rce-proof", "Apache-worker execution proof observed", "target: labctl evidence (ownership + challenge + session mtime)", evidenceCheck.output);
      }
      const summary = genuineProof
        ? "The target holds a fresh challenge file owned by apache whose content matches this session."
        : "No Apache-owned challenge proof exists for this session.";
      this.patchExercise({
        targetVerification: {
          observedAt: new Date().toISOString(),
          workers: workers.output.trim(),
          phpLogTail: phpLog.output.slice(-20_000),
          proofCheck: `${proofStat.output}\nlabctl evidence exit=${evidenceCheck.exitCode}\n${evidenceCheck.output}`.slice(-20_000),
          genuineProof,
          summary,
        },
      });
      this.evidence("target", "log", "Target-side verification", "target: pidof httpd, labctl telemetry, labctl evidence, /var/www/html stat", `${workers.output}\n${phpLog.output}\n${proofStat.output}\n${evidenceCheck.output}`);
      this.patch({ notice: summary, error: null });
      this.log(summary, genuineProof ? "success" : "info");
      this.settleExerciseStatus();
      await this.persistReport();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.setStepFailure("target-verification", message);
      this.patch({ error: `Target-side verification failed: ${message}` });
      this.settleExerciseStatus();
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /** Step 7: compare the running build against the verified patch and mitigations. */
  compareRemediation = async (): Promise<void> => {
    if (this.state.operation || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    this.clearStepFailure("remediation");
    this.patch({ operation: "Comparing builds and mitigations", status: "testing", error: null });
    try {
      const build = this.state.exercise.build;
      if (!build) throw new Error("The running build has not been inspected yet.");
      const patchedAsset = this.state.manifest?.targets.find((target) => target.buildRole === "patched");
      const patchedImageAvailable = Boolean(patchedAsset?.image.available);
      const patchMarkerPresent = build.observation.hardLimitDirective !== null;
      const comparison = [
        `Advisory ${ADVISORY.advisory} (${ADVISORY.id}) lists affected ${ADVISORY.affected.join(", ")} and patched ${ADVISORY.patched.join(", ")}.`,
        `This target runs PHP ${build.observation.phpVersion} with ${build.observation.sapi}; ${patchMarkerPresent ? "the 8.2.35 allocator patch marker is present" : `the ${PATCH_INI_MARKER} marker from the 8.2.35 allocator patch is absent`}.`,
        `Pinned sources re-verified: ${PINNED_SOURCES.map((source) => `${source.tag} ${source.sha256.slice(0, 16)}…`).join(", ")}.`,
        `First fixed 8.2 release: 8.2.${PATCHED_RELEASES["8.2"]}.`,
      ].join(" ");
      const limitation = patchedImageAvailable
        ? "The patched PHP 8.2.35 image is installed. Stop both machines, select it, cold-boot, and repeat the probe to compare observed behaviour."
        : "The PHP 8.2.35 comparison image is not provisioned in this workspace, so the patch comparison is established from the verified source diff and the running build's marker, not from a second boot.";
      const observation = {
        observedAt: new Date().toISOString(),
        runningBuild: `${build.classification} (PHP ${build.observation.phpVersion}, ${build.observation.sapi})`,
        patchMarkerPresent,
        patchedImageAvailable,
        comparison,
        advisoryGuidance: [...ADVISORY_GUIDANCE],
        limitation,
      };
      this.patchExercise({ remediation: observation });
      this.evidence("target", "system", "Remediation comparison", "verified advisory + pinned source diff + running build marker", `${comparison}\n\n${ADVISORY_GUIDANCE.map((item) => `- ${item}`).join("\n")}\n\n${limitation}`);
      this.patch({ notice: limitation, error: null });
      this.log("Remediation comparison recorded against the verified patch and the running build.", "success");
      this.settleExerciseStatus();
      await this.persistReport();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.setStepFailure("remediation", message);
      this.patch({ error: `Remediation comparison failed: ${message}` });
      this.settleExerciseStatus();
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /**
   * Explicitly labelled training simulation. It is a knowledge check answered
   * from observed build facts: no shell, no target effect, and never genuine
   * exploitation status.
   */
  answerSimulation = (questionId: string, choice: string): void => {
    const build = this.state.exercise.build;
    if (!build) {
      this.patch({ error: "The simulation is answered from observed values. Run reconnaissance first." });
      return;
    }
    if (this.state.completedAs === "genuine-rce") {
      this.patch({ error: "Genuine exploitation completion is already recorded; the simulation is not needed and will not be mixed with it." });
      return;
    }
    const question = SIMULATION_QUESTIONS.find((item) => item.id === questionId);
    if (!question) {
      this.patch({ error: `Unknown simulation question: ${questionId}` });
      return;
    }
    const answer = validateSimulationAnswer(question, choice, build);
    const previous = this.state.exercise.simulation;
    const answers = [...(previous?.answers ?? []).filter((item) => item.questionId !== questionId), answer];
    const passed = SIMULATION_QUESTIONS.every((item) => answers.find((entry) => entry.questionId === item.id && entry.correct));
    this.patchExercise({
      simulation: {
        answers,
        passed,
        completedAt: passed ? new Date().toISOString() : undefined,
        note: "Training simulation. It checks your reading of the real guest configuration; it does not exercise the target and is not RCE evidence.",
      },
    });
    if (passed) {
      this.patch({
        completedAs: "simulated-exercise",
        notice: "Training simulation complete. This is recorded as SIMULATION ONLY: no target-side code execution, no shell, and no genuine CTF completion.",
      });
      this.evidence("attacker", "system", "Training simulation completed (not exploitation)", "parent UI knowledge check answered from observed target facts", answers.map((entry) => `${entry.questionId}: ${entry.choice} (${entry.correct ? "correct" : "incorrect"})`).join("\n"));
      this.log("Training simulation completed and labelled as simulated; genuine exploitation status is unchanged.", "warning");
    } else {
      this.patch({ notice: answer.correct ? `Correct: ${question.because}` : `Not correct. Observed value: ${answer.observedValue}. ${question.because}` });
    }
    this.settleExerciseStatus();
    void this.persistReport();
  };

  /**
   * Reset the exercise against the real guest: cold-boot the target, generate a
   * new session flag and challenge inside it, remove the previous proof, and
   * clear parent-side progress only after the guest confirms the new state.
   */
  resetExercise = async (): Promise<void> => {
    if (this.state.operation) return;
    const runtime = this.runtime.target;
    const session = this.state.session;
    if (!runtime || !session || !this.sessionProvisioned) {
      this.patch({ error: "A running, provisioned target is required to reset the exercise. Start the lab first." });
      return;
    }
    const generation = ++this.generation;
    const previousDigest = session.flagSha256;
    this.telemetryRunning = false;
    runtime.serial.cancelCommands(new Error("Target exercise reset"));
    this.targetSerialSealed = false;
    this.patch({ operation: "Resetting the target exercise", status: "resetting", error: null, completedAs: null });
    try {
      const challenge = randomToken(24);
      this.patch({
        session: { ...session, challenge, flagSha256: "", proof: undefined, flagSubmittedAt: undefined },
        exercise: emptyExercise(),
      });
      runtime.emulator.restart();
      await runtime.serial.waitFor(/[$#] /, BOOT_TIMEOUT, false);
      if (generation !== this.generation) return;
      await this.provisionTarget(runtime.serial);
      if (generation !== this.generation) return;
      await this.waitGuestReady("target", false);
      this.patch({ status: "initializing-network", checks: NETWORK_CHECKS.map((check) => ({ ...check })) });
      await this.verifyNetwork(generation);
      await this.refreshTarget(false);
      if (generation !== this.generation) return;
      const proofCheck = await this.requireSerial("target").exec("if [ -e /var/www/html/rce-proof.txt ]; then stat -c '%U %a %Y %n' /var/www/html/rce-proof.txt; else echo 'rce-proof.txt absent'; fi; stat -c '%U %G %a %n' /var/www/html/flag.txt", 20_000);
      if (generation !== this.generation) return;
      const newDigest = this.state.session?.flagSha256 ?? "";
      const rotated = Boolean(previousDigest && newDigest && newDigest !== previousDigest);
      if (!newDigest || newDigest === previousDigest) throw new Error("The target reported the same flag digest after reset; a fresh session-specific flag was not generated.");
      if (!proofCheck.output.includes("rce-proof.txt absent")) throw new Error("The previous execution proof still exists after the target reset.");
      this.targetSerialSealed = true;
      this.patch({ status: "ready" });
      this.evidence("target", "system", "Target exercise reset verified in the guest", "target: labctl provision + stat /var/www/html", `previous_flag_sha256=${previousDigest.slice(0, 16)}…\nnew_flag_sha256=${newDigest.slice(0, 16)}…\nrotated=${rotated}\n${proofCheck.output}`);
      this.patch({ notice: "Target reset verified in the guest: new session flag and challenge generated inside the target, previous proof removed, parent progress cleared." });
      this.log("Exercise reset against the real target; a new session-specific flag was generated inside the guest.", "success");
      await this.persistReport();
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.handleFailure(error, "Exercise reset failed");
      this.patch({ error: `Exercise reset failed: ${message}` });
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /** Bounded recovery: resume paused emulators, and reboot only an unresponsive guest. */
  recoverGuests = async (): Promise<void> => {
    if (this.state.operation || !this.state.session) return;
    const generation = this.generation;
    this.patch({ operation: "Checking guest responsiveness", error: null });
    const attempts = (this.state.recovery?.attempts ?? 0) + 1;
    try {
      for (const machine of ["attacker", "target"] as const) {
        const runtime = this.runtime[machine];
        if (!runtime) throw new Error(`${machine} is not running; use Start lab.`);
        if (!runtime.emulator.is_running()) {
          await runtime.emulator.run();
          if (!runtime.emulator.is_running()) throw new Error(`${machine} v86 could not be resumed.`);
        }
        try {
          await runtime.serial.exec("labctl ready", 25_000);
        } catch (error) {
          if (generation !== this.generation) return;
          this.patch({ recovery: { attempts, lastAt: new Date().toISOString(), detail: `${machine} was unresponsive; rebooting it.` } });
          this.log(`${machine} did not answer labctl ready; performing a real v86 reboot.`, "warning");
          this.patch({ operation: null });
          await this.rebootMachine(machine);
          return;
        }
      }
      this.patch({
        recovery: { attempts, lastAt: new Date().toISOString(), detail: "Both guests answered labctl ready." },
        notice: "Both guests responded to real readiness checks; no reset was needed.",
      });
      this.log("Guest responsiveness verified.", "success");
    } catch (error) {
      if (generation !== this.generation) return;
      this.patch({ recovery: { attempts, lastAt: new Date().toISOString(), detail: error instanceof Error ? error.message : String(error) } });
      this.patch({ error: `Recovery failed: ${error instanceof Error ? error.message : String(error)}` });
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  /** Exposed for the UI so a step is never shown as complete without its facts. */
  exerciseSummary = (): ReturnType<typeof evaluateExercise> => evaluateExercise(this.state);

  submitFlag = async (value: string): Promise<boolean> => {
    const session = this.state.session;
    const generation = this.generation;
    if (!session) {
      this.patch({ error: "Start a lab before submitting a flag." });
      return false;
    }
    const progress = evaluateExercise(this.state);
    const unmet = progress.steps.filter((step) => step.id !== "completion" && step.status !== "passed");
    if (unmet.length) {
      this.patch({ error: `The completion step unlocks only after its real requirements are met. Outstanding: ${unmet.map((step) => step.title).join(", ")}.` });
      return false;
    }
    const submitted = value.trim();
    const digest = await sha256Text(submitted);
    if (generation !== this.generation || session.id !== this.state.session?.id) return false;
    if (digest !== session.flagSha256) {
      this.patch({ error: "Flag does not match this lab session. No completion was awarded." });
      return false;
    }
    if (!session.proof) {
      this.patch({ error: "The flag matches, but fresh Apache-worker execution evidence is absent. Reading the flag through administration, a snapshot, or this client is not sufficient." });
      return false;
    }
    const check = validateGenuineCompletion({ session: { ...session, flagSubmittedAt: new Date().toISOString() }, completedAs: "genuine-rce" });
    if (!check.ok) {
      this.patch({ error: `Genuine completion was refused: ${check.reason}` });
      return false;
    }
    const flagSubmittedAt = new Date().toISOString();
    this.patch({
      session: { ...session, flagSubmittedAt },
      status: "completed",
      completedAs: "genuine-rce",
      hasUnsavedProgress: true,
      error: null,
      notice: "Genuine RCE completion awarded: target-owned challenge proof and the matching guest flag are both present.",
    });
    this.evidence("target", "rce-proof", "Flag submission validated", "client hash comparison + prior target-owned execution proof", `flag_sha256=${digest}\nproof_observed=${session.proof.observedAt}\nproof_owner=${session.proof.owner}`);
    this.log("Lab completed with genuine target evidence; no simulation credit was used.", "success");
    await this.persistReport();
    return true;
  };

  saveState = async (): Promise<void> => {
    if (this.state.operation || !this.state.session || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const generation = this.generation;
    const session = this.state.session;
    const attacker = this.runtime.attacker?.emulator;
    const target = this.runtime.target?.emulator;
    if (!attacker || !target || !session.flagSha256 || !this.sessionProvisioned || !this.targetSerialSealed) {
      this.patch({ error: "Both verified running guests, a sealed target console, and target-generated session provisioning are required for a consistent snapshot." });
      return;
    }
    this.patch({ operation: "Saving both VM states", error: null });
    try {
      const [attackerBuffer, targetBuffer] = await Promise.all([attacker.save_state(), target.save_state()]);
      if (generation !== this.generation) return;
      const now = new Date().toISOString();
      const meta: SnapshotMeta = {
        id: `snapshot-${randomToken(8)}`,
        createdAt: now,
        sessionId: session.id,
        phpVersion: session.phpVersion,
        attackerBytes: attackerBuffer.byteLength,
        targetBytes: targetBuffer.byteLength,
        v86Version: "0.5.472",
      };
      const record: SnapshotRecord = {
        meta,
        session,
        resourceMode: this.state.resourceMode,
        attacker: attackerBuffer,
        target: targetBuffer,
      };
      await saveSnapshot(record);
      const snapshots = await listSnapshots();
      if (generation !== this.generation) return;
      this.patch({ snapshots, hasUnsavedProgress: false, notice: `Saved two v86 state images (${Math.round((meta.attackerBytes + meta.targetBytes) / 1024 / 1024)} MiB total) in browser-local storage.` });
      await this.persistReport();
      if (generation !== this.generation) return;
      this.log("Both VM state images saved. Restore will still rerun network and service checks.", "success");
    } catch (error) {
      if (generation !== this.generation) return;
      const message = error instanceof Error ? error.message : String(error);
      this.patch({ error: `State save failed. Browser quota is often the limiting factor; no partial snapshot is considered usable. ${message}` });
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  deleteSnapshot = async (id: string): Promise<void> => {
    try {
      await deleteStoredSnapshot(id);
      this.patch({ snapshots: await listSnapshots(), notice: "Browser-local snapshot deleted." });
    } catch (error) {
      this.patch({ error: error instanceof Error ? error.message : String(error) });
    }
  };

  rebootMachine = async (machine: MachineId): Promise<void> => {
    if (this.state.operation || !["ready", "testing", "completed"].includes(this.state.status)) return;
    const runtime = this.runtime[machine];
    const session = this.state.session;
    if (!runtime || !session || !this.sessionProvisioned) {
      this.patch({ error: `${machine} is not running with a target-provisioned session.` });
      return;
    }
    const generation = ++this.generation;
    this.telemetryRunning = false;
    runtime.serial.cancelCommands(new Error(`${machine} is rebooting`));
    if (machine === "target") this.targetSerialSealed = false;
    this.patch({ operation: `Rebooting ${machine}`, status: machine === "attacker" ? "booting-attacker" : "booting-target", error: null });
    this.patchMachine(machine, { status: "booting", detail: "v86 hardware reset in progress", error: undefined });
    try {
      runtime.emulator.restart();
      await runtime.serial.waitFor(/[$#] /, BOOT_TIMEOUT, false);
      if (machine === "target") {
        this.patch({ session: { ...session, proof: undefined, flagSubmittedAt: undefined }, completedAs: null });
        await this.provisionTarget(runtime.serial);
      }
      await this.waitGuestReady(machine, false);
      this.patch({ status: "initializing-network", checks: NETWORK_CHECKS.map((check) => ({ ...check })) });
      await this.verifyNetwork(generation);
      await this.refreshTarget(false);
      if (machine === "target") this.targetSerialSealed = true;
      this.patch({ status: this.state.completedAs ? "completed" : "ready", notice: `${machine} rebooted through v86 and all guest/network checks passed again.` });
      this.log(`${machine} reboot and post-boot verification completed.`, "success");
    } catch (error) {
      if (generation === this.generation) this.handleFailure(error, `${machine} reboot failed`);
    } finally {
      if (generation === this.generation) this.patch({ operation: null });
    }
  };

  stopBoth = async (): Promise<void> => {
    const generation = ++this.generation;
    this.patch({ operation: "Stopping both machines" });
    await this.destroyRuntimes();
    if (generation !== this.generation) return;
    this.patch({
      status: "not-started",
      operation: null,
      machines: {
        attacker: { ...this.state.machines.attacker, status: "stopped", detail: "v86 instance destroyed; restart boots from prepared media" },
        target: { ...this.state.machines.target, status: "stopped", detail: "v86 instance destroyed; restart boots from prepared media" },
      },
      notice: "Both emulators and their isolated network are stopped. Unsaved guest changes are gone; evidence remains in the report.",
    });
    this.log("Both v86 instances stopped by the parent interface.");
  };

  resetLab = async (): Promise<void> => {
    const generation = ++this.generation;
    this.patch({ operation: "Resetting lab", status: "resetting", error: null });
    await this.destroyRuntimes();
    if (generation !== this.generation) return;
    const snapshots = this.state.snapshots;
    this.sessionProvisioned = false;
    this.state = { ...freshState(), snapshots, resourceMode: this.state.resourceMode, selectedTarget: this.state.selectedTarget, manifest: this.state.manifest };
    this.emit();
    this.patch({ operation: null, notice: "Session, flag, challenge, exercise progress, proxy history, and guest changes were reset. Cached verified assets and explicitly saved snapshots were retained." });
    await clearProgress("last-report").catch(() => undefined);
    this.log("Lab reset to its initial not-started state.");
  };

  private async destroyRuntimes(): Promise<void> {
    if (this.telemetryTimer) {
      clearInterval(this.telemetryTimer);
      this.telemetryTimer = null;
    }
    const machines = Object.values(this.runtime);
    this.runtime = {};
    await Promise.allSettled(machines.map(async ({ emulator, serial }) => {
      serial.destroy();
      await emulator.destroy();
    }));
    this.releaseNetworkLock();
    if (this.wasmUrl) URL.revokeObjectURL(this.wasmUrl);
    this.wasmUrl = null;
    this.images = null;
    this.telemetryRunning = false;
    this.targetSerialSealed = false;
  }

  private handleFailure(error: unknown, prefix: string): void {
    const message = error instanceof Error ? error.message : String(error);
    if (message === "Operation superseded by a lab reset") return;
    this.patch({ status: "failed", error: `${prefix}: ${message}` });
    this.log(`${prefix}: ${message}`, "error");
  }

  private async persistReport(): Promise<void> {
    if (!this.state.session) return;
    await saveProgress("last-report", {
      session: this.state.session,
      evidence: this.state.evidence,
      checks: this.state.checks,
      exercise: this.state.exercise,
      completedAs: this.state.completedAs,
      savedAt: new Date().toISOString(),
    }).catch((error) => this.patch({ notice: `Report persistence failed: ${error instanceof Error ? error.message : String(error)}` }));
  }
}
