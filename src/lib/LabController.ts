import type { V86, V86Options } from "v86";
import type {
  AssetManifest,
  EvidenceRecord,
  LabState,
  MachineId,
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
import { clampText, jsonFromOutput, randomToken, sha256Text } from "./utils";

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
      const report = await loadProgress<{ session: SessionInfo; evidence: EvidenceRecord[]; checks: LabState["checks"]; completedAs: LabState["completedAs"] } | null>("last-report");
      if (report && report.session && Array.isArray(report.evidence) && Array.isArray(report.checks)) {
        this.patch({ session: report.session, evidence: report.evidence, checks: report.checks, completedAs: report.completedAs ?? null, hasUnsavedProgress: false });
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
      this.patch({ evidence: [], hasUnsavedProgress: false });
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
      const result = await this.command("attacker", `curl --noproxy '*' --max-time 20 -sS -i 'http://192.168.10.55/health.php?evidence=${id}'`, 30_000);
      if (generation !== this.generation) return;
      if (!/HTTP\/1\.[01] 200/.test(result.output)) throw new Error(`Baseline did not return HTTP 200: ${result.output}`);
      this.evidence("attacker", "http", "Learner baseline request", `attacker: curl -i http://192.168.10.55/health.php?evidence=${id}`, result.output);
      const logs = await this.command("target", "labctl logs access");
      if (generation !== this.generation) return;
      this.patch({ logs: { ...this.state.logs, access: logs.output }, notice: "Baseline response captured from the target and corroborated by its guest access log." });
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

  submitFlag = async (value: string): Promise<boolean> => {
    const session = this.state.session;
    const generation = this.generation;
    if (!session) {
      this.patch({ error: "Start a lab before submitting a flag." });
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
    this.patch({ operation: null, notice: "Session, flag, challenge, proxy history, and guest changes were reset. Cached verified assets and explicitly saved snapshots were retained." });
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
      completedAs: this.state.completedAs,
      savedAt: new Date().toISOString(),
    }).catch((error) => this.patch({ notice: `Report persistence failed: ${error instanceof Error ? error.message : String(error)}` }));
  }
}
