import { BookOpen, Box, Check, ChevronRight, CircleSlash2, Cpu, FileCode2, Globe2, HardDrive, MemoryStick, Network, Play, ScanLine, ShieldCheck, Terminal, Waypoints, Wrench } from "lucide-react";
import { useLab } from "../lib/LabContext";
import { VmScreen } from "../components/VmScreen";
import { EmptyState, KeyValue, PageHeading, Panel, StatusPill } from "../components/ui";
import { formatBytes, shortHash } from "../lib/utils";

export function AttackerView() {
  const { controller, state } = useLab();
  const guest = state.machines.attacker;
  const running = !["offline", "stopped"].includes(guest.status);
  const ready = ["ready", "testing", "completed"].includes(state.status);
  const selected = state.manifest?.targets.find((target) => target.id === state.selectedTarget);
  const ram = state.resourceMode === "low" ? 640 : 896;
  const hasBrowser = state.attackerTools.includes("dillo-beta") || state.attackerTools.includes("dillo");

  return <div className="view attacker-view">
    <PageHeading index="01" eyebrow="ATTACKER WORKSTATION" title="Your foothold in the range" description="A real Tiny Core x86 desktop with guest-hosted tooling, connected to one isolated assessment target."
      actions={<><StatusPill status={guest.status} /><span className="address-chip"><Network size={14} />192.168.10.10<span>/24</span></span></>} />

    <div className="workstation-grid">
      <div className="workstation-primary">
        <VmScreen machine="attacker" allowSerial />
        <div className="under-screen-note"><ShieldCheck size={14} /><span>Actual v86 display output. View changes never stop this guest.</span><span className="mono">Buildroot alternative: not used · Tiny Core profile selected</span></div>
      </div>

      <aside className="workstation-sidebar">
        {running ? <>
          <Panel eyebrow="GUEST APPLICATIONS" title="Launch on workstation">
            <div className="app-launcher-list">
              <button onClick={() => void controller.launchAttackerTool("browser")} disabled={!ready || !hasBrowser}>
                <span className="app-icon teal"><Globe2 size={20} /></span><span><strong>HTTP browser</strong><small>Dillo · real target responses</small></span><ChevronRight size={16} />
              </button>
              <button onClick={() => void controller.launchAttackerTool("proxy")} disabled={!ready || !hasBrowser || state.proxyStatus !== "running"}>
                <span className="app-icon amber"><Waypoints size={20} /></span><span><strong>RangeProxy</strong><small>Intercept + repeater · not Burp</small></span><ChevronRight size={16} />
              </button>
              <button onClick={() => void controller.launchAttackerTool("terminal")} disabled={!ready || (!state.attackerTools.includes("aterm") && !state.attackerTools.includes("xterm"))}>
                <span className="app-icon blue"><Terminal size={20} /></span><span><strong>Guest terminal</strong><small>xterm/aterm · real shell</small></span><ChevronRight size={16} />
              </button>
            </div>
            <button className="button secondary full-width" onClick={() => void controller.runBaseline()} disabled={!ready || Boolean(state.operation)}><ScanLine size={15} />Run guest baseline request</button>
            <button className="button secondary full-width" onClick={() => void controller.runProxyBaseline()} disabled={!ready || state.proxyStatus !== "running" || Boolean(state.operation)} title="Guest curl through RangeProxy, with target log corroboration"><Waypoints size={15} />Run guest proxy request</button>
          </Panel>

          <Panel eyebrow="VERIFIED IN-GUEST" title="Binary inventory" action={<Wrench size={16} />}>
            {state.attackerTools.length ? <div className="tool-tags">{state.attackerTools.map((tool) => <span key={tool}><Check size={11} />{tool}</span>)}</div> : <p className="muted">Waiting for the guest's command -v inventory…</p>}
            <p className="panel-footnote">Only executables reported by the running guest appear here. <span className="mono">~/exploit.py</span> uses the guest Python interpreter.</p>
          </Panel>

          <Panel eyebrow="VIRTUAL HARDWARE" title="Machine allocation">
            <KeyValue label="Guest OS" value={guest.guestOs ?? "Tiny Core Linux 11.0"} />
            <KeyValue label="Architecture" value={guest.architecture ?? "x86"} mono />
            <KeyValue label="Allocated RAM" value={`${guest.ramMiB} MiB`} />
            <KeyValue label="Network adapter" value="NE2000 / ne2k-pci" mono />
            <KeyValue label="Proxy process" value={<StatusPill status={state.proxyStatus === "running" ? "ready" : "warning"} label={state.proxyStatus} />} />
          </Panel>
        </> : <>
          <Panel eyebrow="COLD BOOT CONFIGURATION" title="Range resources" action={<Cpu size={17} />}>
            <div className="resource-selector">
              <button className={state.resourceMode === "standard" ? "selected" : ""} onClick={() => controller.setResourceMode("standard")}><strong>Standard</strong><span>384 + 512 MiB</span><small>Recommended desktop</small></button>
              <button className={state.resourceMode === "low" ? "selected" : ""} onClick={() => controller.setResourceMode("low")}><strong>Lower resource</strong><span>256 + 384 MiB</span><small>Slower guest services</small></button>
            </div>
            <div className="resource-summary"><MemoryStick size={17} /><div><strong>{ram} MiB guest RAM</strong><span>Plus WASM, images, and browser overhead. Allow ~{state.resourceMode === "low" ? "1.0" : "1.5"} GiB free memory.</span></div></div>
          </Panel>

          <Panel eyebrow="TARGET ARTIFACT" title="PHP build profile">
            <label className="field-label" htmlFor="target-build">Boot target</label>
            <select id="target-build" className="select" value={state.selectedTarget} onChange={(event) => controller.selectTarget(event.target.value)}>
              {(state.manifest?.targets ?? [{ id: "alpine-php-8.2.34", phpVersion: "8.2.34", buildRole: "vulnerable" }, { id: "alpine-php-8.2.35", phpVersion: "8.2.35", buildRole: "patched" }]).map((target) => <option key={target.id} value={target.id}>PHP {target.phpVersion} · {target.buildRole}</option>)}
            </select>
            <div className="artifact-detail">
              <span className={`artifact-icon ${selected?.image.available ? "ok" : "missing"}`}>{selected?.image.available ? <Check size={18} /> : <CircleSlash2 size={18} />}</span>
              <div><strong>{selected?.image.available ? "Image verified in manifest" : "Image not provisioned"}</strong><span>{selected ? `${formatBytes(selected.image.bytes)} · SHA-256 ${shortHash(selected.image.sha256, 16)}` : "Loading asset manifest…"}</span></div>
            </div>
            <p className="panel-footnote">The patched image is a comparison profile, not a mitigation applied to the vulnerable VM. Source-built Apache prefork/mod_php is required.</p>
          </Panel>

          <Panel eyebrow="BEFORE YOU START" title="Offline asset preflight">
            <div className="preflight-list">
              <div><HardDrive size={15} /><span>Attacker ISO</span><strong className={state.manifest?.attacker.image.available ? "text-success" : "text-warning"}>{state.manifest?.attacker.image.available ? "Present" : "Missing"}</strong></div>
              <div><Box size={15} /><span>Target ISO</span><strong className={selected?.image.available ? "text-success" : "text-warning"}>{selected?.image.available ? "Present" : "Missing"}</strong></div>
              <div><FileCode2 size={15} /><span>v86 + firmware</span><strong className={state.manifest?.v86.wasm.available ? "text-success" : "text-warning"}>{state.manifest?.v86.wasm.available ? "Pinned" : "Missing"}</strong></div>
            </div>
            <p className="panel-footnote">Missing or corrupt media fails closed with a technical error. No simulated desktop is substituted.</p>
            <button className="button text-button full-width" onClick={() => controller.setView("guide")}><BookOpen size={15} />Read requirements & troubleshooting</button>
          </Panel>
        </>}
      </aside>
    </div>
    {!running && <div className="start-banner"><div><span className="eyebrow">TWO MACHINES. ZERO BACKEND.</span><h2>Initialize the isolated assessment network</h2><p>Downloads only pinned local assets, then verifies real guest boot, network, HTTP, and logs before reporting Ready.</p></div><button className="button primary large" onClick={() => void controller.startLab()} disabled={Boolean(state.operation)}><Play size={18} />Start lab</button></div>}
    {running && state.attackerTools.length === 0 && <EmptyState title="Waiting for guest inventory">Tools are shown after the attacker itself reports them.</EmptyState>}
  </div>;
}
