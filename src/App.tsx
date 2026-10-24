import { useState } from "react";
import { Activity, BookOpen, Box, CheckCircle2, ChevronRight, CircleStop, Flag, FlaskConical, HardDrive, History, MemoryStick, Monitor, Network, Play, RefreshCw, RotateCcw, Save, Server, ShieldCheck, Square, X } from "lucide-react";
import { useLab } from "./lib/LabContext";
import { STATUS_LABELS } from "./types";
import { AttackerView } from "./views/AttackerView";
import { TargetView } from "./views/TargetView";
import { NetworkView } from "./views/NetworkView";
import { GuideView } from "./views/GuideView";
import { LabView } from "./views/LabView";
import { InlineMessage, StatusPill } from "./components/ui";
import { formatBytes, formatTime } from "./lib/utils";

interface Confirmation {
  title: string;
  description: string;
  confirmLabel: string;
  action: () => Promise<void>;
}

const navigation = [
  { id: "attacker" as const, label: "ATTACKER WORKSTATION", icon: Monitor },
  { id: "target" as const, label: "TARGET SERVER HOUSING", icon: Server },
  { id: "network" as const, label: "NETWORK TOPOLOGY", icon: Network },
  { id: "lab" as const, label: "VULNERABILITY LAB", icon: FlaskConical },
  { id: "guide" as const, label: "LAB GUIDE", icon: BookOpen },
];

export default function App() {
  const { controller, state } = useLab();
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const busy = Boolean(state.operation);
  const running = ["ready", "testing", "completed"].includes(state.status);
  const active = state.status !== "not-started";
  const allocatedRam = state.machines.attacker.ramMiB! + state.machines.target.ramMiB!;
  const latestActivity = state.activity[0];

  const guarded = (title: string, description: string, confirmLabel: string, action: () => Promise<void>, always = false) => {
    if (state.hasUnsavedProgress || always) setConfirmation({ title, description, confirmLabel, action });
    else void action();
  };
  const restore = (id: string) => guarded("Restore VM states and replace this session?", "Restoring boots both saved v86 states and revalidates their actual network/services. Any unsaved changes in the current session will be discarded. Export evidence first if needed.", "Restore states", () => controller.restoreSnapshot(id));
  const executeConfirmation = async () => {
    if (!confirmation) return;
    setConfirmBusy(true);
    await confirmation.action();
    setConfirmBusy(false);
    setConfirmation(null);
  };

  return <div className="app-shell">
    <header className="app-header">
      <div className="brand-row">
        <button className="brand" onClick={() => controller.setView("attacker")} aria-label="Enterprise Cyber Range home"><span className="brand-mark"><ShieldCheck size={24} /></span><span><strong>ENTERPRISE <b>CYBER RANGE</b></strong><small>CVE-2026-109618 · PHP2Shell Dual-OS Simulation</small></span></button>
        <div className="brand-right">
          <span className="environment-badge"><span className="pulse-dot" />REAL x86 GUESTS</span>
          <span className="session-badge">{state.session ? <>SESSION <code>{state.session.id}</code></> : "NO ACTIVE SESSION"}</span>
          <StatusPill status={state.status} label={STATUS_LABELS[state.status]} />
        </div>
      </div>
      <nav className="top-navigation" aria-label="Lab views">
        {navigation.map(({ id, label, icon: Icon }) => <button key={id} className={state.view === id ? "active" : ""} onClick={() => controller.setView(id)} aria-current={state.view === id ? "page" : undefined}><Icon size={15} /><span>{label}</span>{id === "lab" && <b>{controller.exerciseSummary().steps.filter((step) => step.status === "passed").length}/8</b>}</button>)}
      </nav>
    </header>

    <section className="control-deck" aria-label="Virtual machine controls">
      <div className="primary-controls">
        <button className="button primary" onClick={() => guarded("Start a fresh boot and discard unsaved work?", "The current session has unsaved progress. Starting again reinitializes the guests from prepared media. Export evidence first if you need it.", "Start lab", () => controller.startLab())} disabled={busy || running}><Play size={15} />{state.status === "failed" ? "Retry start" : running ? "Lab running" : "Start lab"}</button>
        <button className="button secondary" onClick={() => guarded("Reset the entire lab?", "This destroys both running guests, the session flag/challenge, current evidence, and proxy history. Cached assets and explicitly saved snapshots are retained.", "Reset lab", () => controller.resetLab(), active && state.hasUnsavedProgress)} disabled={!active && !state.evidence.length}><RotateCcw size={15} />Reset lab</button>
        <span className="control-divider" />
        <button className="button ghost" onClick={() => guarded("Reboot attacker and discard guest changes?", "The attacker will go through a real v86 hardware reset and cold boot. Unsaved guest files and proxy history in RAM will be lost.", "Reboot attacker", () => controller.rebootMachine("attacker"))} disabled={busy || !running}><RefreshCw size={14} />Reboot attacker</button>
        <button className="button ghost" onClick={() => guarded("Reboot target and discard guest changes?", "The target will go through a real v86 hardware reset and cold boot. Current proof must be reproduced afterward. Unsaved target changes will be lost.", "Reboot target", () => controller.rebootMachine("target"))} disabled={busy || !running}><RefreshCw size={14} />Reboot target</button>
      </div>
      <div className="secondary-controls">
        <button className="button ghost" onClick={() => void controller.saveState()} disabled={busy || !running}><Save size={14} />Save state</button>
        <button className="button ghost" onClick={() => state.snapshots[0] && restore(state.snapshots[0].id)} disabled={busy || !state.snapshots.length}><History size={14} />Restore state</button>
        <button className="button ghost danger-text" onClick={() => guarded("Stop both machines?", "Both v86 instances will be destroyed. Unsaved guest changes will be lost; report evidence remains available.", "Stop both", () => controller.stopBoth())} disabled={!active && !busy}><Square size={13} />Stop both machines</button>
        <span className="control-divider" />
        <button className="button ghost" onClick={() => controller.setView("guide")}><BookOpen size={14} />Lab instructions</button>
      </div>
    </section>

    {state.assetProgress && <div className="asset-progress"><div><span>{state.assetProgress.label}</span><strong>{formatBytes(state.assetProgress.loaded)} / {formatBytes(state.assetProgress.total)}</strong></div><div className="progress-track"><span style={{ width: `${state.assetProgress.total ? Math.min(100, state.assetProgress.loaded / state.assetProgress.total * 100) : 0}%` }} /></div></div>}
    {state.operation && !state.assetProgress && <div className="operation-strip"><Activity size={14} className="pulse" /><span>{state.operation}</span><small>Parent controls remain available</small></div>}
    {state.error && <div className="global-message"><InlineMessage type="error" onClose={controller.clearMessages}>{state.error}</InlineMessage></div>}
    {state.notice && !state.error && <div className="global-message"><InlineMessage type="info" onClose={controller.clearMessages}>{state.notice}</InlineMessage></div>}

    <main className="main-content">
      <div hidden={state.view !== "attacker"}><AttackerView /></div>
      <div hidden={state.view !== "target"}><TargetView /></div>
      <div hidden={state.view !== "network"}><NetworkView /></div>
      <div hidden={state.view !== "guide"}><GuideView /></div>
      <div hidden={state.view !== "lab"}><LabView /></div>
    </main>

    <footer className="app-footer">
      <div><span><Box size={13} />v86 0.5.472</span><span><HardDrive size={13} />Pinned local assets</span><span><Network size={13} />No backend / no relay</span><span><MemoryStick size={13} />{allocatedRam} MiB guest RAM</span></div>
      {latestActivity && <div className={`footer-activity ${latestActivity.level}`}><span>{latestActivity.level === "success" ? <CheckCircle2 size={13} /> : <Activity size={13} />}</span><span>{latestActivity.message}</span><time>{formatTime(latestActivity.timestamp)}</time></div>}
    </footer>

    {confirmation && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !confirmBusy) setConfirmation(null); }}>
      <section className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
        <button className="icon-button modal-close" onClick={() => setConfirmation(null)} disabled={confirmBusy} aria-label="Cancel"><X size={17} /></button>
        <span className="confirm-icon"><CircleStop size={25} /></span><span className="eyebrow">CONFIRM SESSION CHANGE</span><h2 id="confirm-title">{confirmation.title}</h2><p>{confirmation.description}</p>
        <div className="confirm-note"><Flag size={15} /><span>Need to keep this work? Cancel and save both VM states first. Exercise progress is re-derived from guest evidence after a restart.</span></div>
        <div className="modal-actions"><button className="button secondary" onClick={() => setConfirmation(null)} disabled={confirmBusy}>Cancel</button><button className="button danger" onClick={() => void executeConfirmation()} disabled={confirmBusy}>{confirmBusy ? "Working…" : confirmation.confirmLabel}<ChevronRight size={15} /></button></div>
      </section>
    </div>}
  </div>;
}
