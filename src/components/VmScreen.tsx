import { useState } from "react";
import { Expand, Monitor, Play, TerminalSquare } from "lucide-react";
import { useLab } from "../lib/LabContext";
import type { MachineId } from "../types";
import { SerialTerminal } from "./SerialTerminal";
import { StatusPill } from "./ui";

export function VmScreen({ machine, allowSerial = false, compact = false }: { machine: MachineId; allowSerial?: boolean; compact?: boolean }) {
  const { controller, state } = useLab();
  const [mode, setMode] = useState<"display" | "serial">("display");
  const guest = state.machines[machine];
  const offline = ["offline", "stopped"].includes(guest.status);
  const active = state.view === machine;

  return <div id={`vm-${machine}`} className={`vm-window ${compact ? "compact" : ""}`}>
    <div className="vm-titlebar">
      <div className="vm-title"><span className={`window-led ${guest.status === "ready" ? "online" : ""}`} /><strong>{machine === "attacker" ? "attacker-workstation" : "assessment-target"}</strong><span>/ {mode === "display" ? "tty1" : "ttyS0"}</span></div>
      <div className="vm-window-actions">
        {allowSerial && <div className="segmented small"><button className={mode === "display" ? "active" : ""} onClick={() => setMode("display")} title="Actual VGA display"><Monitor size={13} />Display</button><button className={mode === "serial" ? "active" : ""} onClick={() => setMode("serial")} title="Real guest serial shell"><TerminalSquare size={13} />Serial</button></div>}
        <button className="icon-button" onClick={() => controller.fullscreen(machine)} disabled={offline} title="Fullscreen actual guest display"><Expand size={15} /></button>
      </div>
    </div>
    <div className={`vm-stage ${active ? "focused" : ""}`} onPointerDown={() => active && controller.focusMachine(machine)}>
      <div className="v86-screen" hidden={mode !== "display"} ref={(element) => controller.registerScreen(machine, element)}>
        <div style={{ whiteSpace: "pre", font: "14px monospace", lineHeight: "14px" }} />
        <canvas style={{ display: "none" }} />
      </div>
      {allowSerial && <div className="serial-screen" hidden={mode !== "serial"}><SerialTerminal machine={machine} /></div>}
      {offline && <div className="vm-offline">
        <div className="offline-emblem"><Monitor size={30} /></div>
        <h3>{guest.status === "stopped" ? "Guest stopped" : "Guest not started"}</h3>
        <p>{machine === "attacker" ? "Boot the prepared Tiny Core x86 graphical workstation." : "Boot Alpine x86 with the Apache/mod_php target."}</p>
        {machine === "attacker" && <button className="button primary" onClick={() => void controller.startLab()}><Play size={15} />Start lab</button>}
      </div>}
      {!offline && guest.status === "booting" && <div className="boot-ribbon"><span className="pulse-dot" />Actual guest boot in progress · watch the display for kernel output</div>}
    </div>
    <div className="vm-statusbar">
      <StatusPill status={guest.status} />
      <span>{guest.ramMiB ?? "—"} MiB RAM</span><span>NE2000</span><span className="vm-input-hint">{active ? "Click display to capture keyboard + mouse" : "Display remains running in background"}</span>
    </div>
    {guest.error && <div className="vm-error">{guest.error}</div>}
  </div>;
}
