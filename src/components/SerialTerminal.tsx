import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { useLab } from "../lib/LabContext";
import type { MachineId } from "../types";

export function SerialTerminal({ machine }: { machine: MachineId }) {
  const { controller, state } = useLab();
  const host = useRef<HTMLDivElement>(null);
  const lastBootAt = state.machines[machine].lastBootAt;

  useEffect(() => {
    if (!host.current) return;
    const terminal = new Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: "IBM Plex Mono, monospace",
      fontSize: 13,
      lineHeight: 1.2,
      scrollback: 5000,
      theme: { background: "#070b0f", foreground: "#c9d8d5", cursor: "#54d8c2", selectionBackground: "#24534f" },
    });
    terminal.open(host.current);
    const transcript = controller.getSerialTranscript(machine);
    if (transcript) terminal.write(transcript.replace(/\n/g, "\r\n"));
    const unsubscribe = controller.subscribeSerial(machine, (text) => terminal.write(text));
    const input = terminal.onData((data) => {
      try {
        controller.sendSerial(machine, data);
      } catch (error) {
        terminal.write(`\r\n\x1b[33m${error instanceof Error ? error.message : String(error)}\x1b[0m\r\n`);
      }
    });
    const resize = () => {
      if (!host.current) return;
      const bounds = host.current.getBoundingClientRect();
      if (bounds.width > 100 && bounds.height > 80) terminal.resize(Math.max(40, Math.floor((bounds.width - 20) / 7.8)), Math.max(10, Math.floor((bounds.height - 12) / 15.6)));
    };
    const observer = new ResizeObserver(resize);
    observer.observe(host.current);
    resize();
    terminal.focus();
    return () => {
      observer.disconnect();
      input.dispose();
      unsubscribe();
      terminal.dispose();
    };
  }, [controller, machine, lastBootAt]);

  return <div className="serial-terminal" ref={host} aria-label={`${machine} real guest serial terminal`} />;
}
