import type { LabState, Verification } from "../types";
import { emptyExercise } from "./exercise";

export const NETWORK_CHECKS: Verification[] = [
  { id: "attacker-ip", label: "Attacker addressing", description: "Confirm eth0 owns 192.168.10.10/24", status: "pending", detail: "Not checked", source: "attacker: ip -4 -o addr show dev eth0" },
  { id: "target-ip", label: "Target addressing", description: "Confirm eth0 owns 192.168.10.55/24", status: "pending", detail: "Not checked", source: "target: ip -4 -o addr show dev eth0" },
  { id: "connectivity", label: "Guest-to-guest connectivity", description: "Send real ICMP echo requests over the emulated Ethernet", status: "pending", detail: "Not checked", source: "attacker: ping 192.168.10.55" },
  { id: "listener", label: "Apache listener", description: "Inspect the target's actual listening socket table", status: "pending", detail: "Not checked", source: "target: ss -ltn" },
  { id: "http", label: "Genuine HTTP transaction", description: "Request health.php from the attacker through the guest network stack", status: "pending", detail: "Not checked", source: "attacker: curl → target Apache/mod_php" },
  { id: "headers", label: "Response status and headers", description: "Capture the target's actual status line and response headers", status: "pending", detail: "Not checked", source: "attacker: curl -D -" },
  { id: "logs", label: "Target log confirmation", description: "Find the unique request in Apache's actual access log", status: "pending", detail: "Not checked", source: "target: /var/log/apache2/access.log" },
  { id: "isolation", label: "Isolation boundary", description: "Verify session-specific inbrowser transport and no guest default route", status: "pending", detail: "Not checked", source: "v86 config + both guests: ip route" },
];

export const initialState: LabState = {
  view: "attacker",
  status: "not-started",
  operation: null,
  error: null,
  notice: null,
  manifest: null,
  assetProgress: null,
  resourceMode: "standard",
  selectedTarget: "alpine-php-8.2.34",
  machines: {
    attacker: { id: "attacker", status: "offline", title: "Attacker Workstation", detail: "Tiny Core Linux · x86 · X11", ramMiB: 384, serial: "" },
    target: { id: "target", status: "offline", title: "Assessment Target", detail: "Alpine Linux · x86 · Apache/mod_php", ramMiB: 512, serial: "" },
  },
  checks: NETWORK_CHECKS.map((check) => ({ ...check })),
  telemetry: null,
  health: null,
  buildInfo: "",
  logs: { access: "", error: "", php: "" },
  evidence: [],
  activity: [{ id: "welcome", timestamp: new Date().toISOString(), level: "info", message: "Range controller initialized. No virtual machines are running." }],
  session: null,
  snapshots: [],
  hasUnsavedProgress: false,
  completedAs: null,
  activeSerialMachine: "attacker",
  attackerTools: [],
  proxyStatus: "unknown",
  proxyAcceptance: null,
  exercise: emptyExercise(),
  recovery: null,
};
