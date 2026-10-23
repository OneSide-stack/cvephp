import { ArrowRight, CheckCircle2, CloudOff, EthernetPort, LockKeyhole, Network, RefreshCw, Router, Server, ShieldCheck, Terminal, Workflow } from "lucide-react";
import { useLab } from "../lib/LabContext";
import { CheckIcon, KeyValue, PageHeading, Panel, StatusPill } from "../components/ui";
import { formatTime } from "../lib/utils";

export function NetworkView() {
  const { controller, state } = useLab();
  const passed = state.checks.filter((check) => check.status === "passed").length;
  const connected = passed === state.checks.length;
  const running = Boolean(state.session && !["not-started"].includes(state.status));

  return <div className="view network-view">
    <PageHeading index="03" eyebrow="NETWORK TOPOLOGY" title="One private Ethernet segment" description="Raw guest frames travel only through a session-owned v86 inbrowser BroadcastChannel—never a public relay or the host LAN."
      actions={<button className="button secondary" onClick={() => void controller.verifyNetworkNow()} disabled={!running || Boolean(state.operation)}><RefreshCw size={15} />Repeat all checks</button>} />

    <Panel className={`topology-panel ${connected ? "connected" : ""}`}>
      <div className="topology-meta"><span className="eyebrow">LAB SEGMENT</span><code>192.168.10.0 / 255.255.255.0</code><StatusPill status={connected ? "ready" : running ? "initializing-network" : "not-started"} label={connected ? "Verified end-to-end" : running ? `${passed}/${state.checks.length} checks passed` : "Network offline"} /></div>
      <div className="topology-canvas">
        <div className="topology-node attacker-node">
          <div className="node-icon"><Terminal size={28} /></div><span className="node-type">ATTACKER</span><h3>Workstation</h3><code>192.168.10.10</code><p>Tiny Core x86 · eth0</p><span className="node-nic">NE2000 · 52:54:**:**:**:**</span>
        </div>
        <div className="topology-link left-link"><span className="packet p1" /><div><span>Raw Ethernet</span><code>guest NIC</code></div></div>
        <div className="topology-switch"><span className="switch-rings"><Router size={29} /></span><strong>v86 inbrowser</strong><code>v86-inbrowser-{state.session?.networkId ?? "unallocated"}</code><span>Exclusive Web Lock</span></div>
        <div className="topology-link right-link"><span className="packet p2" /><div><span>TCP / HTTP</span><code>port 80</code></div></div>
        <div className="topology-node target-node">
          <div className="node-icon"><Server size={28} /></div><span className="node-type">TARGET</span><h3>Assessment server</h3><code>192.168.10.55</code><p>Alpine x86 · eth0</p><span className="node-nic">Apache + mod_php</span>
        </div>
      </div>
      <div className="isolation-strip"><LockKeyhole size={17} /><div><strong>Isolation enforced at allocation</strong><span>No NAT · no default route · no wsproxy/wisp/fetch relay · no external IP forwarding</span></div><CloudOff size={20} /></div>
    </Panel>

    <div className="network-detail-grid">
      <Panel eyebrow="RUNTIME CONTRACT" title="Boundary & session ownership">
        <KeyValue label="Backend" value="inbrowser (raw Ethernet)" mono />
        <KeyValue label="Session" value={state.session?.id ?? "Not allocated"} mono />
        <KeyValue label="Network identifier" value={state.session?.networkId ?? "Not allocated"} mono />
        <KeyValue label="Ownership" value={state.session ? "Exclusive same-origin Web Lock" : "Not held"} />
        <KeyValue label="Host LAN bridge" value={<span className="text-success">Not configured</span>} />
        <KeyValue label="Internet egress" value={<span className="text-success">Not configured</span>} />
        <p className="panel-footnote">If Web Locks are unavailable or an identifier is already owned, boot fails closed instead of risking shared traffic.</p>
      </Panel>
      <Panel eyebrow="REQUEST PATH" title="What “real HTTP” means here">
        <div className="request-path">
          <div><span>1</span><strong>Attacker process</strong><small>curl, Dillo, RangeProxy, or exploit.py</small></div><ArrowRight size={16} />
          <div><span>2</span><strong>Guest TCP/IP</strong><small>ARP + IP + TCP through ne2k-pci</small></div><ArrowRight size={16} />
          <div><span>3</span><strong>Target Apache</strong><small>httpd accepts the actual socket</small></div><ArrowRight size={16} />
          <div><span>4</span><strong>mod_php + logs</strong><small>PHP response and file evidence</small></div>
        </div>
        <div className="source-note"><ShieldCheck size={14} />The frontend observes outputs. It cannot synthesize a target response.</div>
      </Panel>
    </div>

    <Panel eyebrow="ACTUAL VERIFICATION RESULTS" title={`Network acceptance checks · ${passed}/${state.checks.length}`} action={<Workflow size={18} />}>
      <div className="verification-list">
        {state.checks.map((check, index) => <div className={`verification-row ${check.status}`} key={check.id}>
          <div className="verification-index">{String(index + 1).padStart(2, "0")}</div><CheckIcon status={check.status} />
          <div className="verification-main"><strong>{check.label}</strong><span>{check.description}</span><code>{check.source}</code></div>
          <div className="verification-result"><span>{check.detail}</span><small>{check.observedAt ? formatTime(check.observedAt) : "Awaiting execution"}</small></div>
        </div>)}
      </div>
      {connected && <div className="verification-complete"><CheckCircle2 size={17} /><span>Every check passed against the current running guests. Reboot or restore invalidates and repeats these checks.</span></div>}
    </Panel>

    <div className="network-footnotes"><span><EthernetPort size={14} />NE2000 emulation</span><span><Network size={14} />Session-specific BroadcastChannel</span><span><LockKeyhole size={14} />Browser origin + Web Lock separation</span></div>
  </div>;
}
