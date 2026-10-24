import { useState } from "react";
import { AlertOctagon, ArrowRight, Check, CheckCircle2, Clipboard, ExternalLink, FileSearch, Flag, Gauge, Globe2, Info, LockKeyhole, Play, Server, ShieldAlert, Wrench, XCircle } from "lucide-react";
import { useLab } from "../lib/LabContext";
import { PageHeading, Panel, StatusPill } from "../components/ui";

const phases = [
  { number: "01", title: "Reconnaissance", text: "Read the target's SAPI, build marker and limits from the target itself.", command: "curl --noproxy '*' -i http://192.168.10.55/health.php" },
  { number: "02", title: "Baseline testing", text: "Send ordinary GET and POST requests and require target-log corroboration.", command: "python3 ~/exploit.py baseline" },
  { number: "03", title: "Request analysis", text: "Route traffic through RangeProxy, modify a request, and see the target accept it.", command: "curl -x http://127.0.0.1:8080 -i http://192.168.10.55/health.php" },
  { number: "04", title: "Vulnerability investigation", text: "Classify the build from version plus patch marker, and record every applicable condition.", command: "cat /home/tc/notes.txt" },
  { number: "05", title: "Controlled reproduction", text: "Send one bounded multipart probe; OOM is a primitive, never an exploit result.", command: "python3 ~/exploit.py oom-probe --mib 8" },
  { number: "06", title: "Target-side verification", text: "Correlate the target's own logs, worker state, and any Apache-owned proof.", command: "labctl logs php   # target's visible lab console" },
  { number: "07", title: "Remediation", text: "Compare the observed build against the verified 8.2.35 patch and its mitigations.", command: "# Open Vulnerability Lab → Compare builds" },
  { number: "08", title: "Completion", text: "Awarded only for target-owned execution proof plus the matching session flag.", command: "# Genuine path stays closed until that evidence exists" },
];

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return <button className="icon-button copy-button" title="Copy command" onClick={() => {
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  }}>{copied ? <Check size={14} /> : <Clipboard size={14} />}</button>;
}

export function GuideView() {
  const { controller, state } = useLab();
  const ready = ["ready", "testing", "completed"].includes(state.status);
  const challenge = state.session?.challenge ?? "<start-lab-to-allocate-challenge>";
  const proofCommand = `printf '%s' '${challenge}' > /var/www/html/rce-proof.txt\ncat /var/www/html/flag.txt > /var/www/html/flag-proof.txt\nid > /var/www/html/id-proof.txt`;

  return <div className="view guide-view">
    <PageHeading index="04" eyebrow="LAB GUIDE" title="Operation PHP2Shell" description="A disciplined investigation of PHP request-processing OOM corruption on a real, isolated Apache/mod_php target."
      actions={<><StatusPill status="real" label="Genuine guest execution" /><span className="difficulty-chip">HIGH COMPLEXITY</span></>} />

    <div className="guide-hero">
      <div className="guide-hero-main"><span className="cve-label">CVE-2026-109618</span><h2>From request semantics to verifiable execution.</h2><p>Trace the vulnerable path through real guests. Learn why allocator state, SAPI behavior, worker affinity, and build-specific layouts matter—and why a fatal error is not a shell.</p><div className="guide-hero-actions"><button className="button primary" onClick={() => controller.setView("lab")}><Play size={15} />Open the gated lab</button><button className="button secondary" onClick={() => void controller.runBaseline()} disabled={!ready || Boolean(state.operation)}><Play size={15} />Run baseline in guest</button><a className="button secondary" href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w" target="_blank" rel="noreferrer">Official advisory<ExternalLink size={14} /></a></div></div>
      <div className="cve-facts"><div><span>Upstream affected</span><strong>&lt; 8.2.35</strong></div><div><span>Lab build</span><strong>PHP {state.session?.phpVersion ?? "8.2.34"}</strong></div><div><span>Required SAPI</span><strong>Apache mod_php</strong></div><div><span>Configured limit</span><strong>{state.health?.memory_limit ?? "128M (planned)"}</strong></div></div>
    </div>

    <div className="truth-banner"><ShieldAlert size={22} /><div><strong>Advisory verified · RCE on this 32-bit Alpine build unverified</strong><p>The patch and affected versions were verified from the upstream advisory and the 8.2.34→8.2.35 source diff. No exploit profile for this musl/mod_php build is included, so OOM observations and genuine completion remain separate evidence classes.</p></div></div>

    <div className="guide-grid">
      <Panel eyebrow="LEARNING RUNBOOK" title="Eight gated phases" className="runbook-panel">
        <div className="phase-list">
          {phases.map((phase) => <article className="phase" key={phase.number}>
            <div className="phase-number">{phase.number}</div><div className="phase-body"><h3>{phase.title}</h3><p>{phase.text}</p><div className="command-block"><code>{phase.command}</code><CopyButton value={phase.command} /></div></div>
          </article>)}
        </div>
      </Panel>

      <div className="guide-side">
        <Panel eyebrow="TARGET ACCESS" title="Start with ordinary requests">
          <div className="guide-step"><Globe2 size={18} /><div><strong>Training portal</strong><code>http://192.168.10.55/</code></div></div>
          <div className="guide-step"><LockKeyhole size={18} /><div><strong>WordPress-style login</strong><code>http://192.168.10.55/wp-login.php</code><small>Custom PHP app, not WordPress · analyst / range</small></div></div>
          <div className="guide-step"><ProxyIcon /><div><strong>RangeProxy management</strong><code>http://127.0.0.1:8081/</code><small>Open inside the attacker guest only</small></div></div>
          <button className="button secondary full-width" onClick={() => controller.setView("attacker")}>Open attacker workstation<ArrowRight size={14} /></button>
        </Panel>

        <Panel eyebrow="CONTROLLED TEST" title="OOM probe safety">
          <p>The guest research harness streams multipart part headers without a declared Content-Length. Start small and inspect actual target behavior.</p>
          <div className="command-block multiline"><code>python3 ~/exploit.py oom-probe --mib 16</code><CopyButton value="python3 ~/exploit.py oom-probe --mib 16" /></div>
          <p className="warning-text"><AlertOctagon size={14} />A larger probe (for example 160 MiB) is disruptive and may still not reproduce the intended condition under v86. It requires <code>--i-understand-oom</code>.</p>
        </Panel>

        <Panel eyebrow="PROOF STANDARD" title="What does not count">
          <div className="not-proof"><XCircle size={15} /><span>Content-Length ≥ 134217728</span></div><div className="not-proof"><XCircle size={15} /><span>HTTP 500 or a PHP OOM fatal</span></div><div className="not-proof"><XCircle size={15} /><span>A vulnerable-looking version banner</span></div><div className="not-proof"><XCircle size={15} /><span>A changed prompt or frontend success log</span></div>
        </Panel>
      </div>
    </div>

    <Panel eyebrow="POST-EXPLOITATION VERIFICATION" title="Prove execution in the target’s own filesystem" className="proof-panel">
      <div className="proof-grid"><div><p>If—and only if—you establish genuine command execution as the Apache worker, run the following through that execution context. It writes a fresh challenge proof and a web-readable copy of the flag. These commands have no special meaning to the frontend or application.</p><div className="proof-requirements"><span><CheckCircle2 size={14} />File owner must be <b>apache</b></span><span><CheckCircle2 size={14} />Challenge must match this session</span><span><CheckCircle2 size={14} />Modification time must be in this session</span><span><CheckCircle2 size={14} />Flag must match the guest-provisioned hash</span></div></div><div className="command-block code-large"><code>{proofCommand}</code><CopyButton value={proofCommand} /></div></div>
      <div className="session-challenge"><span>Current session challenge</span><code>{challenge}</code><small>The target console's unprivileged lab user cannot create an Apache-owned proof or read the flag.</small></div>
    </Panel>

    <div className="guide-reference-grid">
      <Panel eyebrow="TECHNICAL BACKGROUND" title="Why the SAPI and build matter">
        <div className="reference-item"><FileSearch size={18} /><div><strong>Request startup is the boundary</strong><p>The advisory describes OOM <code>longjmp()</code> leaving temporarily reachable request memory invalid before application code runs. Apache mod_php unconditionally invokes request shutdown, including after failed startup.</p></div></div>
        <div className="reference-item"><Gauge size={18} /><div><strong>OOM is a primitive, not the impact</strong><p>Multipart behavior can help exhaust a finite memory limit. Reliable control flow depends on allocator layout, extensions, worker behavior, and exact binary offsets.</p></div></div>
        <div className="reference-item"><Server size={18} /><div><strong>FPM is not interchangeable</strong><p>Do not substitute PHP-FPM or the built-in server for the lab's mod_php reproduction and then claim equivalent evidence.</p></div></div>
        <a className="inline-link" href="https://github.com/php/php-src/security/advisories" target="_blank" rel="noreferrer">PHP source security advisories<ExternalLink size={13} /></a>
      </Panel>

      <Panel eyebrow="RESOURCES & RECOVERY" title="Troubleshooting">
        <div className="troubleshoot-row"><strong>Missing / corrupt image</strong><span>Run <code>npm run assets:verify</code>; rebuild with <code>image-build/build-all.sh</code>. Startup refuses mismatched bytes.</span></div>
        <div className="troubleshoot-row"><strong>Guest will not boot</strong><span>Inspect its actual VGA/serial output, then use Reboot or Stop both. The parent UI remains independent.</span></div>
        <div className="troubleshoot-row"><strong>Apache worker exited</strong><span>Read Apache/PHP logs and fresh telemetry. Reboot the target to return to clean media and reprovision this session.</span></div>
        <div className="troubleshoot-row"><strong>Proxy rejects a request</strong><span>Check Content-Length/body agreement and chunk framing. Requests above 32 MiB belong in the streaming guest harness.</span></div>
        <div className="troubleshoot-row"><strong>Snapshot quota error</strong><span>Delete older snapshots. State images can be hundreds of MiB and are never called saved until both writes complete.</span></div>
      </Panel>
    </div>

    <div className="guide-bottom-bar"><div><Info size={16} /><span>Supported: current desktop Chrome, Edge, or Firefox with WebAssembly, BroadcastChannel, IndexedDB, Web Locks, and adequate memory.</span></div><button className="button text-button" onClick={() => controller.setView("lab")}><Flag size={15} />Review evidence & report</button></div>
  </div>;
}

function ProxyIcon() {
  return <span className="inline-tool-icon"><Wrench size={18} /></span>;
}
