import { useMemo, useState, type FormEvent } from "react";
import { Award, Check, CheckCircle2, ChevronRight, Clock3, Database, Download, FileJson, FileText, Flag, HardDriveDownload, History, Info, LockKeyhole, RefreshCw, Save, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { useLab } from "../lib/LabContext";
import { EmptyState, KeyValue, PageHeading, Panel, StatusPill } from "../components/ui";
import { createJsonReport, createMarkdownReport } from "../lib/report";
import { downloadBlob, formatBytes, formatDateTime, shortHash } from "../lib/utils";

export function EvidenceView({ onRestore }: { onRestore: (id: string) => void }) {
  const { controller, state } = useLab();
  const [flag, setFlag] = useState("");
  const [filter, setFilter] = useState("all");
  const [submitting, setSubmitting] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const categories = ["all", ...new Set(state.evidence.map((record) => record.category))];
  const filtered = filter === "all" ? state.evidence : state.evidence.filter((record) => record.category === filter);
  const passed = state.checks.filter((check) => check.status === "passed").length;
  const reportName = `cyber-range-${state.session?.id ?? "no-session"}-${new Date().toISOString().slice(0, 10)}`;
  const snapshotTotal = useMemo(() => state.snapshots.reduce((sum, item) => sum + item.attackerBytes + item.targetBytes, 0), [state.snapshots]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    const accepted = await controller.submitFlag(flag);
    if (accepted) setFlag("");
    setSubmitting(false);
  };

  return <div className="view evidence-view">
    <PageHeading index="05" eyebrow="EVIDENCE & REPORT" title="Observations, not assertions" description="Preserve genuine guest artifacts, validate the CTF objective, and export a report with its limitations intact."
      actions={<><button className="button secondary" onClick={() => downloadBlob(`${reportName}.json`, createJsonReport(state), "application/json")}><FileJson size={15} />JSON bundle</button><button className="button primary" onClick={() => downloadBlob(`${reportName}.md`, createMarkdownReport(state), "text/markdown")}><Download size={15} />Export report</button></>} />

    <div className="evidence-summary-grid">
      <Panel className="summary-card"><span className="app-icon teal"><FileText size={19} /></span><div><strong>{state.evidence.length}</strong><span>Guest evidence records</span></div><small>Proxy, HTTP, logs, system</small></Panel>
      <Panel className="summary-card"><span className="app-icon blue"><CheckCircle2 size={19} /></span><div><strong>{passed}/{state.checks.length}</strong><span>Verification checks</span></div><small>Current guest runtime</small></Panel>
      <Panel className="summary-card"><span className="app-icon amber"><ShieldCheck size={19} /></span><div><strong>{state.session?.proof ? "Observed" : "Absent"}</strong><span>Apache-worker proof</span></div><small>{state.session?.proof ? `Owner: ${state.session.proof.owner}` : "No RCE claim"}</small></Panel>
      <Panel className="summary-card"><span className="app-icon violet"><Award size={19} /></span><div><strong>{state.completedAs ? "Complete" : "Incomplete"}</strong><span>CTF objective</span></div><small>{state.completedAs ? "Genuine RCE" : "Not awarded"}</small></Panel>
    </div>

    <div className="evidence-main-grid">
      <Panel eyebrow="CTF COMPLETION" title="Submit the target flag" className="flag-panel">
        {state.completedAs ? <div className="completion-card"><span className="completion-seal"><Award size={30} /></span><div><h3>Genuine RCE completion validated</h3><p>Apache-owned challenge evidence and the matching per-session flag are both present. No simulation credit was used.</p><span>Validated {formatDateTime(state.session?.flagSubmittedAt)}</span></div></div> : <>
          <p>Read <code>/var/www/html/flag.txt</code> through a demonstrated target-side execution context. A matching flag without fresh worker evidence is not enough.</p>
          <form className="flag-form" onSubmit={(event) => void submit(event)}><label htmlFor="flag-input">Flag token</label><div><Flag size={17} /><input id="flag-input" value={flag} onChange={(event) => setFlag(event.target.value)} placeholder="RANGE{…}" autoComplete="off" spellCheck={false} /><button className="button primary" disabled={!flag.trim() || submitting || !state.session}>{submitting ? "Checking…" : "Validate flag"}<ChevronRight size={15} /></button></div></form>
          <div className="completion-checklist"><div className={state.session?.proof ? "done" : ""}>{state.session?.proof ? <Check size={14} /> : <XCircle size={14} />}Target-owned execution proof</div><div className={state.session?.proof && state.session.flagSubmittedAt ? "done" : ""}><LockKeyhole size={14} />Matching flag + evidence</div></div>
        </>}
        <div className="ctf-limitation"><Info size={14} /><span>This client-side flag is a learning mechanism, not a secret or an authorization control.</span></div>
      </Panel>

      <Panel eyebrow="SESSION PROOF" title="Current evidence chain">
        {state.session ? <><KeyValue label="Session" value={state.session.id} mono /><KeyValue label="Target build" value={`PHP ${state.session.phpVersion}`} mono /><KeyValue label="Flag SHA-256" value={shortHash(state.session.flagSha256, 20)} mono title={state.session.flagSha256} /><KeyValue label="Proof owner" value={state.session.proof?.owner ?? "Not observed"} /><KeyValue label="Proof observed" value={formatDateTime(state.session.proof?.observedAt)} /><KeyValue label="Completion" value={<StatusPill status={state.completedAs ? "completed" : "testing"} label={state.completedAs ? "Genuine RCE" : "Evidence incomplete"} />} /></> : <EmptyState title="No active lab session">Start the guests to allocate a session-specific flag and challenge.</EmptyState>}
      </Panel>
    </div>

    <Panel eyebrow="BROWSER-LOCAL PERSISTENCE" title="VM state snapshots" action={<span className="panel-header-note"><Database size={14} />{state.snapshots.length} snapshot(s) · {formatBytes(snapshotTotal)}</span>}>
      <div className="snapshot-actions"><p>v86 state images include real guest memory and device state. Restore always repeats network and service checks. Browser quota failures are reported, not hidden.</p><button className="button secondary" onClick={() => void controller.saveState()} disabled={!state.session || Boolean(state.operation)}><Save size={15} />Save current state</button></div>
      {state.snapshots.length ? <div className="snapshot-list">{state.snapshots.map((snapshot) => <div className="snapshot-row" key={snapshot.id}><span className="app-icon blue"><HardDriveDownload size={18} /></span><div className="snapshot-name"><strong>{formatDateTime(snapshot.createdAt)}</strong><span>PHP {snapshot.phpVersion} · session {snapshot.sessionId} · v86 {snapshot.v86Version}</span></div><strong>{formatBytes(snapshot.attackerBytes + snapshot.targetBytes)}</strong><button className="button secondary small-button" onClick={() => onRestore(snapshot.id)} disabled={Boolean(state.operation)}><History size={14} />Restore</button>{pendingDelete === snapshot.id ? <><button className="button danger small-button" onClick={() => { void controller.deleteSnapshot(snapshot.id); setPendingDelete(null); }}>Confirm</button><button className="button text-button small-button" onClick={() => setPendingDelete(null)}>Cancel</button></> : <button className="icon-button danger-icon" title="Delete snapshot" onClick={() => setPendingDelete(snapshot.id)}><Trash2 size={15} /></button>}</div>)}</div> : <EmptyState icon={<Save size={24} />} title="No VM snapshots saved">Use Save state when both guests are running. Evidence export is separate and much smaller.</EmptyState>}
    </Panel>

    <Panel eyebrow="GENUINE GUEST ARTIFACTS" title="Evidence timeline" action={<button className="button secondary small-button" onClick={() => void controller.syncGuestEvidence()} disabled={!state.session || Boolean(state.operation)}><RefreshCw size={14} />Sync RangeProxy evidence</button>}>
      <div className="evidence-toolbar"><div className="filter-tabs">{categories.map((category) => <button key={category} className={filter === category ? "active" : ""} onClick={() => setFilter(category)}>{category}<span>{category === "all" ? state.evidence.length : state.evidence.filter((record) => record.category === category).length}</span></button>)}</div><span>{filtered.length} record(s)</span></div>
      {filtered.length ? <div className="evidence-list">{filtered.map((record) => <details className="evidence-record" key={record.id}><summary><span className={`evidence-category ${record.category}`}>{record.category}</span><div><strong>{record.title}</strong><span>{record.source}</span></div><time><Clock3 size={13} />{formatDateTime(record.timestamp)}</time><ChevronRight size={15} className="details-chevron" /></summary><div className="evidence-data"><div className="evidence-provenance"><ShieldCheck size={14} />Genuine guest-derived record · {record.machine} · {record.id}</div><pre>{record.data}</pre></div></details>)}</div> : <EmptyState icon={<FileText size={25} />} title={state.evidence.length ? "No records in this category" : "No guest evidence yet"}>{state.evidence.length ? "Choose another evidence category." : "Start the lab and run a baseline or proxy request. Boot verification also produces real evidence."}</EmptyState>}
    </Panel>

    <div className="report-method"><FileText size={16} /><div><strong>Report methodology</strong><span>Exports include up to 32 MiB of evidence, actual target log tails, asset checksums, telemetry sources, and explicit unverified/limitation statements.</span></div></div>
  </div>;
}
