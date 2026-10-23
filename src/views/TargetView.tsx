import { useState } from "react";
import { Activity, Braces, CheckCircle2, Cpu, FileClock, FileWarning, Gauge, HardDrive, MemoryStick, Network, RefreshCw, Server, ScrollText, ShieldCheck } from "lucide-react";
import { useLab } from "../lib/LabContext";
import { VmScreen } from "../components/VmScreen";
import { EmptyState, KeyValue, Meter, PageHeading, Panel, StatusPill } from "../components/ui";
import { formatBytes, formatTime, parseKeyValues, shortHash } from "../lib/utils";

export function TargetView() {
  const { controller, state } = useLab();
  const [logTab, setLogTab] = useState<"access" | "error" | "php">("access");
  const guest = state.machines.target;
  const telemetry = state.telemetry;
  const health = state.health;
  const build = parseKeyValues(state.buildInfo);
  const memoryPercent = telemetry && telemetry.guest_mem_total_kib > 0 ? telemetry.guest_mem_used_kib / telemetry.guest_mem_total_kib * 100 : 0;
  const logSources = { access: "/var/log/apache2/access.log", error: "/var/log/apache2/error.log", php: "/var/log/apache2/php-error.log" };

  return <div className="view target-view">
    <PageHeading index="02" eyebrow="TARGET SERVER HOUSING" title="Assessment target internals" description="Guest-derived service health, PHP configuration, log files, and process memory—never frontend-generated telemetry."
      actions={<><StatusPill status={guest.status} /><span className="address-chip"><Network size={14} />192.168.10.55<span>/24</span></span></>} />

    <div className="target-top-grid">
      <VmScreen machine="target" compact />
      <Panel eyebrow="SERVICE ENCLOSURE" title="Runtime identity" className="target-identity">
        <div className="server-identity"><span className="server-icon"><Server size={25} /></span><div><strong>Alpine assessment target</strong><span>{health?.apache ?? "Apache version not collected"}</span></div></div>
        <KeyValue label="Guest OS" value={guest.guestOs ?? "Not observed"} />
        <KeyValue label="Target address" value={guest.address ?? "Not observed"} mono />
        <KeyValue label="Apache service" value={<span className={telemetry?.apache_state === "running" ? "text-success" : ""}>{telemetry?.apache_state ?? "Not observed"}</span>} />
        <KeyValue label="PHP version" value={health?.php_version ?? telemetry?.php_version ?? "Not observed"} mono />
        <KeyValue label="Execution mode" value={health?.php_sapi ?? telemetry?.php_sapi ?? "Not observed"} mono />
        <KeyValue label="Allocated VM RAM" value={`${guest.ramMiB ?? "—"} MiB`} />
        <KeyValue label="NIC / transport" value="NE2000 · inbrowser" mono />
        <div className="source-note"><ShieldCheck size={14} />Source: target guest, labctl health + /proc</div>
      </Panel>
    </div>

    <div className="telemetry-heading"><div><span className="eyebrow">LIVE GUEST TELEMETRY</span><h2>Memory & process measurements</h2></div><span>Observed {formatTime(telemetry ? telemetry.timestamp * 1000 : undefined)}</span></div>
    <div className="telemetry-grid">
      <Panel className="metric-card"><div className="metric-title"><span className="app-icon blue"><Gauge size={18} /></span><span>Configured PHP limit</span></div><strong className="metric-value">{telemetry ? (telemetry.php_memory_limit_bytes < 0 ? "Unlimited" : formatBytes(telemetry.php_memory_limit_bytes)) : "—"}</strong><span className="metric-label">{telemetry?.php_memory_limit ?? "memory_limit not collected"} · {telemetry?.php_memory_limit_bytes?.toLocaleString() ?? "—"} bytes</span><p>Configuration ceiling, not current usage.</p></Panel>
      <Panel className="metric-card"><div className="metric-title"><span className="app-icon teal"><Activity size={18} /></span><span>Apache/mod_php RSS</span></div><strong className="metric-value">{telemetry ? formatBytes(telemetry.apache_modphp_rss_kib * 1024) : "—"}</strong><span className="metric-label">Aggregate across {telemetry?.apache_worker_count ?? "—"} observed worker(s)</span><Meter value={telemetry?.apache_modphp_rss_kib ?? 0} maximum={telemetry?.guest_mem_total_kib ?? 1} /><p>Includes Apache and loaded module memory.</p></Panel>
      <Panel className="metric-card"><div className="metric-title"><span className="app-icon amber"><MemoryStick size={18} /></span><span>Guest OS memory</span></div><strong className="metric-value">{telemetry ? `${memoryPercent.toFixed(1)}%` : "—"}</strong><span className="metric-label">{telemetry ? `${formatBytes(telemetry.guest_mem_used_kib * 1024)} used of ${formatBytes(telemetry.guest_mem_total_kib * 1024)}` : "/proc/meminfo not collected"}</span><Meter value={telemetry?.guest_mem_used_kib ?? 0} maximum={telemetry?.guest_mem_total_kib ?? 1} tone="amber" /><p>MemTotal − MemAvailable from the guest.</p></Panel>
      <Panel className="metric-card"><div className="metric-title"><span className="app-icon violet"><Cpu size={18} /></span><span>Service process state</span></div><strong className="metric-value">{telemetry?.apache_worker_count ?? "—"}</strong><span className="metric-label">httpd processes · {telemetry?.apache_state ?? "unknown"}</span><p>Last HTTP worker PID: <span className="mono">{health?.worker_pid ?? "—"}</span></p></Panel>
    </div>

    <div className="target-detail-grid">
      <Panel eyebrow="PHP & BUILD" title="Configuration provenance" action={<Braces size={17} />}>
        {health ? <div className="config-grid">
          <KeyValue label="memory_limit" value={health.memory_limit} mono />
          <KeyValue label="post_max_size" value={health.post_max_size} mono />
          <KeyValue label="upload_max_filesize" value={health.upload_max_filesize} mono />
          <KeyValue label="max_file_uploads" value={health.max_file_uploads} mono />
          <KeyValue label="upload progress" value={health.upload_progress ? "Enabled" : "Disabled"} />
          <KeyValue label="Application" value="Custom training app · not WordPress" />
        </div> : <EmptyState title="No PHP health data">Boot the target to read its real mod_php configuration.</EmptyState>}
        {telemetry && <div className="binary-hash"><span>libphp.so SHA-256</span><code title={telemetry.php_binary_sha256}>{shortHash(telemetry.php_binary_sha256, 24)}</code></div>}
        {build.php_source_version && <div className="build-provenance"><span>Source {build.php_source_version}</span><span>Alpine {build.alpine_version}</span><span className="text-warning">RCE {build.cve_reproduction_status ?? "unverified"}</span></div>}
      </Panel>

      <Panel eyebrow="REQUEST & SERVICE ACTIVITY" title="Health observations" action={<CheckCircle2 size={17} />}>
        <KeyValue label="Application route" value="/health.php" mono />
        <KeyValue label="Observed at" value={health?.time ?? "—"} mono />
        <KeyValue label="Last worker PID" value={health?.worker_pid ?? "—"} mono />
        <KeyValue label="WordPress installed" value={health ? (health.wordpress ? "Yes" : "No — custom training application") : "—"} />
        <KeyValue label="Telemetry source" value="/proc/meminfo + /proc/[pid]/status" mono />
        <p className="panel-footnote">A worker exit or failed health request is shown as observed. The interface does not infer a crash from payload strings or response codes.</p>
      </Panel>
    </div>

    <Panel className="logs-panel" eyebrow="ACTUAL TARGET FILES" title="Server logs & HTTP request activity" action={<button className="button secondary small-button" onClick={() => void controller.refreshTargetNow()} disabled={!telemetry && !health || Boolean(state.operation)}><RefreshCw size={14} className={state.operation?.includes("telemetry") ? "spin" : ""} />Refresh from guest</button>}>
      <div className="log-tabs" role="tablist">
        <button className={logTab === "access" ? "active" : ""} onClick={() => setLogTab("access")}><ScrollText size={14} />Apache access</button>
        <button className={logTab === "error" ? "active" : ""} onClick={() => setLogTab("error")}><FileWarning size={14} />Apache error</button>
        <button className={logTab === "php" ? "active" : ""} onClick={() => setLogTab("php")}><FileClock size={14} />PHP errors</button>
      </div>
      <div className="log-source"><HardDrive size={13} /><span>{logSources[logTab]}</span><span>Guest read · max 256 KiB tail</span></div>
      {state.logs[logTab] ? <pre className="log-viewer">{state.logs[logTab]}</pre> : <EmptyState icon={<ScrollText size={25} />} title="No guest log data collected">Log entries will appear here only after the target file is read.</EmptyState>}
    </Panel>
  </div>;
}
