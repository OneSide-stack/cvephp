import type { EvidenceRecord, LabState } from "../types";
import { STATUS_LABELS } from "../types";
import { formatBytes } from "./utils";

const REPORT_BUDGET = 32 * 1024 * 1024;

function evidenceWithinBudget(evidence: EvidenceRecord[]): { records: EvidenceRecord[]; omitted: number; truncated: boolean } {
  const records: EvidenceRecord[] = [];
  let bytes = 0;
  let omitted = 0;
  let truncated = false;
  for (const record of evidence) {
    if (bytes + record.data.length > REPORT_BUDGET) {
      omitted += 1;
      truncated = true;
      continue;
    }
    records.push(record);
    bytes += record.data.length;
  }
  return { records, omitted, truncated };
}

function reportObject(state: LabState) {
  const selectedEvidence = evidenceWithinBudget(state.evidence);
  return {
    schema: "enterprise-cyber-range-evidence/v1",
    generatedAt: new Date().toISOString(),
    title: "Enterprise Cyber Range — CVE-2026-109618 (PHP2Shell)",
    execution: {
      emulator: "v86 0.5.472",
      mode: "genuine x86 guests in browser",
      simulated: false,
      backend: "session-scoped inbrowser raw Ethernet",
      status: STATUS_LABELS[state.status],
      completion: state.completedAs === "genuine-rce" ? "Genuine RCE evidence and matching flag validated" : "Incomplete / genuine RCE not verified",
    },
    session: state.session,
    machines: state.machines,
    resourceMode: state.resourceMode,
    verification: state.checks,
    target: {
      health: state.health,
      telemetry: state.telemetry,
      buildInfo: state.buildInfo,
      logs: state.logs,
    },
    evidence: selectedEvidence.records,
    evidenceExport: {
      included: selectedEvidence.records.length,
      omittedForSize: selectedEvidence.omitted,
      truncated: selectedEvidence.truncated,
      budgetBytes: REPORT_BUDGET,
    },
    assetManifest: state.manifest,
    limitations: [
      "A client-side CTF flag is a learning mechanism, not a secret suitable for authorization.",
      "Browser and v86 isolation are separate concerns; this report is not a host-safety certification.",
      "No OOM, HTTP status, version string, or simulated output is accepted as RCE evidence.",
    ],
  };
}

export function createJsonReport(state: LabState): string {
  return JSON.stringify(reportObject(state), null, 2);
}

function fence(value: string): string {
  return `\`\`\`text\n${value.replace(/```/g, "` ` `")}\n\`\`\``;
}

export function createMarkdownReport(state: LabState): string {
  const object = reportObject(state);
  const lines: string[] = [
    "# Enterprise Cyber Range — Evidence Report",
    "",
    "**Exercise:** CVE-2026-109618 (PHP2Shell) Dual-OS Simulation  ",
    `**Generated:** ${object.generatedAt}  `,
    `**Execution:** ${object.execution.mode} (simulation: no)  `,
    `**Runtime status:** ${object.execution.status}  `,
    `**Completion:** ${object.execution.completion}`,
    "",
    "> This report distinguishes guest-derived observations from completion claims. An OOM, crash, HTTP 500, or version string alone is not RCE evidence.",
    "",
    "## Session",
    "",
    state.session ? `- Session ID: \`${state.session.id}\`\n- Started: ${state.session.startedAt}\n- Network ID: \`${state.session.networkId}\`\n- Target build: PHP ${state.session.phpVersion}\n- Flag SHA-256: \`${state.session.flagSha256}\`\n- Challenge: \`${state.session.challenge}\`\n- Apache-worker proof: ${state.session.proof ? `${state.session.proof.observedAt}, owner ${state.session.proof.owner}` : "not observed"}` : "No active session.",
    "",
    "## Virtual machines",
    "",
    "| Machine | State | Guest OS | Address | RAM | Detail |",
    "|---|---|---|---|---:|---|",
    ...Object.values(state.machines).map((machine) => `| ${machine.title} | ${machine.status} | ${machine.guestOs ?? machine.detail} | ${machine.address ?? "—"} | ${machine.ramMiB ?? "—"} MiB | ${machine.detail} |`),
    "",
    "## Network and service verification",
    "",
    "| Check | Result | Observed detail | Source |",
    "|---|---|---|---|",
    ...state.checks.map((check) => `| ${check.label} | ${check.status} | ${check.detail.replace(/\|/g, "\\|")} | \`${check.source}\` |`),
    "",
    "## Target runtime",
    "",
    state.health ? fence(JSON.stringify(state.health, null, 2)) : "No PHP health observation collected.",
    "",
    "### Memory and process telemetry",
    "",
    state.telemetry ? `- PHP memory limit: **${state.telemetry.php_memory_limit}** (${state.telemetry.php_memory_limit_bytes} bytes)\n- Apache/mod_php aggregate RSS: **${formatBytes(state.telemetry.apache_modphp_rss_kib * 1024)}**\n- Guest memory used: **${formatBytes(state.telemetry.guest_mem_used_kib * 1024)} / ${formatBytes(state.telemetry.guest_mem_total_kib * 1024)}**\n- Apache workers: **${state.telemetry.apache_worker_count}**, state **${state.telemetry.apache_state}**\n- libphp.so SHA-256: \`${state.telemetry.php_binary_sha256}\`\n- Source: target \`/proc/meminfo\`, \`/proc/[pid]/status\`, PHP/Apache queries` : "No telemetry collected.",
    "",
    "### Build provenance",
    "",
    state.buildInfo ? fence(state.buildInfo) : "No target build record collected.",
    "",
    "## Guest evidence",
    "",
    `Included ${object.evidenceExport.included} record(s); omitted ${object.evidenceExport.omittedForSize} for the 32 MiB report budget.`,
    "",
  ];
  for (const [index, record] of object.evidence.entries()) {
    lines.push(`### ${index + 1}. ${record.title}`, "", `- Time: ${record.timestamp}\n- Machine: ${record.machine}\n- Source: ${record.source}\n- Category: ${record.category}\n- Genuine guest evidence: ${record.genuine ? "yes" : "no"}`, "", fence(record.data), "");
  }
  lines.push("## Target log tails", "");
  for (const [name, content] of Object.entries(state.logs)) {
    lines.push(`### ${name}`, "", content ? fence(content) : "No log data collected.", "");
  }
  if (state.manifest) {
    lines.push("## Asset integrity", "", "| Asset | Bytes | SHA-256 |", "|---|---:|---|");
    const assets = [
      ["v86 WASM", state.manifest.v86.wasm],
      ["SeaBIOS", state.manifest.v86.bios],
      ["VGA BIOS", state.manifest.v86.vgaBios],
      ["Attacker ISO", state.manifest.attacker.image],
      ...state.manifest.targets.map((target) => [`Target PHP ${target.phpVersion}`, target.image] as const),
    ] as const;
    for (const [name, asset] of assets) lines.push(`| ${name} | ${asset.bytes ?? "missing"} | \`${asset.sha256 ?? "—"}\` |`);
    lines.push("");
  }
  lines.push("## Limitations", "", ...object.limitations.map((item) => `- ${item}`), "");
  return lines.join("\n");
}
