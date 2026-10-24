import type { CommandResult } from "./SerialChannel";
import { jsonFromOutput, randomToken } from "./utils";
import type { MachineId, ProxyAcceptanceGateId, ProxyAcceptanceReport } from "../types";

const GATE_LABELS: Record<ProxyAcceptanceGateId, string> = {
  process: "Proxy process readiness",
  "browser-routing": "Actual Dillo browser proxy routing",
  interception: "Interception and pause before target delivery",
  editing: "Request editing and forwarding",
  "target-log": "Edited request corroborated by the target access log",
  disabled: "Interception disabled without direct-route bypass",
  repeater: "Repeater method, URL, headers, and real response",
  errors: "Malformed input, unavailable services, timeouts, dropping, repetition, and recovery",
};

const GATE_IDS = Object.keys(GATE_LABELS) as ProxyAcceptanceGateId[];
const MANAGEMENT = "http_proxy= HTTPS_PROXY= HTTP_PROXY= ALL_PROXY= all_proxy= curl --noproxy '*'";
const MANAGEMENT_URL = "http://127.0.0.1:8081";
const TARGET_URL = "http://192.168.10.55/";

interface ProxyState {
  intercept: boolean;
  pending: Array<{ id: string; created: string; bytes: number; request_line: string }>;
  requests_recorded: number;
  target: string;
}

interface ProxyEvidenceItem {
  sequence: number;
  timestamp: string;
  kind: string;
  id: string;
  source: string;
  request_base64: string;
  response?: { status?: number; headers?: unknown; body_base64?: string } | null;
  error?: string | null;
}

export interface ProxyAcceptanceHost {
  execute(machine: MachineId, command: string, timeout?: number): Promise<CommandResult>;
  pauseTarget(): Promise<void>;
  resumeTarget(): Promise<void>;
  onProgress(report: ProxyAcceptanceReport): void;
  capture(name: string, machine: MachineId, data: string): void;
}

export function decodeManagementTextarea(html: string, rows: number): string {
  const match = html.match(new RegExp(`<textarea name=raw rows=${rows}>([\\s\\S]*?)<\\/textarea>`));
  if (!match) throw new Error(`RangeProxy management did not expose its raw request textarea (rows=${rows})`);
  const decoded = (match[1] ?? "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&");
  // Serial terminals may normalize guest CRLF to LF. The management textarea
  // represents an HTTP wire request, so restore canonical CRLF before sending
  // it back; otherwise RangeProxy correctly rejects the edited framing.
  return decoded.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n/g, "\r\n");
}

export function parseProxyEvidence(output: string): ProxyEvidenceItem[] {
  const items: ProxyEvidenceItem[] = [];
  for (const line of output.split("\n")) {
    if (!line.trim().startsWith("{")) continue;
    try {
      const item = JSON.parse(line) as ProxyEvidenceItem;
      if (item && typeof item.kind === "string" && typeof item.request_base64 === "string") items.push(item);
    } catch {
      // A partial final JSONL line is not valid evidence and is never matched.
    }
  }
  return items;
}

export function evidenceRequest(item: ProxyEvidenceItem): string {
  return atob(item.request_base64);
}

export function editDefaultRepeaterRequest(defaultRaw: string, marker: string): string {
  let raw = defaultRaw.replace(/^GET \/health\.php HTTP\/1\.1/, `POST /health.php?evidence=${marker} HTTP/1.1`);
  if (raw === defaultRaw) throw new Error("Repeater default request did not have the documented method and URL");
  raw = raw.replace(/^User-Agent:[^\r\n]*\r?\n/m, `User-Agent: RangeRepeaterAcceptance/1.0\r\nX-Proxy-Acceptance: ${marker}\r\nContent-Length: 0\r\n`);
  if (!raw.includes(`X-Proxy-Acceptance: ${marker}`)) throw new Error("Repeater default headers could not be edited");
  return raw;
}

function evidenceMatches(output: string, kind: string, marker: string): ProxyEvidenceItem[] {
  return parseProxyEvidence(output).filter((candidate) => candidate.kind === kind && evidenceRequest(candidate).includes(marker));
}

function apacheMatches(output: string, marker: string): string[] {
  return output.split("\n").filter((line) => line.includes(marker));
}

export function oneDistinctApacheLine(output: string, marker: string): { line: string; occurrences: number } {
  const matches = apacheMatches(output, marker);
  const distinct = [...new Set(matches)];
  if (distinct.length !== 1) {
    throw new Error(`Expected one distinct Apache request for ${marker}; found ${distinct.length} distinct lines in ${matches.length} occurrences:\n${matches.join("\n")}`);
  }
  return { line: distinct[0]!, occurrences: matches.length };
}

export function apacheRequestMatches(line: string, method: string, path: string): boolean {
  // HTTP proxies send absolute-form; Repeater normally uses origin-form.
  // Apache preserves either form in %r, so require the exact request target
  // in both valid forms instead of assuming the proxy rewrote it.
  return line.includes(`\"${method} ${path} HTTP/`) || line.includes(`\"${method} http://192.168.10.55${path} HTTP/`);
}

export function managementRequestBody(raw: string, id?: string): string {
  const encode = (value: string) => encodeURIComponent(value).replace(/'/g, "%27");
  return `raw=${encode(raw)}${id === undefined ? "" : `&id=${encode(id)}`}`;
}

function managementStatus(output: string): number {
  const match = output.match(/PROXY_HTTP_STATUS:(\d+)/);
  if (!match) throw new Error(`Management response had no bounded curl status: ${output.slice(-800)}`);
  return Number(match[1]);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${Math.round(ms / 1000)}s`)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export class ProxyAcceptanceRunner {
  private report: ProxyAcceptanceReport;
  private initialIntercept: boolean | null = null;
  private heldIds = new Set<string>();

  constructor(private host: ProxyAcceptanceHost, runId = randomToken(8)) {
    this.report = {
      schema: 1,
      runId,
      startedAt: new Date().toISOString(),
      finishedAt: null,
      status: "RUNNING",
      gates: GATE_IDS.map((id) => ({ id, label: GATE_LABELS[id], status: "PENDING", detail: "Not reached" })),
      markers: {},
      artifacts: {},
      error: null,
    };
  }

  private emit(): void {
    this.host.onProgress({
      ...this.report,
      gates: this.report.gates.map((gate) => ({ ...gate })),
      markers: { ...this.report.markers },
      artifacts: { ...this.report.artifacts },
    });
  }

  private capture(name: string, machine: MachineId, data: string): void {
    this.report.artifacts[name] = data;
    this.host.capture(name, machine, data);
    this.emit();
  }

  private marker(name: string): string {
    const value = this.report.markers[name];
    if (!value) throw new Error(`Proxy acceptance marker ${name} was not initialized by its preceding gate`);
    return value;
  }

  private async command(machine: MachineId, command: string, timeout = 30_000): Promise<CommandResult> {
    const result = await this.host.execute(machine, command, timeout);
    if (result.exitCode !== 0) throw new Error(`${machine} command exited ${result.exitCode}: ${command}\n${result.output.slice(-1600)}`);
    return result;
  }

  private async gate(id: ProxyAcceptanceGateId, action: () => Promise<string>): Promise<boolean> {
    if (this.report.status !== "RUNNING") return false;
    const gate = this.report.gates.find((item) => item.id === id)!;
    gate.status = "RUNNING";
    gate.detail = "Executing against the actual guests";
    this.emit();
    try {
      gate.detail = await action();
      gate.status = "PASS";
      this.emit();
      return true;
    } catch (error) {
      gate.status = "FAIL";
      gate.detail = error instanceof Error ? error.message : String(error);
      this.report.status = "FAIL";
      this.report.error = gate.detail;
      for (const remaining of this.report.gates) {
        if (remaining.status === "PENDING") {
          remaining.status = "BLOCKED";
          remaining.detail = "Not reached because an earlier proxy acceptance gate failed";
        }
      }
      this.emit();
      return false;
    }
  }

  private async state(): Promise<ProxyState> {
    const result = await this.command("attacker", `${MANAGEMENT} -fsS --max-time 5 ${MANAGEMENT_URL}/api/state`, 10_000);
    return jsonFromOutput<ProxyState>(result.output);
  }

  private async setIntercept(enabled: boolean): Promise<void> {
    const current = await this.state();
    if (this.initialIntercept === null) this.initialIntercept = current.intercept;
    if (current.intercept !== enabled) {
      await this.command("attacker", `${MANAGEMENT} -fsS --max-time 5 -X POST -d '' ${MANAGEMENT_URL}/toggle >/dev/null`, 10_000);
    }
    const updated = await this.state();
    if (updated.intercept !== enabled) throw new Error(`Interception did not change to ${enabled ? "ON" : "OFF"}: ${JSON.stringify(updated)}`);
  }

  private async targetLogs(): Promise<string> {
    const result = await this.command("target", "labctl logs access", 30_000);
    return result.output;
  }

  private async evidence(): Promise<string> {
    const result = await this.command("attacker", "labctl evidence", 30_000);
    return result.output;
  }

  private async launchBrowser(marker: string): Promise<void> {
    await this.command("attacker", `BROWSER=$(command -v dillo-beta || command -v dillo) || exit 1; DISPLAY=:0 "$BROWSER" '${TARGET_URL}?evidence=${marker}' >>/tmp/proxy-acceptance-dillo.log 2>&1 &`, 10_000);
  }

  private async waitPending(marker: string, timeoutMs = 60_000): Promise<{ id: string; state: ProxyState }> {
    const deadline = Date.now() + timeoutMs;
    let latest = "";
    while (Date.now() < deadline) {
      const state = await this.state();
      latest = JSON.stringify(state);
      const pending = state.pending.find((item) => item.request_line.includes(marker));
      if (pending) {
        this.heldIds.add(pending.id);
        return { id: pending.id, state };
      }
      await sleep(750);
    }
    throw new Error(`No real held browser request contained ${marker} before the bounded wait expired: ${latest}`);
  }

  private async heldRaw(id: string): Promise<{ raw: string; html: string }> {
    const result = await this.command("attacker", `${MANAGEMENT} -fsS --max-time 8 '${MANAGEMENT_URL}/request?id=${id}'`, 15_000);
    return { raw: decodeManagementTextarea(result.output, 24), html: result.output };
  }

  private async postRaw(action: "/forward" | "/repeater", raw: string, id?: string, curlTimeout = 20, commandTimeout = 30_000): Promise<string> {
    // Send the exact edited bytes as an ASCII form payload. This avoids a
    // temporary file and another Python process on the software-emulated guest
    // while preserving every CR/LF through percent encoding.
    const body = managementRequestBody(raw, id);
    const result = await this.command("attacker", `${MANAGEMENT} -sS --max-time ${curlTimeout} -w '\\nPROXY_HTTP_STATUS:%{http_code}\\n' --data '${body}' '${MANAGEMENT_URL}${action}'`, commandTimeout);
    return result.output;
  }

  private async dropHeld(id: string): Promise<void> {
    await this.command("attacker", `${MANAGEMENT} -fsS --max-time 8 --data-urlencode 'id=${id}' '${MANAGEMENT_URL}/drop' >/dev/null`, 15_000);
    this.heldIds.delete(id);
  }

  private async waitTargetMarker(marker: string, timeoutMs = 60_000): Promise<string> {
    const deadline = Date.now() + timeoutMs;
    let logs = "";
    while (Date.now() < deadline) {
      logs = await this.targetLogs();
      if (logs.includes(marker)) return logs;
      await sleep(750);
    }
    throw new Error(`Target Apache did not record ${marker} before the bounded wait expired. Last log tail:\n${logs.slice(-2000)}`);
  }

  private async waitEvidence(marker: string, kind: string, timeoutMs = 60_000): Promise<{ output: string; item: ProxyEvidenceItem }> {
    const deadline = Date.now() + timeoutMs;
    let output = "";
    while (Date.now() < deadline) {
      output = await this.evidence();
      const item = parseProxyEvidence(output).find((candidate) => candidate.kind === kind && evidenceRequest(candidate).includes(marker));
      if (item) return { output, item };
      await sleep(750);
    }
    throw new Error(`Proxy evidence did not contain ${kind} for ${marker} before the bounded wait expired`);
  }

  private async proxyCurl(marker: string, path = "?evidence="): Promise<string> {
    const result = await this.command("attacker", `curl -x http://127.0.0.1:8080 --max-time 20 -fsS -i '${TARGET_URL}${path}${marker}'`, 30_000);
    if (!/HTTP\/1\.[01] 200/.test(result.output)) throw new Error(`Proxy request ${marker} did not return HTTP 200: ${result.output}`);
    return result.output;
  }

  private async restartProxy(): Promise<void> {
    await this.command("attacker", "PY=$(command -v python3 || command -v python3.6) || exit 1; nohup \"$PY\" -u /home/tc/lab/range_proxy.py >>/tmp/range-proxy.log 2>&1 &", 10_000);
    const deadline = Date.now() + 90_000;
    let last: unknown;
    while (Date.now() < deadline) {
      try {
        await this.state();
        return;
      } catch (error) {
        last = error;
        await sleep(1_000);
      }
    }
    throw new Error(`Proxy did not recover its management listener within 90s: ${last instanceof Error ? last.message : String(last)}`);
  }

  private async ensureProxyRunning(): Promise<void> {
    try {
      await this.state();
    } catch {
      await this.restartProxy();
    }
  }

  private processGate(): Promise<string> {
    return (async () => {
      const result = await this.command("attacker", "labctl ready && labctl proxy-state && printf '%s\\n' '--- Dillo configuration ---' && cat /home/tc/.dillo/dillorc && printf '%s\\n' '--- Processes and listeners ---' && ps && (netstat -ltn 2>&1 || ss -ltn 2>&1)", 30_000);
      this.capture("guest-configuration.txt", "attacker", result.output);
      const state = await this.state();
      this.initialIntercept = state.intercept;
      if (state.target !== "http://192.168.10.55:80") throw new Error(`Unexpected proxy target: ${state.target}`);
      if (state.pending.length !== 0) throw new Error("Finish or drop pre-existing held requests before running proxy acceptance");
      if (!result.output.includes("http_proxy=http://127.0.0.1:8080/")) throw new Error("Dillo proxy configuration is absent");
      return "The actual attacker reported Dillo, a running proxy, loopback proxy/management listeners, and target-only proxy configuration.";
    })();
  }

  private browserRoutingGate(): Promise<string> {
    return (async () => {
      const original = `browser-original-${randomToken(6)}`;
      const edited = `browser-edited-${randomToken(6)}`;
      this.report.markers.original = original;
      this.report.markers.edited = edited;
      this.capture("target-access-before-browser.log", "target", await this.targetLogs());
      await this.setIntercept(true);
      await this.launchBrowser(original);
      const pending = await this.waitPending(original);
      this.capture("browser-pending-state.json", "attacker", JSON.stringify(pending.state, null, 2));
      const held = await this.heldRaw(pending.id);
      this.report.markers.heldId = pending.id;
      this.capture("browser-held-request.raw", "attacker", held.raw);
      this.capture("browser-held-management.html", "attacker", held.html);
      if (!/^GET .*HTTP\/1\.[01]\r?$/.test(held.raw.split("\n")[0] ?? "")) throw new Error("Held request method/URL/version is not visible");
      if (!held.raw.includes(original) || !/Host: 192\.168\.10\.55/i.test(held.raw)) throw new Error("Held request does not contain the intended target URL and Host header");
      if (!/User-Agent:.*Dillo/i.test(held.raw)) throw new Error(`Held request did not come from Dillo:\n${held.raw}`);
      return `${original}: a real Dillo request appeared in RangeProxy with its GET method, absolute target URL, Host/Dillo headers, and empty GET body visible.`;
    })();
  }

  private interceptionGate(): Promise<string> {
    return (async () => {
      const original = this.marker("original");
      const heldId = this.marker("heldId");
      await sleep(1_500);
      const logs = await this.targetLogs();
      this.capture("browser-before-forward-access.log", "target", logs);
      if (logs.includes(original)) throw new Error("The held browser request reached Apache before operator forwarding");
      const state = await this.state();
      if (!state.pending.some((item) => item.id === heldId)) throw new Error("The browser request did not remain paused while the target was checked");
      return `${original}: remained held in RangeProxy and was independently absent from Apache before forwarding.`;
    })();
  }

  private editingGate(): Promise<string> {
    return (async () => {
      const original = this.marker("original");
      const edited = this.marker("edited");
      const heldId = this.marker("heldId");
      const held = await this.heldRaw(heldId);
      const editedRaw = held.raw.replace(original, edited);
      if (editedRaw === held.raw || editedRaw.includes(original) || !editedRaw.includes(edited)) throw new Error("The harmless query marker edit was not applied exactly once");
      this.capture("browser-edited-request.raw", "attacker", editedRaw);
      const response = await this.postRaw("/forward", editedRaw, heldId);
      this.heldIds.delete(heldId);
      this.capture("browser-forward-response.html", "attacker", response);
      if (managementStatus(response) !== 200 || !response.includes("Real target response") || !response.includes("Status <b>200</b>") || !response.includes("Assessment Portal")) {
        throw new Error(`Forwarding did not return the genuine target response: ${response.slice(-2000)}`);
      }
      return `${original} → ${edited}: the edited raw request was forwarded and returned the target's real HTTP 200 response and body.`;
    })();
  }

  private targetLogGate(): Promise<string> {
    return (async () => {
      const original = this.marker("original");
      const edited = this.marker("edited");
      const logs = await this.waitTargetMarker(edited);
      this.capture("browser-after-forward-access.log", "target", logs);
      if (logs.includes(original)) throw new Error("The original marker reached Apache even though only the edited request was forwarded");
      const evidence = await this.waitEvidence(edited, "intercept-forwarded");
      this.capture("browser-forward-proxy-evidence.jsonl", "attacker", evidence.output);
      const forwards = evidenceMatches(evidence.output, "intercept-forwarded", edited);
      const apache = oneDistinctApacheLine(logs, edited);
      if (forwards.length !== 1) throw new Error(`Expected exactly one real proxy intercept-forwarded record for ${edited}, found ${forwards.length}`);
      if (!apacheRequestMatches(apache.line, "GET", `/?evidence=${edited}`) || !apache.line.includes(" 200 ")) throw new Error(`Edited Apache line does not match the intended GET and HTTP 200: ${apache.line}`);
      const loggingConfig = await this.command("target", "grep -R -n -E '^[[:space:]]*(ServerRoot|CustomLog)' /etc/apache2 2>/dev/null || true", 15_000);
      this.capture("target-logging-configuration.txt", "target", loggingConfig.output);
      return `${edited}: one real proxy intercept-forwarded record and one distinct Apache GET with HTTP 200 corroborated the edit (${apache.occurrences} identical log occurrence${apache.occurrences === 1 ? "" : "s"}); ${original} remained absent.`;
    })();
  }

  private disabledGate(): Promise<string> {
    return (async () => {
      const marker = `browser-off-${randomToken(6)}`;
      this.report.markers.disabled = marker;
      await this.setIntercept(false);
      await this.launchBrowser(marker);
      const deadline = Date.now() + 60_000;
      let evidenceOutput = "";
      let logs = "";
      let item: ProxyEvidenceItem | undefined;
      while (Date.now() < deadline) {
        evidenceOutput = await this.evidence();
        item = parseProxyEvidence(evidenceOutput).find((candidate) => candidate.kind === "forwarded" && evidenceRequest(candidate).includes(marker));
        logs = await this.targetLogs();
        if (item && logs.includes(marker)) break;
        await sleep(750);
      }
      this.capture("disabled-proxy-evidence.jsonl", "attacker", evidenceOutput);
      this.capture("disabled-target-access.log", "target", logs);
      if (!item) throw new Error("Interception-off browser traffic did not produce a forwarded proxy record; a direct-route fallback cannot be ruled out");
      const forwarded = evidenceMatches(evidenceOutput, "forwarded", marker);
      if (forwarded.length !== 1) throw new Error(`Interception-off marker had ${forwarded.length} real proxy forwarded records instead of one`);
      const raw = evidenceRequest(item);
      if (!/User-Agent:.*Dillo/i.test(raw)) throw new Error("The interception-off proxy record was not from Dillo");
      const apache = oneDistinctApacheLine(logs, marker);
      if (!apacheRequestMatches(apache.line, "GET", `/?evidence=${marker}`) || !apache.line.includes(" 200 ")) throw new Error(`Interception-off Apache line does not match the Dillo GET: ${apache.line}`);
      return `${marker}: with interception OFF, one Dillo RangeProxy forwarded record and one distinct Apache GET ruled out a direct-route fallback (${apache.occurrences} identical log occurrence${apache.occurrences === 1 ? "" : "s"}).`;
    })();
  }

  private repeaterGate(): Promise<string> {
    return (async () => {
      const marker = `repeater-${randomToken(6)}`;
      this.report.markers.repeater = marker;
      const page = await this.command("attacker", `${MANAGEMENT} -fsS --max-time 8 ${MANAGEMENT_URL}/`, 15_000);
      const defaultRaw = decodeManagementTextarea(page.output, 14);
      const raw = editDefaultRepeaterRequest(defaultRaw, marker);
      if (!raw.startsWith(`POST /health.php?evidence=${marker} HTTP/1.1\r\n`) || !raw.includes(`User-Agent: RangeRepeaterAcceptance/1.0`) || !raw.includes(`X-Proxy-Acceptance: ${marker}`)) {
        throw new Error("Repeater method, URL, and headers were not all edited");
      }
      this.capture("repeater-request.raw", "attacker", raw);
      const response = await this.postRaw("/repeater", raw);
      this.capture("repeater-response.html", "attacker", response);
      if (managementStatus(response) !== 200 || !response.includes("Status <b>200</b>") || !response.includes("application/json") || !response.includes("apache2handler") || !response.includes("8.2.34")) {
        throw new Error(`Repeater did not display the actual target status, headers, and health body: ${response.slice(-2000)}`);
      }
      const logs = await this.waitTargetMarker(marker);
      this.capture("repeater-target-access.log", "target", logs);
      const line = logs.split("\n").find((candidate) => candidate.includes(marker)) ?? "";
      if (!apacheRequestMatches(line, "POST", `/health.php?evidence=${marker}`) || !line.includes(" 200 ")) throw new Error(`Repeater Apache line is not the edited POST: ${line}`);
      const evidence = await this.waitEvidence(marker, "repeater");
      this.capture("repeater-proxy-evidence.jsonl", "attacker", evidence.output);
      if (!evidenceRequest(evidence.item).includes("X-Proxy-Acceptance")) throw new Error("Repeater evidence lacks the edited header");
      return `${marker}: Repeater sent the edited POST URL and headers, displayed the real JSON response/status/headers, and was corroborated by Apache.`;
    })();
  }

  private async malformedCheck(): Promise<void> {
    const marker = `malformed-${randomToken(6)}`;
    this.report.markers.malformed = marker;
    const raw = `POST /health.php?evidence=${marker} HTTP/1.1\r\nHost: 192.168.10.55\r\nContent-Length: 9\r\nConnection: close\r\n\r\nx`;
    const response = await this.postRaw("/repeater", raw);
    this.capture("malformed-response.html", "attacker", response);
    if (managementStatus(response) !== 400 || !response.includes("Request was not sent") || !response.includes("Content-Length")) throw new Error("Malformed framing was not rejected with its real error");
    const logs = await this.targetLogs();
    if (logs.includes(marker)) throw new Error("Malformed Repeater request reached Apache");
  }

  private async heldDropCheck(): Promise<void> {
    const marker = `held-drop-${randomToken(6)}`;
    this.report.markers.held = marker;
    await this.setIntercept(true);
    await this.launchBrowser(marker);
    const pending = await this.waitPending(marker);
    await sleep(1_000);
    let logs = await this.targetLogs();
    if (logs.includes(marker)) throw new Error("Unforwarded intercepted request silently reached Apache");
    await this.dropHeld(pending.id);
    const evidence = await this.waitEvidence(marker, "intercept-dropped");
    logs = await this.targetLogs();
    this.capture("held-drop-evidence.jsonl", "attacker", evidence.output);
    this.capture("held-drop-target-access.log", "target", logs);
    if (logs.includes(marker)) throw new Error("Explicitly dropped browser request reached Apache");
  }

  private async proxyFailureRecoveryCheck(): Promise<void> {
    const downMarker = `proxy-down-${randomToken(6)}`;
    const recoveryMarker = `proxy-recovery-${randomToken(6)}`;
    this.report.markers.proxyDown = downMarker;
    this.report.markers.recovery = recoveryMarker;
    await this.setIntercept(false);
    const stopped = await this.command("attacker", "pids=''; for pid in $(pidof python3 python3.6 2>/dev/null); do [ -r \"/proc/$pid/cmdline\" ] || continue; cmd=$(tr '\\000' ' ' <\"/proc/$pid/cmdline\"); case \"$cmd\" in *'/home/tc/lab/range_proxy.py'*) pids=\"$pids $pid\"; printf 'PROXY_PID=%s CMD=%s\\n' \"$pid\" \"$cmd\";; esac; done; [ -n \"$pids\" ] || exit 1; kill $pids; n=0; while [ \"$n\" -lt 20 ]; do if ! curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8081/api/state >/dev/null 2>&1; then printf '%s\\n' 'PROXY_LISTENER_STOPPED=1'; exit 0; fi; n=$((n+1)); sleep 1; done; exit 1", 30_000);
    this.capture("proxy-stop.txt", "attacker", stopped.output);
    const unavailable = await this.command("attacker", `out=$(curl -x http://127.0.0.1:8080 --max-time 5 -sS -i '${TARGET_URL}?evidence=${downMarker}' 2>&1); rc=$?; printf '%s\\nPROXY_CLIENT_RC=%s\\n' \"$out\" \"$rc\"; [ \"$rc\" -ne 0 ]`, 15_000);
    this.capture("proxy-unavailable.txt", "attacker", unavailable.output);
    let logs = await this.targetLogs();
    if (logs.includes(downMarker)) throw new Error("Request succeeded despite the proxy listener being unavailable");
    await this.restartProxy();
    await this.setIntercept(false);
    const recovery = await this.proxyCurl(recoveryMarker);
    this.capture("proxy-recovery-response.txt", "attacker", recovery);
    logs = await this.waitTargetMarker(recoveryMarker);
    this.capture("proxy-recovery-target-access.log", "target", logs);
  }

  private async targetFailureTimeoutCheck(): Promise<void> {
    const unavailableMarker = `target-down-${randomToken(6)}`;
    const timeoutMarker = `request-timeout-${randomToken(6)}`;
    const recoveryMarker = `target-recovery-${randomToken(6)}`;
    Object.assign(this.report.markers, { unavailable: unavailableMarker, timeout: timeoutMarker, targetRecovery: recoveryMarker });
    await this.setIntercept(false);
    await withTimeout(this.host.pauseTarget(), 10_000, "Target v86 stop");
    try {
      const raw = `GET /health.php?evidence=${unavailableMarker} HTTP/1.1\r\nHost: 192.168.10.55\r\nUser-Agent: RangeFailureAcceptance/1.0\r\nConnection: close\r\n\r\n`;
      const unavailable = await this.postRaw("/repeater", raw, undefined, 35, 45_000);
      this.capture("target-unavailable-response.html", "attacker", unavailable);
      if (managementStatus(unavailable) !== 400 || !unavailable.includes("Request was not sent")) throw new Error("Paused target did not produce a real Repeater forwarding error");
      const timeout = await this.command("attacker", `out=$(curl -x http://127.0.0.1:8080 --max-time 3 -sS -i '${TARGET_URL}health.php?evidence=${timeoutMarker}' 2>&1); rc=$?; printf '%s\\nPROXY_CLIENT_RC=%s\\n' \"$out\" \"$rc\"; [ \"$rc\" -eq 28 ]`, 10_000);
      this.capture("request-timeout.txt", "attacker", timeout.output);
      // Keep the target paused until both proxy-side 20-second connect attempts
      // have failed, so a timed-out marker cannot appear after target resume.
      await sleep(25_000);
    } finally {
      await withTimeout(this.host.resumeTarget(), 10_000, "Target v86 resume");
    }
    const logs = await this.targetLogs();
    this.capture("target-failure-access.log", "target", logs);
    if (logs.includes(unavailableMarker) || logs.includes(timeoutMarker)) throw new Error("An unavailable/timed-out request unexpectedly reached Apache");
    const recovery = await this.proxyCurl(recoveryMarker, "health.php?evidence=");
    this.capture("target-recovery-response.txt", "attacker", recovery);
    const recoveredLogs = await this.waitTargetMarker(recoveryMarker);
    this.capture("target-recovery-access.log", "target", recoveredLogs);
  }

  private async repeatedRequestsCheck(): Promise<void> {
    const markers = [`repeat-a-${randomToken(6)}`, `repeat-b-${randomToken(6)}`];
    this.report.markers.repeatA = markers[0]!;
    this.report.markers.repeatB = markers[1]!;
    await this.setIntercept(false);
    const responses = [] as string[];
    for (const marker of markers) responses.push(await this.proxyCurl(marker, "health.php?evidence="));
    this.capture("repeated-proxy-responses.txt", "attacker", responses.join("\n\n--- next request ---\n\n"));
    const logs = await this.waitTargetMarker(markers[1]!);
    this.capture("repeated-target-access.log", "target", logs);
    for (const marker of markers) {
      const apache = oneDistinctApacheLine(logs, marker);
      if (!apacheRequestMatches(apache.line, "GET", `/health.php?evidence=${marker}`) || !apache.line.includes(" 200 ")) throw new Error(`Repeated-request Apache line does not match ${marker}: ${apache.line}`);
      const evidence = await this.waitEvidence(marker, "forwarded");
      this.capture("repeated-proxy-evidence.jsonl", "attacker", evidence.output);
      if (evidenceMatches(evidence.output, "forwarded", marker).length !== 1) throw new Error(`Repeated request ${marker} did not have exactly one real proxy forwarded record`);
    }
  }

  private errorsGate(): Promise<string> {
    return (async () => {
      await this.malformedCheck();
      await this.heldDropCheck();
      await this.proxyFailureRecoveryCheck();
      await this.targetFailureTimeoutCheck();
      await this.repeatedRequestsCheck();
      const diagnostics = await this.command("attacker", "labctl ready; labctl proxy-state; ps; netstat -ltn 2>&1 || ss -ltn 2>&1; printf '%s\\n' '--- proxy log ---'; tail -n 100 /tmp/range-proxy.log; printf '%s\\n' '--- Dillo log ---'; tail -n 80 /tmp/proxy-acceptance-dillo.log 2>&1", 30_000);
      this.capture("proxy-diagnostics.txt", "attacker", diagnostics.output);
      return "Malformed framing was rejected; a held request stayed off the target until explicit drop; proxy-down, paused-target, and caller-timeout errors were bounded; proxy/target recovery and repeated requests passed.";
    })();
  }

  private async cleanup(): Promise<void> {
    const problems: string[] = [];
    try {
      await withTimeout(this.host.resumeTarget(), 10_000, "Cleanup target resume");
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
    try {
      await this.ensureProxyRunning();
      const state = await this.state();
      // The readiness gate rejects pre-existing learner holds, so every hold
      // left here belongs to this run (including an auxiliary favicon).
      for (const pending of state.pending) await this.dropHeld(pending.id);
      if (this.initialIntercept !== null) await this.setIntercept(this.initialIntercept);
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
    if (problems.length) throw new Error(`Proxy acceptance cleanup failed: ${problems.join(" | ")}`);
  }

  async run(): Promise<ProxyAcceptanceReport> {
    this.emit();
    const gates: Array<[ProxyAcceptanceGateId, () => Promise<string>]> = [
      ["process", () => this.processGate()],
      ["browser-routing", () => this.browserRoutingGate()],
      ["interception", () => this.interceptionGate()],
      ["editing", () => this.editingGate()],
      ["target-log", () => this.targetLogGate()],
      ["disabled", () => this.disabledGate()],
      ["repeater", () => this.repeaterGate()],
      ["errors", () => this.errorsGate()],
    ];
    try {
      for (const [id, action] of gates) {
        if (!await this.gate(id, action)) break;
      }
      if (this.report.status === "RUNNING") this.report.status = "PASS";
      await this.cleanup();
    } catch (error) {
      this.report.status = "FAIL";
      this.report.error = error instanceof Error ? error.message : String(error);
      const errors = this.report.gates.find((gate) => gate.id === "errors")!;
      if (errors.status === "PASS") {
        errors.status = "FAIL";
        errors.detail = this.report.error;
      }
    } finally {
      this.report.finishedAt = new Date().toISOString();
      this.emit();
    }
    return this.report;
  }
}
