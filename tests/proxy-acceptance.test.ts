import { describe, expect, it } from "vitest";
import { apacheRequestMatches, decodeManagementTextarea, editDefaultRepeaterRequest, evidenceRequest, managementRequestBody, oneDistinctApacheLine, parseProxyEvidence } from "../src/lib/ProxyAcceptance";

const DEFAULT_RAW = "GET /health.php HTTP/1.1\r\nHost: 192.168.10.55\r\nUser-Agent: RangeRepeater/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";

describe("real proxy acceptance helpers", () => {
  it("reads the actual escaped management textarea without changing HTTP CRLF", () => {
    const html = `<form><textarea name=raw rows=24>GET /?x=1&amp;y=2 HTTP/1.1\r\nHost: 192.168.10.55\r\nX-Test: &lt;value&gt;\r\n\r\n</textarea></form>`;
    expect(decodeManagementTextarea(html, 24)).toBe("GET /?x=1&y=2 HTTP/1.1\r\nHost: 192.168.10.55\r\nX-Test: <value>\r\n\r\n");
    const serialNormalized = `<textarea name=raw rows=24>GET /serial HTTP/1.1\nHost: 192.168.10.55\n\n</textarea>`;
    expect(decodeManagementTextarea(serialNormalized, 24)).toBe("GET /serial HTTP/1.1\r\nHost: 192.168.10.55\r\n\r\n");
    expect(() => decodeManagementTextarea("no request", 24)).toThrow("textarea");
  });

  it("edits Repeater method, URL, and headers with valid CRLF and zero-length framing", () => {
    const raw = editDefaultRepeaterRequest(DEFAULT_RAW, "repeater-test-123");
    expect(raw).toBe("POST /health.php?evidence=repeater-test-123 HTTP/1.1\r\nHost: 192.168.10.55\r\nUser-Agent: RangeRepeaterAcceptance/1.0\r\nX-Proxy-Acceptance: repeater-test-123\r\nContent-Length: 0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    expect(raw.replace(/\r\n/g, "")).not.toContain("\n");
    expect(() => editDefaultRepeaterRequest("GET /other HTTP/1.1\r\n\r\n", "x")).toThrow("method and URL");
  });

  it("round-trips exact raw CRLF and delimiters through the management form", () => {
    const raw = "POST /health.php?x=1&y=2 HTTP/1.1\r\nHost: 192.168.10.55\r\nX-Test: '%=+&\r\nContent-Length: 4\r\n\r\nbody";
    const body = managementRequestBody(raw, "held'id");
    expect(body).not.toContain("'");
    const fields = new URLSearchParams(body);
    expect(fields.get("raw")).toBe(raw);
    expect(fields.get("id")).toBe("held'id");
    expect(fields.get("raw")?.replace(/\r\n/g, "")).not.toContain("\n");
  });

  it("deduplicates only identical Apache log occurrences, never distinct requests", () => {
    const line = `192.168.10.10 - - [now] "GET /?evidence=apache-marker HTTP/1.1" 200 123 "-" "Dillo" pid=42`;
    expect(oneDistinctApacheLine(`${line}\n${line}`, "apache-marker")).toEqual({ line, occurrences: 2 });
    expect(apacheRequestMatches(line, "GET", "/?evidence=apache-marker")).toBe(true);
    expect(apacheRequestMatches(line.replace(`\"GET /?evidence`, `\"GET http://192.168.10.55/?evidence`), "GET", "/?evidence=apache-marker")).toBe(true);
    expect(apacheRequestMatches(line, "POST", "/?evidence=apache-marker")).toBe(false);
    expect(apacheRequestMatches(line, "GET", "/other")).toBe(false);
    expect(() => oneDistinctApacheLine(`${line}\n${line.replace("pid=42", "pid=43")}`, "apache-marker")).toThrow("2 distinct lines");
    expect(() => oneDistinctApacheLine("unrelated", "apache-marker")).toThrow("0 distinct lines");
  });

  it("accepts only complete guest JSONL records and decodes their real request bytes", () => {
    const raw = "GET / HTTP/1.1\r\nHost: 192.168.10.55\r\n\r\n";
    const valid = JSON.stringify({ kind: "forwarded", request_base64: btoa(raw), sequence: 1, timestamp: "now" });
    const items = parseProxyEvidence(`noise\n${valid}\n{"kind":"forwarded","request_base64":"truncated"`);
    expect(items).toHaveLength(1);
    expect(evidenceRequest(items[0]!)).toBe(raw);
    expect(parseProxyEvidence("not json\n\n")).toEqual([]);
  });
});
