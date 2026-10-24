import { describe, expect, it } from "vitest";
import { decodeManagementTextarea, editDefaultRepeaterRequest, evidenceRequest, parseProxyEvidence } from "../src/lib/ProxyAcceptance";

const DEFAULT_RAW = "GET /health.php HTTP/1.1\r\nHost: 192.168.10.55\r\nUser-Agent: RangeRepeater/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";

describe("real proxy acceptance helpers", () => {
  it("reads the actual escaped management textarea without changing HTTP CRLF", () => {
    const html = `<form><textarea name=raw rows=24>GET /?x=1&amp;y=2 HTTP/1.1\r\nHost: 192.168.10.55\r\nX-Test: &lt;value&gt;\r\n\r\n</textarea></form>`;
    expect(decodeManagementTextarea(html, 24)).toBe("GET /?x=1&y=2 HTTP/1.1\r\nHost: 192.168.10.55\r\nX-Test: <value>\r\n\r\n");
    expect(() => decodeManagementTextarea("no request", 24)).toThrow("textarea");
  });

  it("edits Repeater method, URL, and headers with valid CRLF and zero-length framing", () => {
    const raw = editDefaultRepeaterRequest(DEFAULT_RAW, "repeater-test-123");
    expect(raw).toBe("POST /health.php?evidence=repeater-test-123 HTTP/1.1\r\nHost: 192.168.10.55\r\nUser-Agent: RangeRepeaterAcceptance/1.0\r\nX-Proxy-Acceptance: repeater-test-123\r\nContent-Length: 0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    expect(raw.replace(/\r\n/g, "")).not.toContain("\n");
    expect(() => editDefaultRepeaterRequest("GET /other HTTP/1.1\r\n\r\n", "x")).toThrow("method and URL");
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
