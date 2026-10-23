import { describe, expect, it } from "vitest";
import { assertLocalAssetPath } from "../src/lib/assets";
import { initialState } from "../src/lib/initialState";
import { createJsonReport, createMarkdownReport } from "../src/lib/report";
import { clampText, formatBytes, parseKeyValues, stripAnsi } from "../src/lib/utils";
import type { LabState } from "../src/types";

function state(): LabState {
  return structuredClone(initialState);
}

describe("guest output helpers", () => {
  it("parses key/value evidence without interpreting its meaning", () => {
    expect(parseKeyValues("php_version=8.2.34\ninvalid\npath=a=b\n")).toEqual({ php_version: "8.2.34", path: "a=b" });
  });

  it("removes terminal control sequences but preserves observable text", () => {
    expect(stripAnsi("\u001b]0;title\u0007\u001b[31mApache\u001b[0m\r\n")).toBe("Apache\n");
  });

  it("formats binary units and bounds long serial output", () => {
    expect(formatBytes(134217728)).toBe("128.0 MiB");
    expect(clampText("abcdef", 3)).toContain("earlier characters omitted");
    expect(clampText("abcdef", 3)).toContain("def");
  });
});

describe("local asset boundary", () => {
  it("accepts only same-origin paths in pinned asset directories", () => {
    expect(assertLocalAssetPath("/lab-assets/target.iso", "https://range.invalid").href).toBe("https://range.invalid/lab-assets/target.iso");
    expect(assertLocalAssetPath("/v86/v86.wasm", "https://range.invalid").hostname).toBe("range.invalid");
  });

  it.each([
    "https://example.invalid/target.iso",
    "//example.invalid/target.iso",
    "/lab-assets/../secret",
    "/etc/passwd",
    "/lab-assets/image.iso?url=https://example.invalid",
  ])("refuses %s", (path) => {
    expect(() => assertLocalAssetPath(path, "https://range.invalid")).toThrow();
  });
});

describe("evidence report truthfulness", () => {
  it("does not promote an OOM observation to RCE completion", () => {
    const lab = state();
    lab.status = "testing";
    lab.evidence.push({ id: "oom-1", timestamp: "2026-10-23T00:00:00Z", title: "Observed PHP fatal OOM", source: "target /var/log/apache2/php-error.log", machine: "target", category: "log", data: "PHP Fatal error: Allowed memory size exhausted", genuine: true });
    const report = createJsonReport(lab);
    expect(JSON.parse(report).execution.completion).toBe("Incomplete / genuine RCE not verified");
    expect(JSON.parse(report).execution.simulated).toBe(false);
    expect(report).toContain("Allowed memory size exhausted");
  });

  it("exports actual logs, provenance, checksums, and explicit completion", () => {
    const lab = state();
    lab.logs.access = '192.168.10.10 - - "GET /health.php?check=abc HTTP/1.1" 200';
    lab.session = { id: "range-test", startedAt: "2026-10-23T00:00:00Z", flagSha256: "abc123", challenge: "challenge", networkId: "42", targetBuild: "alpine-php-8.2.34", phpVersion: "8.2.34", proof: { observedAt: "2026-10-23T00:01:00Z", owner: "apache", path: "/var/www/html/rce-proof.txt", data: "challenge\n" } };
    lab.completedAs = "genuine-rce";
    const markdown = createMarkdownReport(lab);
    expect(markdown).toContain("Genuine RCE evidence and matching flag validated");
    expect(markdown).toContain("GET /health.php?check=abc");
    expect(markdown).toContain("not a host-safety certification");
  });
});
