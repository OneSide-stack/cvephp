import { describe, expect, it } from "vitest";
import { assertLocalAssetPath } from "../src/lib/assets";
import { clampText, formatBytes, jsonFromOutput, parseKeyValues, stripAnsi } from "../src/lib/utils";

describe("guest output helpers", () => {
  it("parses key/value evidence without interpreting its meaning", () => {
    expect(parseKeyValues("php_version=8.2.34\ninvalid\npath=a=b\n")).toEqual({ php_version: "8.2.34", path: "a=b" });
  });

  it("ignores echoed shell blocks and parses compact or pretty guest JSON", () => {
    expect(jsonFromOutput<{ machine: string }>("{ labctl ready\n}\n{\"machine\":\"attacker\"}\n").machine).toBe("attacker");
    expect(jsonFromOutput<{ service: string; nested: { ok: boolean } }>("{ labctl health\n}\n{\n  \"service\": \"assessment-portal\",\n  \"nested\": { \"ok\": true }\n}\n").nested.ok).toBe(true);
  });

  it("handles braces in JSON strings and rejects missing valid objects", () => {
    expect(jsonFromOutput<{ value: string }>("{ command\n}\n{\"value\":\"a } and { brace\"}").value).toBe("a } and { brace");
    expect(() => jsonFromOutput("{ labctl ready\n}")).toThrow("valid JSON");
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
