import { expect, test } from "@playwright/test";
import { writeFile } from "node:fs/promises";
import type { ProxyAcceptanceGate, ProxyAcceptanceGateId, ProxyAcceptanceReport } from "../../src/types";

const GATE_IDS: ProxyAcceptanceGateId[] = ["process", "browser-routing", "interception", "editing", "target-log", "disabled", "repeater", "errors"];

function decodedProxyRequests(jsonl: string): Array<{ kind: string; raw: string }> {
  const requests: Array<{ kind: string; raw: string }> = [];
  for (const line of jsonl.split("\n")) {
    if (!line.trim().startsWith("{")) continue;
    try {
      const item = JSON.parse(line) as { kind?: string; request_base64?: string };
      if (item.kind && item.request_base64) requests.push({ kind: item.kind, raw: atob(item.request_base64) });
    } catch {
      // Ignore incomplete lines; they cannot satisfy an acceptance assertion.
    }
  }
  return requests;
}

test("real Dillo interception, editing, Repeater, target logs, and recovery", async ({ page }, testInfo) => {
  test.setTimeout(25 * 60 * 1000);
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  let report: ProxyAcceptanceReport | null = null;
  let harnessError: string | null = null;
  let navigationDuringErrors = false;
  let browserCheckReached = false;
  const extraArtifacts = new Map<string, string>();

  const readReport = async () => {
    const text = await page.locator("#proxy-acceptance-json").textContent({ timeout: 1_000 });
    if (!text) return null;
    return JSON.parse(text) as ProxyAcceptanceReport;
  };

  try {
    await page.goto("/");
    await expect(page.locator(".preflight-list")).toContainText("Attacker ISO");
    await expect(page.locator(".preflight-list")).toContainText("Target ISO");
    await expect(page.locator(".preflight-list .text-success")).toHaveCount(3);
    await page.getByRole("button", { name: "Start lab", exact: true }).first().click();
    const labStatus = page.locator(".brand-right .status-pill");
    await page.waitForFunction(() => {
      const status = document.querySelector(".brand-right .status-pill")?.textContent?.trim();
      return status === "Ready" || status === "Failed";
    }, undefined, { timeout: 15 * 60 * 1000 });
    if ((await labStatus.textContent())?.trim() !== "Ready") {
      throw new Error((await page.getByRole("alert").textContent())?.trim() || "Lab startup failed before proxy acceptance");
    }
    await expect(page.locator("#vm-attacker .vm-statusbar .status-pill")).toHaveText("Ready");
    await expect(page.locator("#vm-target .vm-statusbar .status-pill")).toHaveText("Ready");
    await expect(page.locator(".tool-tags")).toContainText("dillo-beta");

    await page.getByRole("button", { name: "Run real proxy acceptance", exact: true }).click();
    await expect(page.locator("#proxy-acceptance-json")).toBeAttached();
    await page.waitForFunction(() => {
      const errorGate = document.querySelector("#proxy-gate-errors");
      const status = document.querySelector("#proxy-acceptance-status")?.textContent?.trim();
      return errorGate?.classList.contains("running") || status === "PASS" || status === "FAIL";
    }, undefined, { timeout: 14 * 60 * 1000 });

    if ((await page.locator("#proxy-gate-errors").getAttribute("class"))?.includes("running")) {
      await page.getByRole("button", { name: "NETWORK TOPOLOGY", exact: true }).click();
      await expect(page.locator(".network-view")).toBeVisible();
      await page.getByRole("button", { name: "TARGET SERVER HOUSING", exact: true }).click();
      await expect(page.locator(".target-view")).toBeVisible();
      await expect(page.getByRole("button", { name: "Reset lab", exact: true })).toBeEnabled();
      await page.getByRole("button", { name: "ATTACKER WORKSTATION", exact: true }).click();
      await expect(page.locator(".proxy-acceptance-panel")).toBeVisible();
      navigationDuringErrors = true;
    }

    await expect(page.locator("#proxy-acceptance-status")).toHaveText(/^(PASS|FAIL)$/, { timeout: 8 * 60 * 1000 });
    report = await readReport();
    expect(report, "The controller must return its real proxy gate report").not.toBeNull();
    for (const gate of report!.gates) console.log(`PROXY ACCEPTANCE ${gate.status} ${gate.id}: ${gate.detail}`);
    for (const [name, data] of Object.entries(report!.artifacts)) {
      await testInfo.attach(name, {
        body: data,
        contentType: name.endsWith(".json") ? "application/json" : name.endsWith(".jsonl") ? "application/x-ndjson" : name.endsWith(".html") ? "text/html" : "text/plain",
      });
    }

    expect(report!.status).toBe("PASS");
    for (const id of GATE_IDS) {
      const gate = report!.gates.find((candidate) => candidate.id === id);
      expect(gate, `Missing proxy acceptance gate ${id}`).toBeDefined();
      expect(gate!.status, `${id}: ${gate!.detail}`).toBe("PASS");
    }
    expect(navigationDuringErrors).toBe(true);

    const { markers, artifacts } = report!;
    const originalRaw = artifacts["browser-held-request.raw"] ?? "";
    const editedRaw = artifacts["browser-edited-request.raw"] ?? "";
    expect(originalRaw).toContain(markers.original);
    expect(originalRaw).toMatch(/User-Agent:.*Dillo/i);
    expect(editedRaw).toContain(markers.edited);
    expect(editedRaw).not.toContain(markers.original);
    expect(artifacts["browser-before-forward-access.log"] ?? "").not.toContain(markers.original);
    expect(artifacts["browser-after-forward-access.log"] ?? "").toContain(markers.edited);
    expect(artifacts["browser-after-forward-access.log"] ?? "").not.toContain(markers.original);
    expect(artifacts["browser-forward-response.html"] ?? "").toContain("Status <b>200</b>");

    const disabledRequests = decodedProxyRequests(artifacts["disabled-proxy-evidence.jsonl"] ?? "");
    expect(disabledRequests.some((item) => item.kind === "forwarded" && item.raw.includes(markers.disabled!) && /User-Agent:.*Dillo/i.test(item.raw))).toBe(true);
    expect(artifacts["repeater-request.raw"] ?? "").toContain(`POST /health.php?evidence=${markers.repeater}`);
    expect(artifacts["repeater-request.raw"] ?? "").toContain("X-Proxy-Acceptance");
    expect(artifacts["repeater-response.html"] ?? "").toContain("Status <b>200</b>");
    expect(artifacts["repeater-response.html"] ?? "").toContain("apache2handler");
    expect(artifacts["malformed-response.html"] ?? "").toContain("Request was not sent");
    expect(artifacts["proxy-unavailable.txt"] ?? "").toMatch(/PROXY_CLIENT_RC=[1-9]/);
    expect(artifacts["request-timeout.txt"] ?? "").toContain("PROXY_CLIENT_RC=28");

    // Independently refresh the real target after all recovery checks rather
    // than accepting only the controller's earlier log snapshot.
    await page.getByRole("button", { name: "TARGET SERVER HOUSING", exact: true }).click();
    await page.getByRole("button", { name: "Refresh from guest", exact: true }).click();
    const logViewer = page.locator(".logs-panel .log-viewer");
    await expect(logViewer).toContainText(markers.edited!, { timeout: 90_000 });
    await expect(logViewer).toContainText(markers.disabled!);
    await expect(logViewer).toContainText(markers.repeater!);
    await expect(logViewer).toContainText(markers.recovery!);
    await expect(logViewer).toContainText(markers.targetRecovery!);
    const finalLogs = await logViewer.innerText();
    expect(finalLogs).toContain(markers.edited);
    expect(finalLogs).not.toContain(markers.original);
    expect(finalLogs).toContain(markers.disabled);
    expect(finalLogs).toContain(markers.repeater);
    expect(finalLogs).toContain(markers.recovery);
    expect(finalLogs).toContain(markers.targetRecovery);
    extraArtifacts.set("final-target-apache-access.log", finalLogs);
    await testInfo.attach("final-target-apache-access.log", { body: finalLogs, contentType: "text/plain" });

    browserCheckReached = true;
    expect(pageErrors).toEqual([]);
  } catch (error) {
    harnessError = error instanceof Error ? error.message : String(error);
    throw error;
  } finally {
    if (!report) {
      try { report = await readReport(); } catch { /* The UI may not have reached the acceptance panel. */ }
    }
    const gates: ProxyAcceptanceGate[] = report?.gates.map((gate) => ({ ...gate })) ?? GATE_IDS.map((id) => ({
      id,
      label: id,
      status: "BLOCKED",
      detail: harnessError ?? "The real proxy acceptance panel was not reached",
    }));
    const browserStatus = pageErrors.length ? "FAIL" : browserCheckReached ? "PASS" : "BLOCKED";
    const summary = {
      schema: 1,
      test: testInfo.title,
      runId: report?.runId ?? null,
      controllerStatus: report?.status ?? "BLOCKED",
      statuses: {
        ...Object.fromEntries(gates.map((gate) => [gate.id, gate.status])),
        "browser-errors": browserStatus,
        "parent-navigation-during-errors": navigationDuringErrors ? "PASS" : "BLOCKED",
      },
      gates: [...gates, {
        id: "browser-errors",
        label: "No uncaught parent browser errors",
        status: browserStatus,
        detail: pageErrors.length ? pageErrors.join(" | ") : browserCheckReached ? "No uncaught browser errors" : "Final browser-error check was not reached",
      }],
      markers: report?.markers ?? {},
      artifacts: [...Object.keys(report?.artifacts ?? {}), ...extraArtifacts.keys()],
      navigationDuringErrors,
      pageErrors,
      harnessError,
      limitations: [
        "Connectivity and proxy acceptance do not establish CVE reproduction, RCE, a target shell, flag retrieval, or snapshot restoration.",
        "Repeater demonstrates GET-based proxy traffic and an edited harmless POST health request; arbitrary methods and body editing are not claimed.",
      ],
    };
    const outputPath = testInfo.outputPath("proxy-acceptance.json");
    await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
    await testInfo.attach("proxy-acceptance.json", { path: outputPath, contentType: "application/json" });
  }
});
