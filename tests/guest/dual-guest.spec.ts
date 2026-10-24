import { expect, test } from "@playwright/test";
import { writeFile } from "node:fs/promises";

type GateId = "assets" | "boot" | "network" | "http" | "telemetry" | "browser";
type GateStatus = "PENDING" | "PASS" | "FAIL" | "BLOCKED";
interface GateResult {
  id: GateId;
  status: GateStatus;
  detail: string;
}

const gateNames: Record<GateId, string> = {
  assets: "Checksummed attacker and target ISO artifacts",
  boot: "Both real v86 guests boot to a usable graphical environment",
  network: "Static addresses, NICs, guest connectivity, listener, and isolated inbrowser transport",
  http: "Attacker-to-target root HTTP response and unique Apache access-log marker",
  telemetry: "Target Apache, PHP configuration, memory, processes, and guest logs",
  browser: "No uncaught browser runtime errors",
};

test("real dual guests provide isolated network, HTTP, and target telemetry", async ({ page }, testInfo) => {
  test.setTimeout(20 * 60 * 1000);
  const results = new Map<GateId, GateResult>((Object.keys(gateNames) as GateId[]).map((id) => [id, {
    id,
    status: "PENDING",
    detail: "Not reached",
  }]));
  const record = (id: GateId, status: GateStatus, detail: string) => {
    results.set(id, { id, status, detail });
    console.log(`ACCEPTANCE ${status} ${id}: ${detail}`);
  };
  const gate = async (id: GateId, action: () => Promise<string>) => {
    try {
      const detail = await test.step(gateNames[id], action);
      record(id, "PASS", detail);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      record(id, "FAIL", detail);
      throw error;
    }
  };

  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.goto("/");

  try {
    await gate("assets", async () => {
      await expect(page.locator(".preflight-list")).toContainText("Attacker ISO");
      await expect(page.locator(".preflight-list")).toContainText("Target ISO");
      await expect(page.locator(".preflight-list .text-success")).toHaveCount(3);
      await expect(page.getByRole("button", { name: "Start lab", exact: true }).first()).toBeEnabled();
      return "The checksummed manifest supplied both guest ISOs and pinned v86/firmware; the real start control was enabled.";
    });

    await gate("boot", async () => {
      await page.getByRole("button", { name: "Start lab", exact: true }).first().click();
      const labStatus = page.locator(".brand-right .status-pill");
      await page.waitForFunction(() => {
        const status = document.querySelector(".brand-right .status-pill")?.textContent?.trim();
        return status === "Ready" || status === "Failed";
      }, undefined, { timeout: 15 * 60 * 1000 });
      if ((await labStatus.textContent())?.trim() !== "Ready") {
        throw new Error((await page.getByRole("alert").textContent())?.trim() || "Lab startup failed");
      }
      await expect(labStatus).toHaveText("Ready");
      await expect(page.locator("#vm-attacker .vm-statusbar .status-pill")).toHaveText("Ready");
      await expect(page.locator("#vm-target .vm-statusbar .status-pill")).toHaveText("Ready");
      await page.locator("#vm-attacker").getByRole("button", { name: "Display", exact: true }).click();
      await expect(page.locator("#vm-attacker canvas")).toBeVisible();
      await expect(page.locator(".tool-tags")).toContainText("curl");
      await expect(page.locator(".tool-tags")).toContainText("dillo-beta");
      await page.getByRole("button", { name: "TARGET SERVER HOUSING", exact: true }).click();
      await expect(page.locator(".target-identity")).toContainText("NE2000 · inbrowser");
      await expect(page.locator(".target-identity")).toContainText("Alpine");
      await expect(page.locator("#vm-target canvas:visible, #vm-target .v86-screen > div:visible").first()).toBeVisible();
      return "Both checksummed images booted to Ready in v86; attacker X/tools and the target Alpine display were present.";
    });

    await gate("network", async () => {
      await page.getByRole("button", { name: "NETWORK TOPOLOGY", exact: true }).click();
      await expect(page.getByText("Network acceptance checks · 8/8", { exact: true })).toBeVisible();
      await expect(page.getByText("Every check passed against the current running guests.", { exact: false })).toBeVisible();
      await expect(page.locator(".verification-list .verification-row")).toHaveCount(8);
      await expect(page.locator(".verification-list .verification-row.passed")).toHaveCount(8);
      await expect(page.locator(".verification-list")).toContainText("192.168.10.10/24");
      await expect(page.locator(".verification-list")).toContainText("192.168.10.55/24");
      await expect(page.locator(".verification-list")).toContainText("no default guest route");
      await expect(page.locator(".verification-list")).toContainText(/HTTP\/1\.[01] 200/);
      return "8/8 guest-side checks passed: both /24 addresses, ICMP, TCP :80 listener, HTTP 200, headers, target log, and no default route on the shared pinned-v86 inbrowser network.";
    });

    await gate("http", async () => {
      await page.getByRole("button", { name: "ATTACKER WORKSTATION", exact: true }).click();
      await page.getByRole("button", { name: "Run guest baseline request", exact: true }).click();
      await expect(page.locator(".global-message")).toContainText(/Baseline learner-[0-9a-f]{12} captured/, { timeout: 90_000 });
      const notice = await page.locator(".global-message").innerText();
      const marker = notice.match(/learner-[0-9a-f]{12}/)?.[0];
      expect(marker, "The real baseline must expose its randomized request marker").toBeTruthy();

      await page.getByRole("button", { name: "TARGET SERVER HOUSING", exact: true }).click();
      await expect(page.locator(".logs-panel")).toContainText(marker!, { timeout: 60_000 });
      const accessLog = await page.locator(".logs-panel .log-viewer").innerText();
      expect(accessLog).toContain(`GET /?evidence=${marker} HTTP/`);
      expect(accessLog).toContain(" 200 ");
      await testInfo.attach("target-apache-access.log", { body: accessLog, contentType: "text/plain" });

      await page.getByRole("button", { name: /^EVIDENCE & REPORT/ }).click();
      const responseRecord = page.locator(".evidence-record").filter({ hasText: "Learner baseline request" }).first();
      await responseRecord.locator("summary").click();
      const response = await responseRecord.locator(".evidence-data pre").innerText();
      expect(response).toMatch(/HTTP\/1\.[01] 200/);
      expect(response).toMatch(/Content-Type: text\/html/i);
      expect(response).toContain("<title>Assessment Portal</title>");
      await testInfo.attach("attacker-to-target-http-response.txt", { body: response, contentType: "text/plain" });
      return `${marker}: the attacker guest received the real root response (status, headers, and Assessment Portal body), and the target's own Apache log recorded the same GET with HTTP 200.`;
    });

    await gate("telemetry", async () => {
      await page.getByRole("button", { name: "TARGET SERVER HOUSING", exact: true }).click();
      await page.getByRole("button", { name: "Refresh from guest", exact: true }).click();
      await expect(page.locator(".global-message")).toContainText("Target status, PHP health, process memory, and all three log files were refreshed from the guest.", { timeout: 90_000 });
      await expect(page.locator(".target-identity")).toContainText("192.168.10.55/24");
      await expect(page.locator(".target-identity")).toContainText("8.2.34");
      await expect(page.locator(".target-identity")).toContainText("apache2handler");
      await expect(page.locator(".target-identity")).toContainText("running");
      await expect(page.locator(".telemetry-grid")).toContainText("128.0 MiB");
      await expect(page.locator(".telemetry-grid")).toContainText("128M");
      await expect(page.locator(".telemetry-grid")).toContainText("134,217,728 bytes");
      await expect(page.locator(".telemetry-grid")).toContainText("httpd processes · running");
      await expect(page.locator(".telemetry-grid")).not.toContainText("not collected");
      await expect(page.locator(".target-detail-grid")).toContainText("memory_limit");
      await expect(page.locator(".target-detail-grid")).toContainText("128M");
      await expect(page.locator(".logs-panel")).toContainText("/var/log/apache2/access.log");
      const telemetry = await page.locator(".target-view").innerText();
      await testInfo.attach("target-guest-telemetry.txt", { body: telemetry, contentType: "text/plain" });
      return "Fresh target-guest data confirmed Apache/mod_php running, PHP memory_limit=128M (distinct from VM and RSS memory), live process/RSS measurements, and readable guest logs.";
    });

    await gate("browser", async () => {
      expect(pageErrors).toEqual([]);
      return "No uncaught browser runtime errors were observed during the real-guest acceptance run.";
    });
  } finally {
    for (const [id, result] of results) {
      if (result.status === "PENDING") record(id, "BLOCKED", "Not reached because an earlier gate failed or the bounded test timed out.");
    }
    const summary = {
      schema: 1,
      test: testInfo.title,
      statuses: Object.fromEntries([...results].map(([id, result]) => [id, result.status])),
      gates: [...results.values()],
      pageErrors,
    };
    const outputPath = testInfo.outputPath("dual-guest-acceptance.json");
    await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
    await testInfo.attach("dual-guest-acceptance.json", { path: outputPath, contentType: "application/json" });
  }
});
