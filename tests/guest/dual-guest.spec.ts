import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

// This suite is intentionally separate from the missing-image shell tests.
// It must be run against the checksummed CI/local guest artifacts.
test.setTimeout(20 * 60 * 1000);

test("real dual guests provide network, HTTP, telemetry, and proxy evidence", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

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
    throw new Error((await page.getByRole("alert").textContent())?.trim() || "Lab startup failed");
  }
  await expect(labStatus).toHaveText("Ready");
  await expect(page.locator("#vm-attacker .vm-statusbar .status-pill")).toHaveText("Ready");
  await expect(page.locator("#vm-target .vm-statusbar .status-pill")).toHaveText("Ready");
  await page.locator("#vm-attacker").getByRole("button", { name: "Display", exact: true }).click();
  // The attacker must enter real graphical VGA mode.
  await expect(page.locator("#vm-attacker canvas")).toBeVisible();
  await expect(page.locator(".tool-tags")).toContainText("curl");
  await expect(page.locator(".tool-tags")).toContainText("dillo-beta");

  await page.getByRole("button", { name: "NETWORK TOPOLOGY", exact: true }).click();
  await expect(page.getByText("Network acceptance checks · 8/8", { exact: true })).toBeVisible();
  await expect(page.getByText("Every check passed against the current running guests.", { exact: false })).toBeVisible();

  await page.getByRole("button", { name: "ATTACKER WORKSTATION", exact: true }).click();
  await page.getByRole("button", { name: "Run guest baseline request", exact: true }).click();
  await expect(page.locator(".global-message")).toContainText("Baseline response captured from the target", { timeout: 60_000 });

  await page.getByRole("button", { name: "TARGET SERVER HOUSING", exact: true }).click();
  // Alpine has no X requirement; depending on the kernel's VGA mode, v86 may
  // expose its real console through the canvas or the text-screen element.
  const targetVgaOutput = page.locator("#vm-target canvas:visible, #vm-target .v86-screen > div:visible").first();
  await expect(targetVgaOutput).toBeVisible();
  await expect(page.locator(".target-identity")).toContainText("8.2.34");
  await expect(page.locator(".target-identity")).toContainText("Apache");
  await expect(page.locator(".telemetry-grid")) .toContainText("128.0 MiB");
  await expect(page.locator(".logs-panel")).toContainText("evidence=learner-");
  await expect(page.locator(".logs-panel")).toContainText("192.168.10.10");

  // This product action uses the real attacker serial shell to inspect the
  // management state and run guest curl through RangeProxy. It then reads the
  // actual target log; neither Playwright nor React performs the HTTP request.
  await page.getByRole("button", { name: "ATTACKER WORKSTATION", exact: true }).click();
  await page.getByRole("button", { name: "Run guest proxy request", exact: true }).click();
  await expect(page.locator(".global-message")).toContainText(/RangeProxy request proxy-[0-9a-f]+ returned HTTP 200/, { timeout: 120_000 });
  const proxyNotice = await page.locator(".global-message").textContent();
  const proxyMarker = proxyNotice?.match(/proxy-[0-9a-f]{12}/)?.[0];
  if (!proxyMarker) throw new Error(`No guest proxy evidence marker in: ${proxyNotice ?? "empty notice"}`);

  await page.getByRole("button", { name: "TARGET SERVER HOUSING", exact: true }).click();
  await page.getByRole("button", { name: "Refresh from guest", exact: true }).click();
  await expect(page.locator(".logs-panel")).toContainText(proxyMarker, { timeout: 60_000 });

  await page.getByRole("button", { name: "EVIDENCE & REPORT", exact: true }).click();
  await page.getByRole("button", { name: "Sync RangeProxy evidence", exact: true }).click();
  await expect(page.locator(".global-message")).toContainText(/Imported [1-9][0-9]* new guest proxy record/, { timeout: 60_000 });
  await expect(page.locator(".evidence-list")).toContainText("RangeProxy");
  await expect(page.locator(".evidence-list")).toContainText(proxyMarker);

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export report", exact: true }).click();
  const download = await downloadPromise;
  const report = await readFile((await download.path())!, "utf8");
  expect(report).toContain("Incomplete / genuine RCE not verified");
  expect(report).toContain(proxyMarker);
  expect(report).not.toContain("Genuine RCE completion validated");
  expect(pageErrors).toEqual([]);
});
