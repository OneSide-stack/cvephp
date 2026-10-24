import { expect, test, type Page } from "@playwright/test";

/**
 * Guest-backed acceptance for the practical exercise.
 *
 * Every assertion below depends on output produced by the real v86 guests. The
 * test deliberately asserts that genuine exploitation is NOT awarded, because
 * no verified control-flow profile for this 32-bit Alpine/musl build exists.
 */

async function openLab(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Start lab", exact: true }).first().click();
  await page.waitForFunction(() => {
    const status = document.querySelector(".brand-right .status-pill")?.textContent?.trim();
    return status === "Ready" || status === "Failed";
  }, undefined, { timeout: 15 * 60 * 1000 });
  const status = (await page.locator(".brand-right .status-pill").textContent())?.trim();
  if (status !== "Ready") {
    throw new Error((await page.getByRole("alert").textContent())?.trim() || `Lab status: ${status}`);
  }
  await page.getByRole("button", { name: "VULNERABILITY LAB", exact: true }).click();
  await expect(page.getByRole("heading", { name: "CVE-2026-109618 · practical exercise" })).toBeVisible();
}

function step(page: Page, title: string) {
  return page.locator(".lab-step", { has: page.getByRole("heading", { name: title, exact: true }) });
}

async function runAction(page: Page, stepTitle: string, action: string) {
  const row = step(page, stepTitle);
  const button = row.getByRole("button", { name: new RegExp(action) }).first();
  await expect(button).toBeEnabled({ timeout: 60_000 });
  await button.click();
}

async function expectVerified(page: Page, stepTitle: string, timeout = 8 * 60 * 1000) {
  const row = step(page, stepTitle);
  await expect(row.locator(".status-pill")).toContainText("Verified", { timeout });
  // A verified step must carry an observed detail, not a placeholder.
  await expect(row.locator(".lab-step-detail strong")).toHaveText("Observed");
}

test("practical lab workflow is guest-backed, gated, resettable and honest about RCE", async ({ page }) => {
  test.setTimeout(40 * 60 * 1000);
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await openLab(page);

  // The plaintext flag must never be present in page data.
  expect(await page.content()).not.toMatch(/RANGE\{[0-9a-f]{48}\}/);
  await expect(page.locator(".lab-step", { hasText: "Reconnaissance" }).locator(".status-pill")).toContainText("Ready to run");

  // 1. Reconnaissance — real target configuration.
  await runAction(page, "Reconnaissance", "Inspect the target");
  await expectVerified(page, "Reconnaissance");
  await expect(page.locator(".lab-side")).toContainText("apache2handler");
  await expect(page.locator(".lab-side")).toContainText("vulnerable-build");
  const buildFacts = await page.locator(".lab-side").innerText();
  expect(buildFacts).toMatch(/memory_limit\s*128M/);
  expect(buildFacts).toMatch(/memory_hard_limit_percent\s*absent/);
  expect(buildFacts).toMatch(/HTTP 403/);
  expect(buildFacts).not.toContain("patched-build");

  const digestBefore = (await page.locator(".key-value", { hasText: "Flag SHA-256" }).locator("strong").innerText()).trim();
  expect(digestBefore.length).toBeGreaterThan(8);

  // 2. Baseline — three exchanges corroborated by the target access log.
  await runAction(page, "Baseline testing", "Send baseline requests");
  await expectVerified(page, "Baseline testing");
  await expect(step(page, "Baseline testing")).toContainText("corroborated in the target access log");

  // 3. Request analysis — real proxy forward and a modified POST.
  await runAction(page, "Request analysis", "Analyse through RangeProxy");
  await expectVerified(page, "Request analysis");
  await expect(step(page, "Request analysis")).toContainText("Proxy sequence");

  // 4. Investigation — classification from observed version and patch marker.
  await runAction(page, "Vulnerability investigation", "Classify this build");
  await expectVerified(page, "Vulnerability investigation");
  const investigation = await step(page, "Vulnerability investigation").innerText();
  expect(investigation).toContain("vulnerable-build");
  expect(investigation).toContain("memory_hard_limit_percent");

  // 5. Controlled reproduction — one bounded 4 MiB probe with target logs.
  await step(page, "Controlled reproduction").getByRole("button", { name: "4 MiB", exact: true }).click();
  await runAction(page, "Controlled reproduction", "Send 4 MiB probe");
  await expectVerified(page, "Controlled reproduction", 12 * 60 * 1000);
  const probe = page.locator(".probe-outcome");
  await expect(probe).toBeVisible();
  await expect(probe).toContainText(/oom-observed|parser-cap-observed|no-target-effect|transport-error/);
  const probeText = await page.locator(".probe-summary").innerText();
  expect(probeText).not.toMatch(/\bRCE (succeeded|achieved)\b/i);
  expect(probeText).toContain("Workers before");

  // 6. Target-side verification — independent guest state and an honest verdict.
  await runAction(page, "Target-side verification", "Verify target-side state");
  await expectVerified(page, "Target-side verification");
  await expect(page.locator(".verification-grid")).toContainText("No Apache-owned challenge proof exists for this session.");
  await expect(page.locator(".verification-grid")).toContainText("absent");

  // 7. Remediation — verified advisory comparison and its explicit limitation.
  await runAction(page, "Remediation", "Compare builds");
  await expectVerified(page, "Remediation");
  await expect(page.locator(".remediation-grid")).toContainText("8.2.35");
  await expect(page.locator(".remediation-grid")).toContainText("not a fix");

  // 8. Completion stays unavailable: no fabricated success, no shell.
  const completion = step(page, "Completion");
  await expect(completion.locator(".status-pill")).toContainText("Genuine path unavailable");
  await expect(page.locator(".completion-card")).toHaveCount(0);
  await expect(page.locator(".blocker-strip")).toContainText("Genuine RCE completion is unavailable");

  // Simulation is explicitly separate and answered from observed values.
  await expect(page.locator(".simulation-banner")).toContainText("performs no target-side effect");
  const sapiQuestion = page.locator(".simulation-question", { hasText: "request-handling mode" });
  await sapiQuestion.getByRole("button", { name: "apache2handler", exact: true }).click();
  const observedLimit = (await page.locator(".key-value", { hasText: "memory_limit" }).locator("strong").first().innerText()).trim();
  const limitQuestion = page.locator(".simulation-question", { hasText: "predictable per-request ceiling" });
  await limitQuestion.getByRole("button", { name: observedLimit, exact: true }).click();
  const markerQuestion = page.locator(".simulation-question", { hasText: "allocator patch marker" });
  await markerQuestion.getByRole("button", { name: "memory_hard_limit_percent", exact: true }).click();
  await expect(page.locator(".simulation-complete")).toContainText("simulation only");
  await expect(completion.locator(".status-pill")).toContainText("Genuine path unavailable");
  await expect(page.getByText("Simulation only")).toBeVisible();

  // Reset is a real target cold boot with a newly generated session flag.
  page.once("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Reset exercise", exact: true }).click();
  await page.waitForFunction(() => document.querySelector(".brand-right .status-pill")?.textContent?.trim() === "Ready", undefined, { timeout: 15 * 60 * 1000 });
  await expect(page.locator(".lab-step.passed")).toHaveCount(0);
  await expect(step(page, "Reconnaissance").locator(".status-pill")).toContainText("Ready to run");
  await expect(page.getByText("Simulation only")).toHaveCount(0);
  const digestAfter = (await page.locator(".key-value", { hasText: "Flag SHA-256" }).locator("strong").innerText()).trim();
  expect(digestAfter).not.toBe(digestBefore);
  await expect(page.locator(".target-identity")).toContainText("Alpine");

  expect(pageErrors).toEqual([]);
});
