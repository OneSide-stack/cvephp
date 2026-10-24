import { expect, test } from "@playwright/test";

test("all views remain mounted and only genuine guest state is shown", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Your foothold in the range" })).toBeVisible();
  await expect(page.locator("#vm-attacker .v86-screen")).toBeAttached();
  await expect(page.locator("#vm-target .v86-screen")).toBeAttached();
  await expect(page.locator("#vm-attacker canvas")).toBeHidden();

  for (const [name, heading] of [
    ["TARGET SERVER HOUSING", "Assessment target internals"],
    ["NETWORK TOPOLOGY", "One private Ethernet segment"],
    ["VULNERABILITY LAB", "CVE-2026-109618 · practical exercise"],
    ["LAB GUIDE", "Operation PHP2Shell"],
  ] as const) {
    await page.getByRole("button", { name, exact: true }).click();
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
    await expect(page.locator("#vm-attacker .v86-screen")).toBeAttached();
  }
});

test("missing pinned images fail visibly without a fake VM", async ({ page }) => {
  await page.goto("/");
  await page.locator(".control-deck").getByRole("button", { name: "Start lab", exact: true }).click();
  await expect(page.locator(".inline-message.error")).toContainText(/image is missing|not provisioned|could not be loaded/i);
  await expect(page.locator(".brand-right .status-pill")).toContainText("Failed");
  await expect(page.locator("#vm-attacker canvas")).toBeHidden();
  await expect(page.locator("#vm-target canvas")).toBeHidden();
  await expect(page.getByRole("button", { name: "Reset lab", exact: true })).toBeEnabled();
});

test("the lab is honest before a session and has no reporting surface", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Lower resource/ }).click();
  await expect(page.getByText("640 MiB guest RAM")).toBeVisible();
  await page.getByRole("button", { name: "VULNERABILITY LAB", exact: true }).click();

  await expect(page.getByRole("heading", { name: "CVE-2026-109618 · practical exercise" })).toBeVisible();
  await expect(page.getByText("Verified advisory, honest reproduction status")).toBeVisible();
  await expect(page.getByText(/Genuine exploitation of this 32-bit Alpine\/musl mod_php build is not verified/)).toBeVisible();
  await expect(page.getByText("GHSA-w8hw-w9fx-j79w")).toBeVisible();

  // No reporting/export navigation or controls remain.
  await expect(page.getByRole("button", { name: /EVIDENCE & REPORT|Export report|Download report/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /export|download/i })).toHaveCount(0);

  // Gated: nothing is awarded and the flag form cannot be used without a session.
  await expect(page.getByText("Locked").first()).toBeVisible();
  await expect(page.getByText("Not awarded")).toBeVisible();
  await expect(page.getByRole("button", { name: "Validate flag", exact: true })).toBeDisabled();
  await expect(page.getByText("Genuine RCE completion is unavailable")).toHaveCount(0);
});

test("narrow layouts retain parent VM controls and instructions", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Start lab", exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Reset lab", exact: true })).toBeAttached();
  await expect(page.getByRole("button", { name: "Stop both machines", exact: true })).toBeAttached();
  await page.getByRole("button", { name: "Lab instructions", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Operation PHP2Shell" })).toBeVisible();
});
