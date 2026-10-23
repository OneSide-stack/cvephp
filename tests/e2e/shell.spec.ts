import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

test("all views remain mounted and only genuine guest state is shown", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Your foothold in the range" })).toBeVisible();
  await expect(page.locator("#vm-attacker .v86-screen")).toBeAttached();
  await expect(page.locator("#vm-target .v86-screen")).toBeAttached();
  await expect(page.locator("#vm-attacker canvas")).toBeHidden();

  for (const [name, heading] of [
    ["TARGET SERVER HOUSING", "Assessment target internals"],
    ["NETWORK TOPOLOGY", "One private Ethernet segment"],
    ["LAB GUIDE", "Operation PHP2Shell"],
    ["EVIDENCE & REPORT", "Observations, not assertions"],
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

test("resource mode and report export are honest before a session", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: /Lower resource/ }).click();
  await expect(page.getByText("640 MiB guest RAM")).toBeVisible();
  await page.getByRole("button", { name: "EVIDENCE & REPORT", exact: true }).click();
  await expect(page.getByText("Incomplete", { exact: true })).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export report", exact: true }).click();
  const download = await downloadPromise;
  const content = await readFile((await download.path())!, "utf8");
  expect(content).toContain("Incomplete / genuine RCE not verified");
  expect(content).toContain("No active session");
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
