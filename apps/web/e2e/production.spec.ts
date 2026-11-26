/**
 * Production build on the asset Worker (R-SEC-10, R-SEC-11, R-SEC-12, R-ACC-4): strict CSP with
 * Trusted Types and no violations, release hash shown in About, and the pinned service worker
 * serving the app offline.
 */
import { expect, test } from "@playwright/test";

const PASSWORD = "test-only production e2e password";

test("production build: CSP clean, release pinned, works offline", async ({ browser }) => {
  const context = await browser.newContext();
  await context.addInitScript(() => {
    (window as unknown as { __csp: string[] }).__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      (window as unknown as { __csp: string[] }).__csp.push(`${e.violatedDirective} ${e.blockedURI}`);
    });
  });
  const page = await context.newPage();
  const consoleErrors: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });
  const response = await page.goto("/");
  const csp = response?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("require-trusted-types-for 'script'");

  // Create an account and an item under the production CSP.
  await page.getByRole("button", { name: "Create a new vault" }).click();
  await page.getByLabel("Email").fill(`prod-${String(Date.now())}@example.test`);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Repeat master password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create vault" }).click();
  const rk = (await page.getByTestId("kit-recovery-key").textContent()) ?? "";
  await page.getByLabel(/last 4 characters/).fill(rk.replace(/-/g, "").slice(-4));
  await page.getByRole("button", { name: "Open my vault" }).click();
  await page.getByRole("button", { name: "New item" }).click();
  await page.getByRole("menuitem", { name: "Secure Note" }).click();
  await page.getByRole("textbox", { name: "Title" }).fill("Offline note");
  await page.getByRole("textbox", { name: "Note", exact: true }).fill("readable offline");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Offline note" })).toBeVisible();
  await page.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByRole("status").filter({ hasText: /^Synced$/ })).toBeVisible();

  // The service worker pinned this release; About shows its hash.
  await page.evaluate(async () => navigator.serviceWorker.ready);
  await page.reload();
  await expect.poll(() => page.evaluate(() => navigator.serviceWorker.controller !== null)).toBe(true);
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Unlock" }).click();
  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByRole("tab", { name: "About" }).click();
  const published = (await (await page.request.get("/release.json")).json()) as { hash: string };
  await expect(page.getByTestId("release-hash")).toHaveText(published.hash);

  // Offline: reload from the pinned cache and unlock locally.
  await context.setOffline(true);
  await page.reload();
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Unlock" }).click();
  await page.getByRole("option", { name: /Offline note/ }).click();
  await expect(page.getByText("readable offline")).toBeVisible();
  await context.setOffline(false);

  const violations = await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
  expect(violations).toEqual([]);
  expect(consoleErrors.filter((e) => /Content Security Policy|Trusted Type/i.test(e))).toEqual([]);
});
