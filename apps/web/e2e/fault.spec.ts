/**
 * Fault injection for key changes (R-REC-3, roadmap P5: there is never a moment when neither
 * the old nor the new Recovery Key works). The test cuts the Recovery Key replacement request
 * at three points, then proves with a fresh browser which key is live:
 *   A. dropped before the server: an error; nothing changed (original key still live);
 *   B. applied, then the response and the confirming re-read are lost: the new key is shown with
 *      a "keep both" warning (it is live);
 *   C. applied, then only the response is lost: the re-read confirms it, and the new key is shown
 *      without a warning (it is live).
 * Values are test-only.
 */
import { expect, test, type BrowserContext, type Page } from "@playwright/test";

const PASSWORD = "test-only fault injection password";

async function createAccount(page: Page, email: string): Promise<string> {
  await page.goto("/");
  await page.getByRole("button", { name: "Create a new vault" }).click();
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Repeat master password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create vault" }).click();
  const rk = (await page.getByTestId("kit-recovery-key").textContent()) ?? "";
  await page.getByLabel(/last 4 characters/).fill(rk.replace(/-/g, "").slice(-4));
  await page.getByRole("button", { name: "Open my vault" }).click();
  await expect(page.getByText("Your vault is empty")).toBeVisible();
  return rk;
}

async function replaceRecoveryKey(page: Page) {
  await page.getByRole("button", { name: "Replace Recovery Key" }).click();
  await page.getByRole("button", { name: "Continue" }).click();
}

/** Returns the Recovery Key shown, after closing the kit. */
async function readKit(page: Page): Promise<string> {
  const rk = (await page.getByTestId("kit-recovery-key").textContent()) ?? "";
  expect(rk).toMatch(/^UKR1-/);
  await page.getByLabel(/last 4 characters/).fill(rk.replace(/-/g, "").slice(-4));
  await page.getByRole("button", { name: "Done" }).click();
  return rk;
}

async function tryRecovery(context: BrowserContext, email: string, rk: string): Promise<boolean> {
  const page = await context.newPage();
  await page.goto("/");
  await page.getByRole("button", { name: "Use a Recovery Key" }).click();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Recovery Key").fill(rk);
  await page.getByRole("button", { name: "Continue" }).click();
  const next = page.getByLabel("New master password", { exact: true });
  const refused = page.getByRole("alert");
  await expect(next.or(refused)).toBeVisible();
  const ok = await next.isVisible();
  await page.close();
  return ok;
}

test("a Recovery Key replacement cut mid-way never leaves no working key (R-REC-3)", async ({ browser }) => {
  const email = `fault-${String(Date.now())}@example.test`;
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const rk0 = await createAccount(page, email);
  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByRole("tab", { name: "Security" }).click();
  const recoveryKeyRoute = "**/v1/account/recovery-key";

  // A. Dropped before it reaches the server.
  await ctx.route(recoveryKeyRoute, (route) => route.abort("connectionreset"));
  await replaceRecoveryKey(page);
  await expect(page.getByText(/Can't reach the server/)).toBeVisible({ timeout: 15_000 });
  await page.getByRole("button", { name: "Cancel" }).click();
  await ctx.unroute(recoveryKeyRoute);

  // B. Applied by the server; the response and the confirming re-read are both lost.
  await ctx.route(recoveryKeyRoute, async (route) => {
    await route.fetch(); // the server applies the change
    await route.abort("connectionreset"); // ...but the response never arrives
  });
  await ctx.route("**/v1/account", (route) => route.abort("connectionreset"));
  await replaceRecoveryKey(page);
  await expect(page.getByText(/couldn.t reach the server to confirm/)).toBeVisible({ timeout: 15_000 });
  const rk1 = await readKit(page);
  await ctx.unroute(recoveryKeyRoute);
  await ctx.unroute("**/v1/account");

  // C. Applied; only the response is lost. The re-read confirms it.
  await ctx.route(recoveryKeyRoute, async (route) => {
    await route.fetch();
    await route.abort("connectionreset");
  });
  await replaceRecoveryKey(page);
  await expect(page.getByTestId("kit-recovery-key")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(/couldn.t reach the server to confirm/)).toHaveCount(0);
  const rk2 = await readKit(page);
  await ctx.unroute(recoveryKeyRoute);

  // Which key is live? A fresh browser tries each one. Exactly the last applied key works.
  const other = await browser.newContext();
  expect(await tryRecovery(other, email, rk0), "original key after replacement").toBe(false);
  expect(await tryRecovery(other, email, rk1), "key from B, superseded by C").toBe(false);
  expect(await tryRecovery(other, email, rk2), "key from C").toBe(true);
  await other.close();
  await ctx.close();
});
