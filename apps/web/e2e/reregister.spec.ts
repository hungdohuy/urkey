/**
 * Zero-knowledge review N-2 (docs/security/reviews/2026-11-27-zero-knowledge-review.md, sync.md
 * §7.1): after the server was restored from an older backup it does not know a device that
 * joined later. The web app must let that device sign in again WITHOUT losing its local data, and
 * must offer its newer content to the server again.
 *
 * The test makes the local dev server forget the account's device, sessions and items and rolls
 * its sequence counter back, which is what a restore from an earlier backup looks like. It edits
 * the dev server's SQLite database directly, so it only runs in the `dev` project against
 * servers the test suite started itself (not against URKEY_E2E_APP_URL). Test-only values.
 */
import { existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { expect, test, type Browser, type Page } from "@playwright/test";

const PASSWORD = "test-only reregister password";

async function newDevice(browser: Browser): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto("/");
  return page;
}

function openServerDb(repoRoot: string): DatabaseSync {
  const dir = resolve(repoRoot, "cloud/workers/api/.cloudflare/state/v3/d1/miniflare-D1DatabaseObject");
  if (!existsSync(dir)) throw new Error("the dev server's D1 state was not found");
  const file = readdirSync(dir).find((f) => f.endsWith(".sqlite") && f !== "metadata.sqlite");
  if (file === undefined) throw new Error("the dev server's D1 database file was not found");
  return new DatabaseSync(resolve(dir, file));
}

/** What restoring an older backup does to one account: the later device, items and counter are gone. */
function serverRestoredFromOlderBackup(repoRoot: string, email: string): void {
  const db = openServerDb(repoRoot);
  try {
    const row = db.prepare("SELECT account_id FROM accounts WHERE email = ?").get(email) as { account_id: Uint8Array } | undefined;
    if (row === undefined) throw new Error("account not found on the dev server");
    const id = row.account_id;
    db.prepare("DELETE FROM sessions WHERE account_id = ?").run(id);
    db.prepare("DELETE FROM mutations WHERE account_id = ?").run(id);
    db.prepare("DELETE FROM items WHERE account_id = ?").run(id);
    db.prepare("DELETE FROM security_events WHERE account_id = ?").run(id);
    db.prepare("DELETE FROM devices WHERE account_id = ?").run(id);
    db.prepare("UPDATE accounts SET vault_seq = 0 WHERE account_id = ?").run(id);
  } finally {
    db.close();
  }
}

test("a device the restored server does not know signs in again and keeps its data (N-2)", async ({ browser }, testInfo) => {
  test.skip(process.env["URKEY_E2E_APP_URL"] !== undefined, "edits the dev server's database directly");
  const email = `reregister-${String(Date.now())}@example.test`;
  const page = await newDevice(browser);
  await page.getByRole("button", { name: "Create a new vault" }).click();
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Repeat master password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create vault" }).click();
  const secretKey = (await page.getByTestId("kit-secret-key").textContent()) ?? "";
  const recoveryKey = (await page.getByTestId("kit-recovery-key").textContent()) ?? "";
  await page.getByLabel(/last 4 characters/).fill(recoveryKey.replace(/-/g, "").slice(-4));
  await page.getByRole("button", { name: "Open my vault" }).click();
  await page.getByRole("button", { name: "New item" }).click();
  await page.getByRole("menuitem", { name: "Secure Note" }).click();
  await page.getByRole("textbox", { name: "Title" }).fill("Only on this device");
  await page.getByRole("textbox", { name: "Note", exact: true }).fill("kept through the restore");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Only on this device" })).toBeVisible();
  await page.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByRole("status").filter({ hasText: /^Synced$/ })).toBeVisible();

  // The operator restores an older backup: the server no longer knows this device or its note.
  // testDir is apps/web/e2e, so the repository root is three levels up.
  serverRestoredFromOlderBackup(resolve(testInfo.project.testDir, "../../.."), email);

  // The device keeps working locally, and tells the user what is wrong instead of failing silently.
  await page.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByText(/doesn.t recognise this device/)).toBeVisible();
  await expect(page.getByRole("option", { name: /Only on this device/ })).toBeVisible();

  await page.getByRole("button", { name: "Sign this device in again" }).click();
  await expect(page.getByText(/doesn.t recognise this device/)).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: /^Synced$/ })).toBeVisible();
  await expect(page.getByRole("option", { name: /Only on this device/ })).toBeVisible();

  // The server has the note again: a brand-new device sees it exactly once.
  const other = await newDevice(browser);
  await other.getByRole("button", { name: "Sign in on this device" }).click();
  await other.getByLabel("Email").fill(email);
  await other.getByLabel("Secret Key").fill(secretKey);
  await other.getByLabel("Master password", { exact: true }).fill(PASSWORD);
  await other.getByLabel("Device name").fill("Fresh browser");
  await other.getByRole("button", { name: "Sign in" }).click();
  await expect(other.getByRole("option", { name: /Only on this device/ })).toHaveCount(1);
  await other.getByRole("option", { name: /Only on this device/ }).click();
  await expect(other.getByRole("region", { name: "Notes" })).toContainText("kept through the restore");
});
