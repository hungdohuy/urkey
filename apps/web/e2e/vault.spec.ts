/**
 * Browser end-to-end tests (roadmap P2–P5): real WASM core in a Web Worker, WebCrypto device
 * keys, IndexedDB, and the real API on cf dev. Each browser context is a separate device.
 */
import AxeBuilder from "@axe-core/playwright";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test, type Browser, type Page } from "@playwright/test";

const PASSWORD = "test-only e2e master password";
const NEW_PASSWORD = "test-only rotated master password";
const email = `web-${String(Date.now())}@example.test`;
let secretKey = "";
let recoveryKey = "";

async function newDevice(browser: Browser): Promise<Page> {
  const ctx = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"] });
  const page = await ctx.newPage();
  await page.goto("/");
  return page;
}

async function unlock(page: Page, password: string) {
  await page.getByLabel("Master password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("navigation", { name: "Vault" })).toBeVisible();
}

async function syncNow(page: Page) {
  await page.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByRole("status").filter({ hasText: /^Synced$/ })).toBeVisible();
}

test.describe.serial("urkey in the browser", () => {
  let device1: Page;

  test("create an account and confirm the Emergency Kit", async ({ browser }) => {
    device1 = await newDevice(browser);
    await device1.getByRole("button", { name: "Create a new vault" }).click();
    await device1.getByLabel("Email").fill(email);
    await device1.getByRole("button", { name: "Continue" }).click();
    await device1.getByLabel("Master password", { exact: true }).fill(PASSWORD);
    await device1.getByLabel("Repeat master password").fill(PASSWORD);
    await device1.getByRole("button", { name: "Create vault" }).click();
    await expect(device1.getByRole("region", { name: "Emergency Kit" })).toBeVisible();
    secretKey = (await device1.getByTestId("kit-secret-key").textContent()) ?? "";
    recoveryKey = (await device1.getByTestId("kit-recovery-key").textContent()) ?? "";
    expect(secretKey).toMatch(/^UK1-/);
    expect(recoveryKey).toMatch(/^UKR1-/);
    await device1.getByLabel(/last 4 characters/).fill(recoveryKey.replace(/-/g, "").slice(-4));
    await device1.getByRole("button", { name: "Open my vault" }).click();
    await expect(device1.getByText("Your vault is empty")).toBeVisible();
    const axe = await new AxeBuilder({ page: device1 }).analyze();
    expect(axe.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
  });

  test("add a login with a generated password and a one-time code", async () => {
    await device1.getByRole("button", { name: "Add a login" }).click();
    await device1.getByLabel("Title").fill("Example site");
    await device1.getByLabel("Username").fill("alice");
    await device1.getByRole("button", { name: "Generate a password" }).click();
    await device1.getByRole("button", { name: "Use" }).click();
    await device1.getByLabel("Paste an otpauth:// link or the secret").fill("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example");
    await device1.getByRole("button", { name: "Add", exact: true }).click();
    await device1.getByRole("button", { name: "Save" }).click();
    await expect(device1.getByRole("heading", { name: "Example site" })).toBeVisible();
    await expect(device1.getByLabel("Password, hidden")).toHaveText("••••••••");
    await expect(device1.getByTestId("totp-code")).toHaveText(/^\d{3} \d{3}$/);
    // Nothing secret in the DOM until revealed.
    expect(await device1.content()).not.toContain("JBSWY3DPEHPK3PXP");
    await device1.getByRole("button", { name: "Reveal password" }).click();
    await expect(device1.getByLabel("Password, hidden")).toHaveCount(0);
    await syncNow(device1);
    const axe = await new AxeBuilder({ page: device1 }).analyze();
    expect(axe.violations.filter((v) => v.impact === "serious" || v.impact === "critical")).toEqual([]);
  });

  test("storage contains no plaintext", async () => {
    const dump = await device1.evaluate(async () => {
      const db = await new Promise<IDBDatabase>((res, rej) => {
        const r = indexedDB.open("urkey");
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(new Error("idb"));
      });
      const all = await new Promise<unknown[]>((res) => {
        const req = db.transaction("kv").objectStore("kv").getAll();
        req.onsuccess = () => res(req.result as unknown[]);
      });
      return JSON.stringify(all, (_k, v: unknown) => (v instanceof Uint8Array ? Array.from(v) : v));
    });
    for (const secret of ["Example site", "alice", "JBSWY3DPEHPK3PXP", PASSWORD]) expect(dump).not.toContain(secret);
  });

  test("lock and unlock; a wrong password gets one generic message", async () => {
    await device1.keyboard.press("Shift+L");
    await expect(device1.getByRole("heading", { name: "Your vault is locked" })).toBeVisible();
    await device1.getByLabel("Master password", { exact: true }).fill("wrong password");
    await device1.getByRole("button", { name: "Unlock" }).click();
    await expect(device1.getByRole("alert")).toHaveText(/Couldn't unlock/);
    await unlock(device1, PASSWORD);
    await expect(device1.getByRole("option", { name: /Example site/ })).toBeVisible();
  });

  test("a second device signs in with the Secret Key and syncs both ways", async ({ browser }) => {
    const device2 = await newDevice(browser);
    await device2.getByRole("button", { name: "Sign in on this device" }).click();
    await device2.getByLabel("Email").fill(email);
    await device2.getByLabel("Secret Key").fill(secretKey);
    await device2.getByLabel("Master password", { exact: true }).fill(PASSWORD);
    await device2.getByLabel("Device name").fill("Second browser");
    await device2.getByRole("button", { name: "Sign in" }).click();
    await expect(device2.getByRole("option", { name: /Example site/ })).toBeVisible();
    // Edit on device 2, see it on device 1.
    await device2.getByRole("option", { name: /Example site/ }).click();
    await device2.getByRole("button", { name: "Edit" }).click();
    await device2.getByLabel("Username").fill("alice-renamed");
    await device2.getByRole("button", { name: "Save" }).click();
    await syncNow(device2);
    await syncNow(device1);
    await expect(device1.getByRole("option", { name: /alice-renamed/ })).toBeVisible();
    // Device 1 sees the new-device notice.
    await expect(device1.getByText("Security activity on your account.")).toBeVisible();
    await device2.context().close();
  });

  test("the native CLI reads what the web app wrote (Rust ↔ WASM interop)", () => {
    const urk = join(process.cwd(), "../../target/debug/urk");
    test.skip(!existsSync(urk), "urk not built");
    const home = mkdtempSync(join(tmpdir(), "urk-web-e2e-"));
    const env = { ...process.env, URKEY_HOME: home };
    execFileSync(urk, ["init", "--server", "http://localhost:8787", "--name", "CLI"], { env });
    execFileSync(urk, ["login", "--email", email, "--password-stdin"], { env, input: `${PASSWORD}\n${secretKey}\n` });
    const user = execFileSync(urk, ["item", "get", "Example", "--field", "username", "--password-stdin"], { env, input: `${PASSWORD}\n` }).toString().trim();
    expect(user).toBe("alice-renamed");
  });

  test("change the master password", async () => {
    await device1.getByRole("button", { name: "Settings" }).click();
    await device1.getByRole("button", { name: "Change master password" }).click();
    await device1.getByLabel("New master password", { exact: true }).fill(NEW_PASSWORD);
    await device1.getByLabel("Repeat it").fill(NEW_PASSWORD);
    await device1.getByRole("button", { name: "Continue" }).click();
    await expect(device1.getByText(/Master password changed/)).toBeVisible();
    await device1.keyboard.press("Shift+L");
    await device1.getByLabel("Master password", { exact: true }).fill(PASSWORD);
    await device1.getByRole("button", { name: "Unlock" }).click();
    await expect(device1.getByRole("alert")).toHaveText(/Couldn't unlock/);
    await unlock(device1, NEW_PASSWORD);
  });

  test("change the vault key: items stay readable", async () => {
    await device1.getByRole("button", { name: "Settings" }).click();
    await device1.getByRole("button", { name: "Change vault key" }).click();
    await device1.getByLabel("Master password", { exact: true }).fill(NEW_PASSWORD);
    await device1.getByRole("button", { name: "Continue" }).click();
    await expect(device1.getByTestId("kit-recovery-key")).toBeVisible();
    recoveryKey = (await device1.getByTestId("kit-recovery-key").textContent()) ?? "";
    await device1.getByLabel(/last 4 characters/).fill(recoveryKey.replace(/-/g, "").slice(-4));
    await device1.getByRole("button", { name: "Done" }).click();
    await device1.getByRole("button", { name: "All items" }).click();
    await device1.getByRole("option", { name: /Example site/ }).click();
    await expect(device1.getByTestId("totp-code")).toHaveText(/^\d{3} \d{3}$/);
  });

  test("recover with the Recovery Key on a new device; the old device is removed", async ({ browser }) => {
    const device3 = await newDevice(browser);
    await device3.getByRole("button", { name: "Use a Recovery Key" }).click();
    await device3.getByLabel("Email").fill(email);
    await device3.getByLabel("Recovery Key").fill(recoveryKey);
    await device3.getByRole("button", { name: "Continue" }).click();
    await device3.getByLabel("New master password", { exact: true }).fill("test-only recovered password");
    await device3.getByLabel("Repeat it").fill("test-only recovered password");
    await device3.getByRole("button", { name: "Finish recovery" }).click();
    const newRk = (await device3.getByTestId("kit-recovery-key").textContent()) ?? "";
    expect(newRk).not.toBe(recoveryKey);
    await device3.getByLabel(/last 4 characters/).fill(newRk.replace(/-/g, "").slice(-4));
    await device3.getByRole("button", { name: "Open my vault" }).click();
    await expect(device3.getByRole("option", { name: /Example site/ })).toBeVisible();
    // Device 1 learns it was removed on its next request.
    await device1.getByRole("button", { name: "Sync now" }).click();
    await expect(device1.getByRole("heading", { name: "This device was removed from your account" })).toBeVisible();
  });
});

/** Creates an account on a fresh device and returns its Secret Key. */
async function createAccount(page: Page, address: string, password: string): Promise<string> {
  await page.getByRole("button", { name: "Create a new vault" }).click();
  await page.getByLabel("Email").fill(address);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Master password", { exact: true }).fill(password);
  await page.getByLabel("Repeat master password").fill(password);
  await page.getByRole("button", { name: "Create vault" }).click();
  const sk = (await page.getByTestId("kit-secret-key").textContent()) ?? "";
  const rk = (await page.getByTestId("kit-recovery-key").textContent()) ?? "";
  await page.getByLabel(/last 4 characters/).fill(rk.replace(/-/g, "").slice(-4));
  await page.getByRole("button", { name: "Open my vault" }).click();
  await expect(page.getByText("Your vault is empty")).toBeVisible();
  return sk;
}

test("encrypted export restores into a fresh account (roadmap P7, ADR 0017)", async ({ browser }) => {
  const stamp = String(Date.now());
  const source = await newDevice(browser);
  const sourceKey = await createAccount(source, `export-${stamp}@example.test`, PASSWORD);
  await source.getByRole("button", { name: "New item" }).click();
  await source.getByRole("menuitem", { name: "Secure Note" }).click();
  await source.getByRole("textbox", { name: "Title" }).fill("Exported note");
  await source.getByRole("textbox", { name: "Note", exact: true }).fill("survives the round trip");
  await source.getByRole("button", { name: "Save" }).click();
  await expect(source.getByRole("heading", { name: "Exported note" })).toBeVisible();

  await source.getByRole("button", { name: "Settings" }).click();
  await source.getByRole("tab", { name: "Backup" }).click();
  const [download] = await Promise.all([source.waitForEvent("download"), source.getByRole("button", { name: "Export encrypted copy" }).click()]);
  const path = await download.path();
  const json = readFileSync(path, "utf8");
  expect(JSON.parse(json)).toMatchObject({ format: "urkey-export", version: 1 });
  for (const plain of ["Exported note", "survives the round trip"]) expect(json).not.toContain(plain);

  const target = await newDevice(browser);
  await createAccount(target, `restore-${stamp}@example.test`, NEW_PASSWORD);
  await target.getByRole("button", { name: "Settings" }).click();
  await target.getByRole("tab", { name: "Backup" }).click();
  await target.getByLabel("Export file").setInputFiles(path);
  await target.getByLabel("Secret Key of the export").fill(sourceKey);
  await target.getByLabel("Master password of the export", { exact: true }).fill("wrong password");
  await target.getByRole("button", { name: "Restore" }).click();
  await expect(target.getByText(/Couldn't open the export/)).toBeVisible();
  await target.getByLabel("Master password of the export", { exact: true }).fill(PASSWORD);
  await target.getByRole("button", { name: "Restore" }).click();
  await expect(target.getByText("Restored 1 item as new items.")).toBeVisible();
  await target.getByRole("button", { name: /^All items/ }).click();
  await target.getByRole("option", { name: /Exported note/ }).click();
  await expect(target.getByRole("region", { name: "Notes" })).toContainText("survives the round trip");
});
