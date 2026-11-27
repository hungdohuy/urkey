/**
 * Canary test (R-SEC-1, roadmap P2/P3, threat model T-20, invariant 1). The test plants known
 * secrets and checks they never appear in places where they could leak:
 * - console output, page titles and every URL (navigations and requests);
 * - request bodies (the server must only ever see ciphertext and signatures);
 * - DOM attributes, and the whole DOM once the values are no longer on screen;
 * - localStorage and sessionStorage.
 * All values are test-only.
 */
import { expect, test, type Page, type Request } from "@playwright/test";

const MASTER = "test-only canary master Quokka-7311";
const ITEM_PASSWORD = "test-only-canary-Pw-9q8w7e6r";
const TOTP_SECRET = "KRSXG5CPNZRWC3TBOJ4Q"; // base32 of "TestOnlyCanary"
const NOTE = "test-only canary note Wombat-2468";
const TITLE = "Canary login Echidna";
const USERNAME = "canary-user-numbat";

/** Plain and base64url forms, in case a value is encoded somewhere. */
function forms(secret: string): string[] {
  const b64 = Buffer.from(secret, "utf8").toString("base64url");
  return [secret, b64, encodeURIComponent(secret)];
}

function leaks(haystack: string, secrets: string[]): string[] {
  return secrets.filter((s) => forms(s).some((f) => haystack.includes(f)));
}

test("known secrets never leak to console, URLs, titles, requests, attributes or storage", async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const consoleText: string[] = [];
  const urls: string[] = [];
  const bodies: string[] = [];
  const posted: string[] = [];
  const titles: string[] = [];
  page.on("console", (m) => consoleText.push(m.text()));
  page.on("pageerror", (e) => consoleText.push(String(e)));
  page.on("framenavigated", (f) => urls.push(f.url()));
  context.on("request", (r: Request) => {
    urls.push(r.url());
    const body = r.postData();
    if (body !== null) {
      bodies.push(body);
      posted.push(r.url());
    }
  });
  const snapTitle = async (p: Page) => titles.push(await p.title());

  await page.goto("/");
  await page.getByRole("button", { name: "Create a new vault" }).click();
  await page.getByLabel("Email").fill(`canary-${String(Date.now())}@example.test`);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Master password", { exact: true }).fill(MASTER);
  await page.getByLabel("Repeat master password").fill(MASTER);
  await page.getByRole("button", { name: "Create vault" }).click();
  const secretKey = (await page.getByTestId("kit-secret-key").textContent()) ?? "";
  const recoveryKey = (await page.getByTestId("kit-recovery-key").textContent()) ?? "";
  expect(secretKey).toMatch(/^UK1-/);
  expect(recoveryKey).toMatch(/^UKR1-/);
  await snapTitle(page);
  await page.getByLabel(/last 4 characters/).fill(recoveryKey.replace(/-/g, "").slice(-4));
  await page.getByRole("button", { name: "Open my vault" }).click();

  // A login with a fixed password and TOTP secret, and a note.
  await page.getByRole("button", { name: "Add a login" }).click();
  await page.getByLabel("Title").fill(TITLE);
  await page.getByLabel("Username").fill(USERNAME);
  await page.getByLabel("Password", { exact: true }).fill(ITEM_PASSWORD);
  await page.getByLabel("Paste an otpauth:// link or the secret").fill(`otpauth://totp/Canary:${USERNAME}?secret=${TOTP_SECRET}&issuer=Canary`);
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: TITLE })).toBeVisible();
  await page.getByRole("button", { name: "New item" }).click();
  await page.getByRole("menuitem", { name: "Secure Note" }).click();
  await page.getByRole("textbox", { name: "Title" }).fill("Canary note");
  await page.getByRole("textbox", { name: "Note", exact: true }).fill(NOTE);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Canary note" })).toBeVisible();
  await page.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByRole("status").filter({ hasText: /^Synced$/ })).toBeVisible();
  await snapTitle(page);

  // Reveal and copy once, so those code paths run too, then go back to the masked login.
  await page.getByRole("option", { name: new RegExp(TITLE) }).click();
  await page.getByRole("button", { name: "Reveal password" }).click();
  await expect(page.getByText(ITEM_PASSWORD)).toBeVisible();
  await page.getByRole("option", { name: /Canary note/ }).click();
  await page.getByRole("option", { name: new RegExp(TITLE) }).click();
  await expect(page.getByLabel("Password, hidden")).toBeVisible();

  // Lock and unlock (the master password goes through the unlock path).
  await page.keyboard.press("Shift+L");
  await expect(page.getByRole("heading", { name: "Your vault is locked" })).toBeVisible();
  await snapTitle(page);
  await page.getByLabel("Master password", { exact: true }).fill(MASTER);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("navigation", { name: "Vault" })).toBeVisible();
  await page.getByRole("option", { name: new RegExp(TITLE) }).click();
  await expect(page.getByLabel("Password, hidden")).toBeVisible();
  await snapTitle(page);

  const always = [MASTER, ITEM_PASSWORD, TOTP_SECRET, secretKey, recoveryKey];
  const content = [...always, NOTE, TITLE, USERNAME];

  // 1. Console output, titles and every URL: no secret and no item content.
  expect(leaks(consoleText.join("\n"), content), "console").toEqual([]);
  expect(leaks(titles.join("\n"), content), "titles").toEqual([]);
  expect(leaks(urls.join("\n"), content), "URLs").toEqual([]);

  // 2. Request bodies: the server only ever sees ciphertext and signatures (invariant 1).
  // Sends seen: account creation (keys + envelopes) and the sync push (both items).
  expect(posted.some((u) => u.endsWith("/v1/accounts"))).toBe(true);
  expect(posted.some((u) => u.endsWith("/v1/sync/push"))).toBe(true);
  expect(leaks(bodies.join("\n"), content), "request bodies").toEqual([]);

  // 3. DOM at rest (masked login on screen): no secret anywhere, in text or attributes.
  const dom = await page.evaluate(() => document.documentElement.outerHTML);
  expect(leaks(dom, always), "DOM").toEqual([]);
  const attributes = await page.evaluate(() =>
    [...document.querySelectorAll("*")].flatMap((el) => [...el.attributes].map((a) => `${a.name}=${a.value}`)).join("\n"),
  );
  expect(leaks(attributes, [...always, NOTE]), "DOM attributes").toEqual([]);

  // 4. Web storage: nothing secret (the vault lives encrypted in IndexedDB, tested elsewhere).
  const storage = await page.evaluate(() => {
    const dump = (st: Storage) => Array.from({ length: st.length }, (_, i) => {
      const k = st.key(i) ?? "";
      return `${k}=${st.getItem(k) ?? ""}`;
    });
    return [...dump(localStorage), ...dump(sessionStorage)].join("\n");
  });
  expect(leaks(storage, content), "web storage").toEqual([]);

  await context.close();
});
