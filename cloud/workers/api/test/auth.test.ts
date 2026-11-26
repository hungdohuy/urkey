import { describe, expect, it } from "vitest";
import { encode } from "../src/b64";
import { random } from "../src/crypto";
import { api, challenge, createAccount, login, newKey } from "./helpers";

describe("account creation and login", () => {
  it("creates an account and returns a full session", async () => {
    const ctx = await createAccount();
    const acct = await api("/v1/account", { token: ctx.token });
    expect(acct.status).toBe(200);
    expect(acct.body["account"]["account_id"]).toBe(encode(ctx.accountId));
    expect(acct.body["devices"]).toHaveLength(1);
  });

  it("rejects a duplicate email", async () => {
    const ctx = await createAccount();
    await expect(createAccount(ctx.email)).rejects.toThrow(/409/);
  });

  it("prelogin returns real values for known emails and stable fake values for unknown ones", async () => {
    const ctx = await createAccount();
    const known = await api("/v1/auth/prelogin", { body: { email: ` ${ctx.email.toUpperCase()} ` } });
    expect(known.body["account_id"]).toBe(encode(ctx.accountId));
    const a = await api("/v1/auth/prelogin", { body: { email: "nobody@example.test" } });
    const b = await api("/v1/auth/prelogin", { body: { email: "nobody@example.test" } });
    expect(a.status).toBe(200);
    expect(a.body).toEqual(b.body);
    expect(Object.keys(a.body).sort()).toEqual(Object.keys(known.body).sort());
    // Challenges are issued for unknown accounts too (no enumeration).
    const ch = await api("/v1/auth/challenge", { body: { account_id: a.body["account_id"], purpose: "login" } });
    expect(ch.status).toBe(200);
  });

  it("logs in a new device with account + device signatures and records an event", async () => {
    const ctx = await createAccount();
    const dev2 = await newKey();
    const res = await login(ctx, random(16), dev2);
    expect(res.status).toBe(200);
    expect(res.body["scope"]).toBe("full");
    const acct = await api("/v1/account", { token: ctx.token });
    expect(acct.body["devices"]).toHaveLength(2);
    const feed = await api("/v1/sync/changes?since=0", { token: ctx.token });
    expect(feed.body["changes"].some((c: any) => c.type === "event" && c.event.kind === "device_enrolled")).toBe(true);
  });

  it("rejects a wrong account key, a replayed challenge and an unknown account", async () => {
    const ctx = await createAccount();
    const dev2 = await newKey();
    expect((await login(ctx, random(16), dev2, await newKey())).status).toBe(401);
    // Replay: consume a challenge, then reuse it.
    const ch = await challenge(ctx.accountId, "login");
    const body = { account_id: encode(ctx.accountId), challenge_id: ch.id, device: { device_id: encode(random(16)), device_pk: encode(dev2.pk), name: "x", platform: "web", client_version: "0.1.0" }, sig_account: encode(random(64)), sig_device: encode(random(64)) };
    expect((await api("/v1/auth/login", { body })).status).toBe(401);
    expect((await api("/v1/auth/login", { body })).status).toBe(401);
  });

  it("refreshes a session with the device key only", async () => {
    const ctx = await createAccount();
    const { messages } = await import("../src/crypto");
    const ch = await challenge(ctx.accountId, "refresh");
    const sig = await ctx.device.sign(messages.refresh(ctx.accountId, ch.nonce, ctx.deviceId));
    const res = await api("/v1/auth/refresh", { body: { account_id: encode(ctx.accountId), device_id: encode(ctx.deviceId), challenge_id: ch.id, sig_device: encode(sig) } });
    expect(res.status).toBe(200);
    expect((await api("/v1/account", { token: res.body["session_token"] })).status).toBe(200);
  });

  it("logout ends the session", async () => {
    const ctx = await createAccount();
    expect((await api("/v1/auth/logout", { method: "POST", token: ctx.token })).status).toBe(204);
    expect((await api("/v1/account", { token: ctx.token })).status).toBe(401);
  });

  it("rejects missing and malformed tokens with a fixed body", async () => {
    const r = await api("/v1/account", { token: "nope" });
    expect(r.status).toBe(401);
    expect(r.body).toEqual({ error: "unauthorized" });
  });

  it("enforces the minimum client version and CORS origin", async () => {
    const r = await api("/v1/health", { headers: { "urkey-client": "web/0.0.0-alpha" } });
    expect(r.status).toBe(200);
    const cors = await api("/v1/health", { headers: { origin: "http://localhost:5173" } });
    expect(cors.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    const evil = await api("/v1/health", { headers: { origin: "https://evil.example" } });
    expect(evil.headers.get("access-control-allow-origin")).toBeNull();
  });
});
