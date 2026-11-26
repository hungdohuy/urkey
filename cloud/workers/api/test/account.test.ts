import { describe, expect, it } from "vitest";
import { encode } from "../src/b64";
import { messages, random } from "../src/crypto";
import { api, challenge, container, createAccount, deviceInfo, login, mutation, newKey, ORIGIN, PARAMS, pull, stepup } from "./helpers";

describe("key changes (step-up)", () => {
  it("changes unlock keys only with the current key and a proof by the new key", async () => {
    const ctx = await createAccount();
    const next = await newKey();
    const payload = { kdf_salt: encode(random(16)), kdf_params: encode(PARAMS), auth_pk: encode(next.pk), unlock_env: encode(container(1, ctx.vmkId)), reason: "password" };
    expect((await stepup(ctx, "/v1/account/unlock-keys", "change_unlock_keys", payload)).status).toBe(401); // no proof
    expect((await stepup(ctx, "/v1/account/unlock-keys", "change_unlock_keys", payload, next, await newKey())).status).toBe(401); // wrong current key
    const ok = await stepup(ctx, "/v1/account/unlock-keys", "change_unlock_keys", payload, next);
    expect(ok.status).toBe(200);
    expect(ok.body["account"]["auth_pk"]).toBe(encode(next.pk));
    expect(ok.body["account"]["keyset_version"]).toBe(2);
    // The old key no longer logs in; the new one does.
    expect((await login(ctx, random(16), await newKey())).status).toBe(401);
    expect((await login(ctx, random(16), await newKey(), next)).status).toBe(200);
  });

  it("refuses weak KDF parameters and mis-keyed envelopes", async () => {
    const ctx = await createAccount();
    const next = await newKey();
    const weak = new Uint8Array([1, 0, 0, 0x10, 0, 0, 0, 0, 1, 0, 0, 0, 1]);
    const base = { kdf_salt: encode(random(16)), auth_pk: encode(next.pk), reason: "password" };
    expect((await stepup(ctx, "/v1/account/unlock-keys", "change_unlock_keys", { ...base, kdf_params: encode(weak), unlock_env: encode(container(1, ctx.vmkId)) }, next)).status).toBe(400);
    expect((await stepup(ctx, "/v1/account/unlock-keys", "change_unlock_keys", { ...base, kdf_params: encode(PARAMS), unlock_env: encode(container(1, random(16))) }, next)).status).toBe(400);
  });

  it("replaces the recovery key", async () => {
    const ctx = await createAccount();
    const r = await newKey();
    const res = await stepup(ctx, "/v1/account/recovery-key", "replace_recovery_key", { rauth_pk: encode(r.pk), recovery_env: encode(container(2, ctx.vmkId)) });
    expect(res.status).toBe(200);
  });

  it("rotates the vault key atomically and refuses stale or partial rotations", async () => {
    const ctx = await createAccount();
    const items = [random(16), random(16)];
    for (const it of items) await api("/v1/sync/push", { body: { mutations: [mutation(ctx, it, 0)] }, token: ctx.token });
    const acct = await api("/v1/account", { token: ctx.token });
    const seq = acct.body["account"]["vault_seq"] as number;
    const newVmk = random(16);
    const rekeyItems = items.map((it) => ({ item_id: encode(it), revision: 2, dek_wrap: encode(container(3, newVmk)), body: encode(container(4, it, 512)), deleted: false }));
    const payload = (s: number, list = rekeyItems) => ({ expected_vault_seq: s, vmk_id: encode(newVmk), unlock_env: encode(container(1, newVmk)), recovery_env: encode(container(2, newVmk)), rauth_pk: encode((ctx.rauth).pk), items: list });
    expect((await stepup(ctx, "/v1/account/rekey", "rekey", payload(seq - 1))).status).toBe(409);
    expect((await stepup(ctx, "/v1/account/rekey", "rekey", payload(seq, rekeyItems.slice(0, 1)))).status).toBe(400);
    const ok = await stepup(ctx, "/v1/account/rekey", "rekey", payload(seq));
    expect(ok.status).toBe(200);
    expect(ok.body["account"]["vmk_id"]).toBe(encode(newVmk));
    expect(ok.body["account"]["vault_seq"]).toBe(seq + 3);
    const feed = await pull(ctx.token);
    expect(feed.body["changes"].filter((c: any) => c.type === "item").every((c: any) => c.item.vmk_id === encode(newVmk))).toBe(true);
    expect(feed.body["changes"].some((c: any) => c.type === "event" && c.event.kind === "vmk_rotated")).toBe(true);
    // Writes under the old key are refused.
    const stale = await api("/v1/sync/push", { body: { mutations: [mutation(ctx, items[0]!, 2)] }, token: ctx.token });
    expect(stale.body["results"][0].status).toBe("keyset_changed");
  });
});

describe("devices and recovery", () => {
  it("revokes a device: its session ends immediately and refresh fails", async () => {
    const ctx = await createAccount();
    const d2 = await newKey();
    const id2 = random(16);
    const l = await login(ctx, id2, d2);
    const token2 = l.body["session_token"] as string;
    expect((await stepup(ctx, "/v1/devices/revoke", "revoke_device", { device_id: encode(ctx.deviceId) })).status).toBe(400); // not itself
    expect((await stepup(ctx, "/v1/devices/revoke", "revoke_device", { device_id: encode(id2) })).status).toBe(200);
    const r = await api("/v1/account", { token: token2 });
    expect(r.status).toBe(401);
    expect(r.body["error"]).toBe("device_revoked");
    expect((await login(ctx, id2, d2)).body["error"]).toBe("device_revoked");
  });

  it("a stolen session token alone cannot revoke devices or change keys", async () => {
    const ctx = await createAccount();
    const ch = await challenge(ctx.accountId, "stepup", ctx.token);
    const res = await api("/v1/devices/revoke", { token: ctx.token, body: { payload: encode(new TextEncoder().encode("{}")), challenge_id: ch.id, sig_account: encode(random(64)) } });
    expect(res.status).toBe(401);
  });

  it("renames a device", async () => {
    const ctx = await createAccount();
    const r = await api("/v1/devices/rename", { token: ctx.token, body: { device_id: encode(ctx.deviceId), name: "Laptop" } });
    expect(r.body["devices"][0].name).toBe("Laptop");
  });

  it("recovers with the recovery key, replaces all credentials and revokes other devices", async () => {
    const ctx = await createAccount();
    const newDevice = await newKey();
    const newDeviceId = random(16);
    const ch = await challenge(ctx.accountId, "recovery");
    const msg = messages.recovery(ctx.accountId, ch.nonce, newDevice.pk, ORIGIN);
    const body = (sig: Uint8Array) => ({ account_id: encode(ctx.accountId), challenge_id: ch.id, device: deviceInfo(newDeviceId, newDevice), sig_recovery: encode(sig), sig_device: "" });
    const bad = await api("/v1/auth/recovery", { body: { ...body(await (await newKey()).sign(msg)), sig_device: encode(await newDevice.sign(msg)) } });
    expect(bad.status).toBe(401);
    const ch2 = await challenge(ctx.accountId, "recovery");
    const msg2 = messages.recovery(ctx.accountId, ch2.nonce, newDevice.pk, ORIGIN);
    const rec = await api("/v1/auth/recovery", {
      body: { account_id: encode(ctx.accountId), challenge_id: ch2.id, device: deviceInfo(newDeviceId, newDevice), sig_recovery: encode(await ctx.rauth.sign(msg2)), sig_device: encode(await newDevice.sign(msg2)) },
    });
    expect(rec.status).toBe(200);
    const recToken = rec.body["session"]["session_token"] as string;
    expect((await api("/v1/account", { token: recToken })).status).toBe(403); // recovery scope only
    const newAuth = await newKey();
    const newR = await newKey();
    const done = await api("/v1/account/recover", {
      token: recToken,
      body: { kdf_salt: encode(random(16)), kdf_params: encode(PARAMS), auth_pk: encode(newAuth.pk), unlock_env: encode(container(1, ctx.vmkId)), rauth_pk: encode(newR.pk), recovery_env: encode(container(2, ctx.vmkId)) },
    });
    expect(done.status).toBe(200);
    const old = await api("/v1/account", { token: ctx.token });
    expect(old.status).toBe(401);
    expect(old.body["error"]).toBe("device_revoked"); // old device revoked
    const acct = await api("/v1/account", { token: done.body["session_token"] });
    expect(acct.body["devices"].filter((d: any) => d.revoked_at === null)).toHaveLength(1);
  });
});
