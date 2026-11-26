/** Test client: builds signed requests the way the Rust clients do (crypto §7). */
import { exports } from "cloudflare:workers";
import { concat, decode, encode } from "../src/b64";
import { messages, random, sha256 } from "../src/crypto";

export const ORIGIN = "http://localhost:8787";
const te = new TextEncoder();

export async function api(path: string, init: { method?: string; body?: unknown; token?: string; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json", ...init.headers };
  if (init.token !== undefined) headers["authorization"] = `Bearer ${init.token}`;
  const res = await exports.default.fetch(`${ORIGIN}${path}`, {
    method: init.method ?? (init.body === undefined ? "GET" : "POST"),
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
  const text = await res.text();
  return { status: res.status, body: (text === "" ? null : JSON.parse(text)) as Record<string, any>, headers: res.headers };
}

export interface Key {
  pk: Uint8Array;
  sign(msg: Uint8Array): Promise<Uint8Array>;
}

export async function newKey(): Promise<Key> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pk = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  return { pk, sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, m)) };
}

/** A container with a valid shape (crypto §6.1); the content is random. */
export function container(kind: number, keyRef: Uint8Array, ctLen = 48): Uint8Array {
  return concat(new Uint8Array([0x55, 0x4b, 1, kind, 1]), keyRef, random(24), random(ctLen));
}

export const PARAMS = new Uint8Array([1, 0, 0, 0x80, 0, 0, 0, 0, 2, 0, 0, 0, 1]); // 32 MiB, t=2, p=1

export interface Ctx {
  accountId: Uint8Array;
  email: string;
  auth: Key;
  rauth: Key;
  device: Key;
  deviceId: Uint8Array;
  vmkId: Uint8Array;
  token: string;
}

export function deviceInfo(deviceId: Uint8Array, key: Key, name = "Test device") {
  return { device_id: encode(deviceId), device_pk: encode(key.pk), name, platform: "web", client_version: "0.1.0" };
}

export async function createAccount(email = `u${encode(random(6))}@example.test`): Promise<Ctx> {
  const accountId = random(16);
  const auth = await newKey();
  const rauth = await newKey();
  const device = await newKey();
  const deviceId = random(16);
  const vmkId = random(16);
  const payload = te.encode(
    JSON.stringify({
      account_id: encode(accountId),
      email,
      kdf_salt: encode(random(16)),
      kdf_params: encode(PARAMS),
      auth_pk: encode(auth.pk),
      rauth_pk: encode(rauth.pk),
      unlock_env: encode(container(1, vmkId)),
      recovery_env: encode(container(2, vmkId)),
      vmk_id: encode(vmkId),
      device: deviceInfo(deviceId, device),
    }),
  );
  const msg = messages.create(accountId, await sha256(payload));
  const res = await api("/v1/accounts", {
    body: { payload: encode(payload), sig_account: encode(await auth.sign(msg)), sig_device: encode(await device.sign(msg)) },
  });
  if (res.status !== 201) throw new Error(`create failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { accountId, email, auth, rauth, device, deviceId, vmkId, token: res.body["session_token"] as string };
}

export async function challenge(accountId: Uint8Array, purpose: string, token?: string) {
  const r = await api("/v1/auth/challenge", { body: { account_id: encode(accountId), purpose }, ...(token === undefined ? {} : { token }) });
  if (r.status !== 200) throw new Error(`challenge failed: ${r.status}`);
  return { id: r.body["challenge_id"] as string, nonce: decode(r.body["nonce"]) ?? new Uint8Array() };
}

export async function login(ctx: Ctx, deviceId: Uint8Array, device: Key, signer: Key = ctx.auth) {
  const ch = await challenge(ctx.accountId, "login");
  const msg = messages.login(ctx.accountId, ch.nonce, deviceId, device.pk, ORIGIN);
  return api("/v1/auth/login", {
    body: {
      account_id: encode(ctx.accountId),
      challenge_id: ch.id,
      device: deviceInfo(deviceId, device, "Second device"),
      sig_account: encode(await signer.sign(msg)),
      sig_device: encode(await device.sign(msg)),
    },
  });
}

export async function stepup(ctx: Ctx, path: string, operation: string, payloadObj: unknown, newKeyForProof?: Key, signer: Key = ctx.auth) {
  const ch = await challenge(ctx.accountId, "stepup", ctx.token);
  const payload = te.encode(JSON.stringify(payloadObj));
  const msg = messages.stepup(ctx.accountId, ch.nonce, operation, await sha256(payload));
  const body: Record<string, string> = { payload: encode(payload), challenge_id: ch.id, sig_account: encode(await signer.sign(msg)) };
  if (newKeyForProof !== undefined) body["sig_new"] = encode(await newKeyForProof.sign(msg));
  return api(path, { body, token: ctx.token });
}

export function mutation(ctx: Ctx, itemId: Uint8Array, base: number, opts: { vmkId?: Uint8Array; deleted?: boolean } = {}) {
  const vmk = opts.vmkId ?? ctx.vmkId;
  return {
    mutation_id: encode(random(16)),
    item_id: encode(itemId),
    base_revision: base,
    revision: base + 1,
    vmk_id: encode(vmk),
    dek_wrap: encode(container(3, vmk)),
    body: encode(container(opts.deleted === true ? 5 : 4, itemId, 512)),
    deleted: opts.deleted === true,
  };
}

export async function pull(token: string, since = 0, limit = 500) {
  return api(`/v1/sync/changes?since=${since}&limit=${limit}`, { token });
}
