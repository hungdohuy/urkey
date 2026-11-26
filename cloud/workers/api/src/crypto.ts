/**
 * The only cryptography the Worker does: SHA-256, HMAC for fake prelogin values, randomness,
 * and Ed25519 *verification* (CLAUDE.md: no vault cryptography on the server). Message layouts
 * match crates/crypto-core/src/sign.rs byte for byte (checked against tests/fixtures).
 */
import { concat } from "./b64";

const te = new TextEncoder();

export function random(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function hmacSha256(key: string, data: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", te.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, te.encode(data)));
}

/** Strict Ed25519 verification; any malformed input is simply `false`. */
export async function verifyEd25519(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature, message);
  } catch {
    return false;
  }
}

/** LP(x) = u32be(len(x)) ‖ x */
function lp(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

const label = (s: string) => lp(te.encode(s));

export const messages = {
  create: (accountId: Uint8Array, bodyHash: Uint8Array) => concat(label("urkey/v1/sig/create"), accountId, bodyHash),
  login: (accountId: Uint8Array, nonce: Uint8Array, deviceId: Uint8Array, devicePk: Uint8Array, origin: string) =>
    concat(label("urkey/v1/sig/login"), accountId, nonce, deviceId, devicePk, lp(te.encode(origin))),
  recovery: (accountId: Uint8Array, nonce: Uint8Array, devicePk: Uint8Array, origin: string) =>
    concat(label("urkey/v1/sig/recovery"), accountId, nonce, devicePk, lp(te.encode(origin))),
  stepup: (accountId: Uint8Array, nonce: Uint8Array, operation: string, bodyHash: Uint8Array) =>
    concat(label("urkey/v1/sig/stepup"), accountId, nonce, lp(te.encode(operation)), bodyHash),
  refresh: (accountId: Uint8Array, nonce: Uint8Array, deviceId: Uint8Array) =>
    concat(label("urkey/v1/sig/refresh"), accountId, nonce, deviceId),
};

/** Container kinds (crypto §6.1). */
export const Kind = { UnlockEnvelope: 1, RecoveryEnvelope: 2, DekWrap: 3, ItemPayload: 4, Tombstone: 5 } as const;

/**
 * Shape check of an encrypted container (crypto §6.2 steps 1–3). The server cannot and does not
 * check the content; it refuses malformed shapes and wrong key references.
 */
export function containerOk(c: Uint8Array, kinds: readonly number[], keyRef: Uint8Array): boolean {
  if (c.length < 21 + 24 + 16) return false;
  if (c[0] !== 0x55 || c[1] !== 0x4b || c[2] !== 1) return false; // "UK", v1
  if (!kinds.includes(c[3] ?? 0) || c[4] !== 1) return false; // XChaCha20-Poly1305
  for (let i = 0; i < 16; i++) if (c[5 + i] !== keyRef[i]) return false;
  return true;
}

/** Validates encoded Argon2id parameters against the floor/ceiling (crypto §4.2). */
export function kdfParamsOk(p: Uint8Array): boolean {
  if (p.length !== 13 || p[0] !== 1) return false;
  const v = new DataView(p.buffer, p.byteOffset, p.byteLength);
  const m = v.getUint32(1);
  const t = v.getUint32(5);
  const par = v.getUint32(9);
  return m >= 32768 && m <= 1048576 && t >= 2 && t <= 20 && par >= 1 && m >= 8 * par;
}

export const DEFAULT_KDF_PARAMS = new Uint8Array([1, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1]);
