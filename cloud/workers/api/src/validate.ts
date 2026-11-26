/** Input validation at the API boundary (CLAUDE.md: validate all API input). */
import { decode } from "./b64";
import { ApiError } from "./http";

const bad = () => new ApiError(400, "invalid_request");

export type Obj = Record<string, unknown>;

export function obj(v: unknown): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw bad();
  return v as Obj;
}

export function bytes(o: Obj, key: string, len?: number, max = 1_200_000): Uint8Array {
  const b = decode(o[key]);
  if (b === null || (len !== undefined && b.length !== len) || b.length > max) throw bad();
  return b;
}

export function optBytes(o: Obj, key: string, len?: number): Uint8Array | null {
  return o[key] === undefined || o[key] === null ? null : bytes(o, key, len);
}

export function str(o: Obj, key: string, min = 0, max = 256): string {
  const s = o[key];
  if (typeof s !== "string") throw bad();
  const chars = Array.from(s).length;
  if (chars < min || chars > max) throw bad();
  return s;
}

export function int(o: Obj, key: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  const n = o[key];
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min || n > max) throw bad();
  return n;
}

export function bool(o: Obj, key: string): boolean {
  const b = o[key];
  if (typeof b !== "boolean") throw bad();
  return b;
}

export function arr(o: Obj, key: string, max: number): unknown[] {
  const a = o[key];
  if (!Array.isArray(a) || a.length > max) throw bad();
  return a;
}

/** Parses the JSON inside a signed payload (exact bytes are what was signed). */
export function payloadJson(payload: Uint8Array): Obj {
  try {
    return obj(JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(payload)));
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw bad();
  }
}

export interface DeviceInfo {
  deviceId: Uint8Array;
  devicePk: Uint8Array;
  name: string;
  platform: string;
  clientVersion: string;
}

export function deviceInfo(v: unknown): DeviceInfo {
  const o = obj(v);
  const platform = str(o, "platform", 1, 32);
  if (!/^[a-z0-9-]+$/.test(platform)) throw bad();
  return {
    deviceId: bytes(o, "device_id", 16),
    devicePk: bytes(o, "device_pk", 32),
    name: str(o, "name", 1, 64),
    platform,
    clientVersion: str(o, "client_version", 1, 32),
  };
}

export function normalizeEmail(email: string): string {
  const e = email.trim().toLowerCase();
  if (e.length < 3 || e.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(e)) throw bad();
  return e;
}

/** Compares two dotted versions numerically; non-numeric parts compare as 0. */
export function versionLess(a: string, b: string): boolean {
  const pa = a.split(/[.+-]/).map((x) => Number.parseInt(x, 10) || 0);
  const pb = b.split(/[.+-]/).map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}
