/** Sessions, challenges, rate limits and device checks (crypto §7.4, §7.8, §7.9). */
import { blob, encode } from "./b64";
import { random, sha256 } from "./crypto";
import type { Env } from "./env";
import { ApiError } from "./http";

export const SESSION_IDLE_MS = 60 * 60 * 1000;
export const SESSION_MAX_MS = 24 * 60 * 60 * 1000;
export const RECOVERY_SESSION_MS = 15 * 60 * 1000;
export const CHALLENGE_MS = 2 * 60 * 1000;
const LAST_SEEN_THROTTLE_MS = 5 * 60 * 1000;

export type Scope = "full" | "recovery";

export interface Session {
  accountId: Uint8Array;
  deviceId: Uint8Array;
  scope: Scope;
  tokenHash: Uint8Array;
}

export interface SessionResponse {
  session_token: string;
  expires_at: number;
  scope: Scope;
}

export async function createSession(env: Env, accountId: Uint8Array, deviceId: Uint8Array, scope: Scope, now: number): Promise<SessionResponse> {
  const token = random(32);
  const expires = now + (scope === "recovery" ? RECOVERY_SESSION_MS : SESSION_IDLE_MS);
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, account_id, device_id, scope, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(await sha256(token), accountId, deviceId, scope, now, now, expires)
    .run();
  return { session_token: encode(token), expires_at: expires, scope };
}

/** Authenticates the bearer token; slides the idle expiry within the absolute limit. */
export async function requireSession(request: Request, env: Env, scopes: readonly Scope[], now: number): Promise<Session> {
  const header = request.headers.get("authorization") ?? "";
  const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(header);
  if (m === null) throw new ApiError(401, "unauthorized");
  const raw = Uint8Array.from(atob((m[1] ?? "").replaceAll("-", "+").replaceAll("_", "/") + "="), (c) => c.charCodeAt(0));
  const tokenHash = await sha256(raw);
  const row = await env.DB.prepare(
    `SELECT s.account_id, s.device_id, s.scope, s.created_at, s.expires_at, d.revoked_at, d.last_seen_at
       FROM sessions s JOIN devices d ON d.device_id = s.device_id WHERE s.token_hash = ?`,
  )
    .bind(tokenHash)
    .first<{ account_id: unknown; device_id: unknown; scope: Scope; created_at: number; expires_at: number; revoked_at: number | null; last_seen_at: number }>();
  if (row === null) throw new ApiError(401, "unauthorized");
  if (row.revoked_at !== null) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    throw new ApiError(401, "device_revoked");
  }
  const maxAge = row.scope === "recovery" ? RECOVERY_SESSION_MS : SESSION_MAX_MS;
  if (now > row.expires_at || now - row.created_at > maxAge) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    throw new ApiError(401, "unauthorized");
  }
  if (!scopes.includes(row.scope)) throw new ApiError(403, "forbidden");
  const deviceId = blob(row.device_id);
  const stmts = [];
  if (row.scope === "full") {
    stmts.push(
      env.DB.prepare("UPDATE sessions SET last_used_at = ?, expires_at = ? WHERE token_hash = ?").bind(
        now,
        Math.min(now + SESSION_IDLE_MS, row.created_at + SESSION_MAX_MS),
        tokenHash,
      ),
    );
  }
  if (now - row.last_seen_at > LAST_SEEN_THROTTLE_MS) {
    stmts.push(env.DB.prepare("UPDATE devices SET last_seen_at = ? WHERE device_id = ?").bind(now, deviceId));
  }
  if (stmts.length > 0) await env.DB.batch(stmts);
  return { accountId: blob(row.account_id), deviceId, scope: row.scope, tokenHash };
}

export async function issueChallenge(env: Env, accountId: Uint8Array, purpose: string, now: number) {
  const challengeId = random(16);
  const nonce = random(32);
  const expires = now + CHALLENGE_MS;
  await env.DB.prepare("INSERT INTO challenges (challenge_id, account_id, nonce, purpose, expires_at) VALUES (?, ?, ?, ?, ?)")
    .bind(challengeId, accountId, nonce, purpose, expires)
    .run();
  return { challenge_id: encode(challengeId), nonce: encode(nonce), expires_at: expires };
}

/** Consumes a challenge exactly once; any mismatch is `401 unauthorized`. */
export async function consumeChallenge(env: Env, challengeId: Uint8Array, accountId: Uint8Array, purpose: string, now: number): Promise<Uint8Array> {
  const row = await env.DB.prepare(
    "UPDATE challenges SET used_at = ? WHERE challenge_id = ? AND account_id = ? AND purpose = ? AND used_at IS NULL AND expires_at >= ? RETURNING nonce",
  )
    .bind(now, challengeId, accountId, purpose, now)
    .first<{ nonce: unknown }>();
  if (row === null) throw new ApiError(401, "unauthorized");
  return blob(row.nonce);
}

/** Fixed-window rate limit. Bucket keys are hashed, so no raw IPs are stored. */
export async function rateLimit(env: Env, key: string, max: number, windowMs: number, now: number): Promise<void> {
  const bucket = await sha256(new TextEncoder().encode(key));
  const windowStart = now - (now % windowMs);
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (bucket, window_start, count) VALUES (?, ?, 1)
     ON CONFLICT(bucket) DO UPDATE SET
       count = CASE WHEN window_start = excluded.window_start THEN count + 1 ELSE 1 END,
       window_start = excluded.window_start
     RETURNING count`,
  )
    .bind(bucket, windowStart)
    .first<{ count: number }>();
  if (row !== null && row.count > max) throw new ApiError(429, "rate_limited");
}

export function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "local";
}
