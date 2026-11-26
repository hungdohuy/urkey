import type { Env } from "./env";
import { getAccount, recover, recoveryKey, rekey, renameDevice, revokeDevice, unlockKeys } from "./handlers/account";
import { challenge, createAccount, login, logout, prelogin, recoveryLogin, refresh } from "./handlers/auth";
import { changes, push } from "./handlers/sync";
import { ApiError, empty, error, json, withCors } from "./http";
import { Router } from "./router";
import { versionLess } from "./validate";

const API_VERSION = "v1";
const DAY = 24 * 60 * 60 * 1000;

export const router = new Router()
  .on("GET", "/v1/health", (_request, env) => json({ status: "ok", api: API_VERSION, min_client_version: env.MIN_CLIENT_VERSION }))
  .on("POST", "/v1/auth/prelogin", prelogin)
  .on("POST", "/v1/auth/challenge", challenge)
  .on("POST", "/v1/accounts", createAccount)
  .on("POST", "/v1/auth/login", login)
  .on("POST", "/v1/auth/refresh", refresh)
  .on("POST", "/v1/auth/recovery", recoveryLogin)
  .on("POST", "/v1/auth/logout", logout)
  .on("GET", "/v1/account", getAccount)
  .on("POST", "/v1/account/unlock-keys", unlockKeys)
  .on("POST", "/v1/account/recovery-key", recoveryKey)
  .on("POST", "/v1/account/rekey", rekey)
  .on("POST", "/v1/account/recover", recover)
  .on("POST", "/v1/devices/revoke", revokeDevice)
  .on("POST", "/v1/devices/rename", renameDevice)
  .on("GET", "/v1/sync/changes", changes)
  .on("POST", "/v1/sync/push", push);

async function route(request: Request, env: Env): Promise<Response> {
  if (request.method === "OPTIONS") {
    return router.methods(new URL(request.url).pathname).length > 0 ? empty(204) : error(404, "not_found");
  }
  const client = request.headers.get("urkey-client");
  if (client !== null) {
    const version = client.split("/")[1] ?? "";
    if (versionLess(version, env.MIN_CLIENT_VERSION)) return error(426, "update_required");
  }
  try {
    return await router.handle(request, env, Date.now());
  } catch (e) {
    if (e instanceof ApiError) return error(e.status, e.code);
    // Never echo exception details: they could contain request data (threat model T-20).
    return error(500, "internal_error");
  }
}

/** Retention (data-model §3): expired auth state, old idempotency entries, 90-day tombstones. */
export async function cleanup(env: Env, now: number): Promise<void> {
  const cutoff = now - 90 * DAY;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM challenges WHERE expires_at < ?").bind(now - DAY),
    env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now),
    env.DB.prepare("DELETE FROM mutations WHERE created_at < ?").bind(now - 30 * DAY),
    env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - DAY),
    env.DB.prepare(
      `UPDATE accounts SET tombstone_horizon = MAX(tombstone_horizon,
         COALESCE((SELECT MAX(seq) FROM items i WHERE i.account_id = accounts.account_id AND i.deleted = 1 AND i.updated_at < ?), 0))`,
    ).bind(cutoff),
    env.DB.prepare("DELETE FROM items WHERE deleted = 1 AND updated_at < ?").bind(cutoff),
  ]);
}

export default {
  async fetch(request, env): Promise<Response> {
    return withCors(await route(request, env), request, env.APP_ORIGIN);
  },
  async scheduled(_controller, env): Promise<void> {
    await cleanup(env, Date.now());
  },
} satisfies ExportedHandler<Env>;
