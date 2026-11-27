/** Typed reads of D1 rows and shared write fragments. */
import { blob, encode } from "./b64";
import type { Env } from "./env";

export interface Account {
  accountId: Uint8Array;
  email: string;
  kdfSalt: Uint8Array;
  kdfParams: Uint8Array;
  authPk: Uint8Array;
  rauthPk: Uint8Array;
  unlockEnv: Uint8Array;
  recoveryEnv: Uint8Array;
  vmkId: Uint8Array;
  keysetVersion: number;
  vaultSeq: number;
  tombstoneHorizon: number;
}

interface AccountDbRow {
  account_id: unknown;
  email: string;
  kdf_salt: unknown;
  kdf_params: unknown;
  auth_pk: unknown;
  rauth_pk: unknown;
  unlock_env: unknown;
  recovery_env: unknown;
  vmk_id: unknown;
  keyset_version: number;
  vault_seq: number;
  tombstone_horizon: number;
}

function toAccount(r: AccountDbRow): Account {
  return {
    accountId: blob(r.account_id),
    email: r.email,
    kdfSalt: blob(r.kdf_salt),
    kdfParams: blob(r.kdf_params),
    authPk: blob(r.auth_pk),
    rauthPk: blob(r.rauth_pk),
    unlockEnv: blob(r.unlock_env),
    recoveryEnv: blob(r.recovery_env),
    vmkId: blob(r.vmk_id),
    keysetVersion: r.keyset_version,
    vaultSeq: r.vault_seq,
    tombstoneHorizon: r.tombstone_horizon,
  };
}

export async function loadAccount(env: Env, accountId: Uint8Array): Promise<Account | null> {
  const r = await env.DB.prepare("SELECT * FROM accounts WHERE account_id = ?").bind(accountId).first<AccountDbRow>();
  return r === null ? null : toAccount(r);
}

export async function loadAccountByEmail(env: Env, email: string): Promise<Account | null> {
  const r = await env.DB.prepare("SELECT * FROM accounts WHERE email = ?").bind(email).first<AccountDbRow>();
  return r === null ? null : toAccount(r);
}

export function accountState(a: Account, env: Env) {
  return {
    account_id: encode(a.accountId),
    email: a.email,
    kdf_salt: encode(a.kdfSalt),
    kdf_params: encode(a.kdfParams),
    auth_pk: encode(a.authPk),
    // Public: lets a client confirm a Recovery Key replacement whose response was lost (R-REC-3).
    rauth_pk: encode(a.rauthPk),
    unlock_env: encode(a.unlockEnv),
    vmk_id: encode(a.vmkId),
    keyset_version: a.keysetVersion,
    vault_seq: a.vaultSeq,
    min_client_version: env.MIN_CLIENT_VERSION,
  };
}

export async function accountResponse(env: Env, accountId: Uint8Array) {
  const a = await loadAccount(env, accountId);
  if (a === null) throw new Error("account vanished");
  const { results } = await env.DB.prepare(
    "SELECT device_id, name, platform, client_version, enrolled_via, created_at, last_seen_at, revoked_at FROM devices WHERE account_id = ? ORDER BY created_at",
  )
    .bind(accountId)
    .all<{ device_id: unknown; name: string; platform: string; client_version: string; enrolled_via: string; created_at: number; last_seen_at: number; revoked_at: number | null }>();
  return {
    account: accountState(a, env),
    devices: results.map((d) => ({
      device_id: encode(blob(d.device_id)),
      name: d.name,
      platform: d.platform,
      client_version: d.client_version,
      enrolled_via: d.enrolled_via,
      created_at: d.created_at,
      last_seen_at: d.last_seen_at,
      revoked_at: d.revoked_at,
    })),
  };
}

/**
 * Two statements that take the next feed position and record a security event there. They must
 * run in the same batch, back to back (api.md, atomicity).
 */
export function eventStatements(env: Env, accountId: Uint8Array, kind: string, deviceId: Uint8Array | null, now: number): D1PreparedStatement[] {
  return [
    env.DB.prepare("UPDATE accounts SET vault_seq = vault_seq + 1, updated_at = ? WHERE account_id = ?").bind(now, accountId),
    env.DB.prepare(
      "INSERT INTO security_events (account_id, seq, kind, device_id, created_at) SELECT account_id, vault_seq, ?, ?, ? FROM accounts WHERE account_id = ?",
    ).bind(kind, deviceId, now, accountId),
  ];
}

export async function activeDeviceCount(env: Env, accountId: Uint8Array): Promise<number> {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM devices WHERE account_id = ? AND revoked_at IS NULL").bind(accountId).first<{ n: number }>();
  return r?.n ?? 0;
}

export const MAX_ACTIVE_DEVICES = 20;
export const MAX_ITEMS = 10_000;
