/** Account and device management (api.md; crypto §7.5–§7.10; devices.md). */
import { blob, encode, equal } from "../b64";
import { consumeChallenge, createSession, requireSession, type Session } from "../auth";
import { containerOk, Kind, kdfParamsOk, messages, sha256, verifyEd25519 } from "../crypto";
import { accountResponse, eventStatements, loadAccount, type Account } from "../db";
import type { Env } from "../env";
import { ApiError, json, readJson } from "../http";
import { arr, bool, bytes, int, obj, optBytes, payloadJson, str, type Obj } from "../validate";

export async function getAccount(request: Request, env: Env, now: number): Promise<Response> {
  const s = await requireSession(request, env, ["full"], now);
  return json(await accountResponse(env, s.accountId));
}

interface StepUp {
  session: Session;
  account: Account;
  payload: Obj;
  message: Uint8Array;
  sigNew: Uint8Array | null;
}

/** Verifies a step-up request (crypto §7.8): fresh challenge + current account key signature. */
async function stepUp(request: Request, env: Env, now: number, operation: string, maxBytes: number): Promise<StepUp> {
  const session = await requireSession(request, env, ["full"], now);
  const req = obj(await readJson(request, maxBytes));
  const payloadBytes = bytes(req, "payload", undefined, maxBytes);
  const nonce = await consumeChallenge(env, bytes(req, "challenge_id", 16), session.accountId, "stepup", now);
  const account = await loadAccount(env, session.accountId);
  if (account === null) throw new ApiError(401, "unauthorized");
  const message = messages.stepup(account.accountId, nonce, operation, await sha256(payloadBytes));
  if (!(await verifyEd25519(account.authPk, message, bytes(req, "sig_account", 64)))) throw new ApiError(401, "unauthorized");
  return { session, account, payload: payloadJson(payloadBytes), message, sigNew: optBytes(req, "sig_new", 64) };
}

export async function unlockKeys(request: Request, env: Env, now: number): Promise<Response> {
  const s = await stepUp(request, env, now, "change_unlock_keys", 16 * 1024);
  const p = s.payload;
  const salt = bytes(p, "kdf_salt", 16);
  const params = bytes(p, "kdf_params", 13);
  const authPk = bytes(p, "auth_pk", 32);
  const env1 = bytes(p, "unlock_env", undefined, 1024);
  const reason = str(p, "reason", 1, 16);
  if (!kdfParamsOk(params) || !containerOk(env1, [Kind.UnlockEnvelope], s.account.vmkId) || !["password", "secret_key"].includes(reason)) {
    throw new ApiError(400, "invalid_request");
  }
  // Proof of possession of the new auth key.
  if (s.sigNew === null || !(await verifyEd25519(authPk, s.message, s.sigNew))) throw new ApiError(401, "unauthorized");
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE accounts SET kdf_salt = ?, kdf_params = ?, auth_pk = ?, unlock_env = ?, keyset_version = keyset_version + 1, updated_at = ? WHERE account_id = ?",
    ).bind(salt, params, authPk, env1, now, s.account.accountId),
    ...eventStatements(env, s.account.accountId, reason === "password" ? "password_changed" : "secret_key_rotated", s.session.deviceId, now),
  ]);
  return json(await accountResponse(env, s.account.accountId));
}

export async function recoveryKey(request: Request, env: Env, now: number): Promise<Response> {
  const s = await stepUp(request, env, now, "replace_recovery_key", 16 * 1024);
  const rauthPk = bytes(s.payload, "rauth_pk", 32);
  const recEnv = bytes(s.payload, "recovery_env", undefined, 1024);
  if (!containerOk(recEnv, [Kind.RecoveryEnvelope], s.account.vmkId)) throw new ApiError(400, "invalid_request");
  await env.DB.batch([
    env.DB.prepare("UPDATE accounts SET rauth_pk = ?, recovery_env = ?, keyset_version = keyset_version + 1, updated_at = ? WHERE account_id = ?").bind(
      rauthPk,
      recEnv,
      now,
      s.account.accountId,
    ),
    ...eventStatements(env, s.account.accountId, "recovery_key_rotated", s.session.deviceId, now),
  ]);
  return json(await accountResponse(env, s.account.accountId));
}

export async function rekey(request: Request, env: Env, now: number): Promise<Response> {
  const s = await stepUp(request, env, now, "rekey", 64 * 1024 * 1024);
  const p = s.payload;
  const a = s.account;
  const expected = int(p, "expected_vault_seq");
  const vmkId = bytes(p, "vmk_id", 16);
  const unlockEnv = bytes(p, "unlock_env", undefined, 1024);
  const recEnv = bytes(p, "recovery_env", undefined, 1024);
  const rauthPk = bytes(p, "rauth_pk", 32);
  if (equal(vmkId, a.vmkId) || !containerOk(unlockEnv, [Kind.UnlockEnvelope], vmkId) || !containerOk(recEnv, [Kind.RecoveryEnvelope], vmkId)) {
    throw new ApiError(400, "invalid_request");
  }
  if (expected !== a.vaultSeq) throw new ApiError(409, "vault_changed");
  const { results: current } = await env.DB.prepare("SELECT item_id, revision FROM items WHERE account_id = ?")
    .bind(a.accountId)
    .all<{ item_id: unknown; revision: number }>();
  const revs = new Map(current.map((r) => [encode(blob(r.item_id)), r.revision]));
  const items = arr(p, "items", 10_000).map((x) => {
    const o = obj(x);
    const itemId = bytes(o, "item_id", 16);
    const it = {
      itemId,
      revision: int(o, "revision", 2),
      dekWrap: bytes(o, "dek_wrap", undefined, 1024),
      body: bytes(o, "body", undefined, 1_200_000),
      deleted: bool(o, "deleted"),
    };
    if (!containerOk(it.dekWrap, [Kind.DekWrap], vmkId) || !containerOk(it.body, [Kind.ItemPayload, Kind.Tombstone], itemId)) {
      throw new ApiError(400, "invalid_request");
    }
    if (revs.get(encode(itemId)) !== it.revision - 1) throw new ApiError(409, "vault_changed");
    return it;
  });
  // Every item exactly once: rotation must not leave anything under the old key.
  if (items.length !== revs.size || new Set(items.map((i) => encode(i.itemId))).size !== items.length) throw new ApiError(400, "invalid_request");
  const n = items.length;
  const guard = "EXISTS (SELECT 1 FROM accounts WHERE account_id = ? AND vmk_id = ? AND vault_seq = ?)";
  const finalSeq = expected + n + 1;
  const stmts: D1PreparedStatement[] = [
    env.DB.prepare(
      `UPDATE accounts SET vmk_id = ?, unlock_env = ?, recovery_env = ?, rauth_pk = ?, keyset_version = keyset_version + 1,
         vault_seq = vault_seq + ?, updated_at = ? WHERE account_id = ? AND vault_seq = ? AND vmk_id = ?`,
    ).bind(vmkId, unlockEnv, recEnv, rauthPk, n + 1, now, a.accountId, expected, a.vmkId),
    ...items.map((it, i) =>
      env.DB.prepare(
        `UPDATE items SET revision = ?, seq = ?, vmk_id = ?, dek_wrap = ?, body = ?, deleted = ?, updated_at = ?, updated_by = ?
         WHERE account_id = ? AND item_id = ? AND revision = ? AND ${guard}`,
      ).bind(it.revision, expected + i + 1, vmkId, it.dekWrap, it.body, it.deleted ? 1 : 0, now, s.session.deviceId, a.accountId, it.itemId, it.revision - 1, a.accountId, vmkId, finalSeq),
    ),
    env.DB.prepare(
      `INSERT INTO security_events (account_id, seq, kind, device_id, created_at) SELECT ?, ?, 'vmk_rotated', ?, ? WHERE ${guard}`,
    ).bind(a.accountId, finalSeq, s.session.deviceId, now, a.accountId, vmkId, finalSeq),
  ];
  const res = await env.DB.batch(stmts);
  if ((res[0]?.meta.changes ?? 0) !== 1) throw new ApiError(409, "vault_changed");
  return json(await accountResponse(env, a.accountId));
}

export async function recover(request: Request, env: Env, now: number): Promise<Response> {
  const session = await requireSession(request, env, ["recovery"], now);
  const p = obj(await readJson(request, 16 * 1024));
  const a = await loadAccount(env, session.accountId);
  if (a === null) throw new ApiError(401, "unauthorized");
  const salt = bytes(p, "kdf_salt", 16);
  const params = bytes(p, "kdf_params", 13);
  const authPk = bytes(p, "auth_pk", 32);
  const unlockEnv = bytes(p, "unlock_env", undefined, 1024);
  const rauthPk = bytes(p, "rauth_pk", 32);
  const recEnv = bytes(p, "recovery_env", undefined, 1024);
  if (!kdfParamsOk(params) || !containerOk(unlockEnv, [Kind.UnlockEnvelope], a.vmkId) || !containerOk(recEnv, [Kind.RecoveryEnvelope], a.vmkId)) {
    throw new ApiError(400, "invalid_request");
  }
  if (equal(rauthPk, a.rauthPk)) throw new ApiError(400, "invalid_request"); // the Recovery Key must change (R-REC-2)
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts SET kdf_salt = ?, kdf_params = ?, auth_pk = ?, unlock_env = ?, rauth_pk = ?, recovery_env = ?,
         keyset_version = keyset_version + 1, updated_at = ? WHERE account_id = ?`,
    ).bind(salt, params, authPk, unlockEnv, rauthPk, recEnv, now, a.accountId),
    env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE account_id = ? AND device_id != ? AND revoked_at IS NULL").bind(now, a.accountId, session.deviceId),
    env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(session.tokenHash),
    ...eventStatements(env, a.accountId, "recovery_used", session.deviceId, now),
  ]);
  return json(await createSession(env, a.accountId, session.deviceId, "full", now));
}

export async function revokeDevice(request: Request, env: Env, now: number): Promise<Response> {
  const s = await stepUp(request, env, now, "revoke_device", 4096);
  const deviceId = bytes(s.payload, "device_id", 16);
  if (equal(deviceId, s.session.deviceId)) throw new ApiError(400, "invalid_request");
  const res = await env.DB.batch([
    // Sessions are kept until next use so the device learns it was revoked (`401 device_revoked`,
    // sync.md §8.3); `requireSession` refuses and deletes them.
    env.DB.prepare("UPDATE devices SET revoked_at = ? WHERE device_id = ? AND account_id = ? AND revoked_at IS NULL").bind(now, deviceId, s.account.accountId),
    ...eventStatements(env, s.account.accountId, "device_revoked", deviceId, now),
  ]);
  if ((res[0]?.meta.changes ?? 0) !== 1) throw new ApiError(404, "not_found");
  return json(await accountResponse(env, s.account.accountId));
}

export async function renameDevice(request: Request, env: Env, now: number): Promise<Response> {
  const s = await requireSession(request, env, ["full"], now);
  const o = obj(await readJson(request, 4096));
  const res = await env.DB.prepare("UPDATE devices SET name = ? WHERE device_id = ? AND account_id = ?")
    .bind(str(o, "name", 1, 64), bytes(o, "device_id", 16), s.accountId)
    .run();
  if (res.meta.changes !== 1) throw new ApiError(404, "not_found");
  return json(await accountResponse(env, s.accountId));
}
