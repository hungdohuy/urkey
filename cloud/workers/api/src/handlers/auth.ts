/** Account creation and authentication (api.md; crypto §7.1, §7.4, §7.7, §7.9). */
import { blob, encode, equal } from "../b64";
import { clientIp, consumeChallenge, createSession, issueChallenge, rateLimit, requireSession } from "../auth";
import { containerOk, DEFAULT_KDF_PARAMS, hmacSha256, Kind, kdfParamsOk, messages, sha256, verifyEd25519 } from "../crypto";
import { activeDeviceCount, eventStatements, loadAccount, loadAccountByEmail, MAX_ACTIVE_DEVICES } from "../db";
import type { Env } from "../env";
import { ApiError, empty, json, readJson } from "../http";
import { bytes, deviceInfo, normalizeEmail, obj, payloadJson, str, type DeviceInfo } from "../validate";

const MINUTE = 60_000;
const PURPOSES = new Set(["login", "recovery", "stepup", "refresh"]);

export async function prelogin(request: Request, env: Env, now: number): Promise<Response> {
  await rateLimit(env, `prelogin:${clientIp(request)}`, 30, MINUTE, now);
  const email = normalizeEmail(str(obj(await readJson(request, 4096)), "email", 3, 254));
  const a = await loadAccountByEmail(env, email);
  if (a !== null) {
    return json({ account_id: encode(a.accountId), kdf_salt: encode(a.kdfSalt), kdf_params: encode(a.kdfParams) });
  }
  if (env.PRELOGIN_SECRET.length < 16) throw new ApiError(500, "internal_error");
  // Unknown email: deterministic fake values so responses do not reveal which emails exist.
  const id = (await hmacSha256(env.PRELOGIN_SECRET, `account:${email}`)).slice(0, 16);
  const salt = (await hmacSha256(env.PRELOGIN_SECRET, `salt:${email}`)).slice(0, 16);
  return json({ account_id: encode(id), kdf_salt: encode(salt), kdf_params: encode(DEFAULT_KDF_PARAMS) });
}

export async function challenge(request: Request, env: Env, now: number): Promise<Response> {
  await rateLimit(env, `challenge:${clientIp(request)}`, 60, MINUTE, now);
  const o = obj(await readJson(request, 4096));
  const accountId = bytes(o, "account_id", 16);
  const purpose = str(o, "purpose", 1, 16);
  if (!PURPOSES.has(purpose)) throw new ApiError(400, "invalid_request");
  if (purpose === "stepup") {
    const s = await requireSession(request, env, ["full"], now);
    if (!equal(s.accountId, accountId)) throw new ApiError(403, "forbidden");
  }
  // Issued for any account id, existing or not, so this endpoint does not reveal accounts.
  return json(await issueChallenge(env, accountId, purpose, now));
}

function insertDevice(env: Env, accountId: Uint8Array, d: DeviceInfo, via: string, now: number): D1PreparedStatement {
  return env.DB.prepare(
    "INSERT INTO devices (device_id, account_id, device_pk, name, platform, client_version, enrolled_via, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).bind(d.deviceId, accountId, d.devicePk, d.name, d.platform, d.clientVersion, via, now, now);
}

export async function createAccount(request: Request, env: Env, now: number): Promise<Response> {
  await rateLimit(env, `create:${clientIp(request)}`, 10, 60 * MINUTE, now);
  const req = obj(await readJson(request, 64 * 1024));
  const payloadBytes = bytes(req, "payload", undefined, 32 * 1024);
  const sigAccount = bytes(req, "sig_account", 64);
  const sigDevice = bytes(req, "sig_device", 64);
  const p = payloadJson(payloadBytes);
  const accountId = bytes(p, "account_id", 16);
  const email = normalizeEmail(str(p, "email", 3, 254));
  const kdfSalt = bytes(p, "kdf_salt", 16);
  const kdfParams = bytes(p, "kdf_params", 13);
  const authPk = bytes(p, "auth_pk", 32);
  const rauthPk = bytes(p, "rauth_pk", 32);
  const unlockEnv = bytes(p, "unlock_env", undefined, 1024);
  const recoveryEnv = bytes(p, "recovery_env", undefined, 1024);
  const vmkId = bytes(p, "vmk_id", 16);
  const device = deviceInfo(p["device"]);
  if (!kdfParamsOk(kdfParams) || !containerOk(unlockEnv, [Kind.UnlockEnvelope], vmkId) || !containerOk(recoveryEnv, [Kind.RecoveryEnvelope], vmkId)) {
    throw new ApiError(400, "invalid_request");
  }
  const msg = messages.create(accountId, await sha256(payloadBytes));
  if (!(await verifyEd25519(authPk, msg, sigAccount)) || !(await verifyEd25519(device.devicePk, msg, sigDevice))) {
    throw new ApiError(401, "unauthorized");
  }
  if ((await loadAccountByEmail(env, email)) !== null) throw new ApiError(409, "email_taken");
  if ((await loadAccount(env, accountId)) !== null) throw new ApiError(409, "conflict");
  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO accounts (account_id, email, kdf_salt, kdf_params, auth_pk, rauth_pk, unlock_env, recovery_env, vmk_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(accountId, email, kdfSalt, kdfParams, authPk, rauthPk, unlockEnv, recoveryEnv, vmkId, now, now),
      insertDevice(env, accountId, device, "create", now),
    ]);
  } catch {
    throw new ApiError(409, "conflict");
  }
  return json(await createSession(env, accountId, device.deviceId, "full", now), 201);
}

/** Registers or checks a device during login/recovery. */
async function enrollDevice(env: Env, accountId: Uint8Array, d: DeviceInfo, via: string, now: number): Promise<D1PreparedStatement[]> {
  const row = await env.DB.prepare("SELECT account_id, device_pk, revoked_at FROM devices WHERE device_id = ?")
    .bind(d.deviceId)
    .first<{ account_id: unknown; device_pk: unknown; revoked_at: number | null }>();
  if (row !== null) {
    if (!equal(blob(row.account_id), accountId) || !equal(blob(row.device_pk), d.devicePk)) throw new ApiError(401, "unauthorized");
    if (row.revoked_at !== null) throw new ApiError(401, "device_revoked");
    return [env.DB.prepare("UPDATE devices SET last_seen_at = ?, client_version = ? WHERE device_id = ?").bind(now, d.clientVersion, d.deviceId)];
  }
  if ((await activeDeviceCount(env, accountId)) >= MAX_ACTIVE_DEVICES) throw new ApiError(409, "too_many_devices");
  return [insertDevice(env, accountId, d, via, now), ...eventStatements(env, accountId, "device_enrolled", d.deviceId, now)];
}

export async function login(request: Request, env: Env, now: number): Promise<Response> {
  const o = obj(await readJson(request, 8192));
  const accountId = bytes(o, "account_id", 16);
  await rateLimit(env, `login-ip:${clientIp(request)}`, 20, MINUTE, now);
  await rateLimit(env, `login-acct:${encode(accountId)}`, 10, MINUTE, now);
  const nonce = await consumeChallenge(env, bytes(o, "challenge_id", 16), accountId, "login", now);
  const device = deviceInfo(o["device"]);
  const a = await loadAccount(env, accountId);
  const msg = messages.login(accountId, nonce, device.deviceId, device.devicePk, env.API_ORIGIN);
  const okAccount = a !== null && (await verifyEd25519(a.authPk, msg, bytes(o, "sig_account", 64)));
  const okDevice = await verifyEd25519(device.devicePk, msg, bytes(o, "sig_device", 64));
  if (a === null || !okAccount || !okDevice) throw new ApiError(401, "unauthorized");
  await env.DB.batch(await enrollDevice(env, accountId, device, "login", now));
  return json(await createSession(env, accountId, device.deviceId, "full", now));
}

export async function refresh(request: Request, env: Env, now: number): Promise<Response> {
  const o = obj(await readJson(request, 4096));
  const accountId = bytes(o, "account_id", 16);
  const deviceId = bytes(o, "device_id", 16);
  await rateLimit(env, `refresh:${encode(deviceId)}`, 30, MINUTE, now);
  const nonce = await consumeChallenge(env, bytes(o, "challenge_id", 16), accountId, "refresh", now);
  const row = await env.DB.prepare("SELECT account_id, device_pk, revoked_at FROM devices WHERE device_id = ?")
    .bind(deviceId)
    .first<{ account_id: unknown; device_pk: unknown; revoked_at: number | null }>();
  if (row === null || !equal(blob(row.account_id), accountId)) throw new ApiError(401, "unauthorized");
  if (row.revoked_at !== null) throw new ApiError(401, "device_revoked");
  if (!(await verifyEd25519(blob(row.device_pk), messages.refresh(accountId, nonce, deviceId), bytes(o, "sig_device", 64)))) {
    throw new ApiError(401, "unauthorized");
  }
  return json(await createSession(env, accountId, deviceId, "full", now));
}

export async function recoveryLogin(request: Request, env: Env, now: number): Promise<Response> {
  const o = obj(await readJson(request, 8192));
  const accountId = bytes(o, "account_id", 16);
  await rateLimit(env, `recovery-ip:${clientIp(request)}`, 10, MINUTE, now);
  await rateLimit(env, `recovery-acct:${encode(accountId)}`, 5, MINUTE, now);
  const nonce = await consumeChallenge(env, bytes(o, "challenge_id", 16), accountId, "recovery", now);
  const device = deviceInfo(o["device"]);
  const a = await loadAccount(env, accountId);
  const msg = messages.recovery(accountId, nonce, device.devicePk, env.API_ORIGIN);
  const okRecovery = a !== null && (await verifyEd25519(a.rauthPk, msg, bytes(o, "sig_recovery", 64)));
  const okDevice = await verifyEd25519(device.devicePk, msg, bytes(o, "sig_device", 64));
  if (a === null || !okRecovery || !okDevice) throw new ApiError(401, "unauthorized");
  await env.DB.batch(await enrollDevice(env, accountId, device, "recovery", now));
  const session = await createSession(env, accountId, device.deviceId, "recovery", now);
  return json({ session, recovery_env: encode(a.recoveryEnv), vmk_id: encode(a.vmkId) });
}

export async function logout(request: Request, env: Env, now: number): Promise<Response> {
  const s = await requireSession(request, env, ["full", "recovery"], now);
  await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(s.tokenHash).run();
  return empty();
}
