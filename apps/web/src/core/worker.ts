/// <reference lib="webworker" />
/* eslint-disable @typescript-eslint/require-await -- every handler is async so the RPC table has one shape */
/**
 * The core worker (D-17, ADR 0013): owns the WASM `Core` (all vault keys), the non-extractable
 * WebCrypto device key and local wrap key (crypto §8.1), the API session and the sync loop
 * (sync.md §10). The UI thread only ever receives display data.
 */
import init, { Core } from "../wasm/wasm_bindings.js";
import { decode, encode } from "./b64";
import { idb } from "./idb";
import type { AppState, Method, Methods, Notice, Request, Response, Settings, SyncStatus } from "./protocol";

declare const self: DedicatedWorkerGlobalScope;

const API = (import.meta.env.VITE_API_ORIGIN as string | undefined) ?? "http://localhost:8787";
const CLIENT = "web/0.1.0";
const SYNC_INTERVAL_MS = 60_000;

interface Config {
  email: string;
  accountId: string;
  deviceId: string;
  deviceName: string;
}

class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

let core: Core | null = null;
let config: Config | null = null;
let token: string | null = null;
let recoveryToken: string | null = null;
let syncTimer: ReturnType<typeof setInterval> | null = null;
let syncing = false;
let keysChanged = false;
let state: AppState = { phase: "loading", email: null, deviceName: null, apiOrigin: API, lockReason: null };
let syncStatus: SyncStatus = { pending: 0, conflicts: 0, quarantined: 0, failed: 0, rollback: false, unread_events: 0, state: "synced", lastSyncAt: null };

const notify = (n: Notice) => {
  self.postMessage(n);
};

function setState(patch: Partial<AppState>): AppState {
  state = { ...state, ...patch };
  notify({ notice: "state", state });
  return state;
}

// ------------------------------------------------------------------ keys (WebCrypto, non-extractable)

async function deviceKeys(): Promise<CryptoKeyPair> {
  const existing = await idb.get<CryptoKeyPair>("keys", "device");
  if (existing) return existing;
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]));
  await idb.put("keys", "device", pair);
  return pair;
}

async function signWithDevice(message: Uint8Array): Promise<string> {
  const data = new Uint8Array(message);
  const pair = await deviceKeys();
  return encode(new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, data)));
}

async function deviceInfo(name: string, deviceId: string) {
  const pair = await deviceKeys();
  const pk = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)));
  return { device_id: deviceId, device_pk: encode(pk), name, platform: "web", client_version: "0.1.0" };
}

async function localWrapKey(): Promise<CryptoKey> {
  const existing = await idb.get<CryptoKey>("keys", "local_wrap");
  if (existing) return existing;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await idb.put("keys", "local_wrap", key);
  return key;
}

/** Stores the Secret Key as container kind 0x06 (crypto §6.1, §8.1). */
async function wrapSecretKey(c: Core, accountId: string, ask: Uint8Array): Promise<void> {
  const ctx = JSON.parse(c.local_wrap_context(accountId)) as { header: string; aad: string };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: decode(ctx.aad) }, await localWrapKey(), new Uint8Array(ask)));
  const header = decode(ctx.header);
  const out = new Uint8Array(header.length + iv.length + ct.length);
  out.set(header, 0);
  out.set(iv, header.length);
  out.set(ct, header.length + iv.length);
  await idb.put("kv", "wrapped_ask", out);
  ask.fill(0);
}

async function unwrapSecretKey(c: Core, accountId: string): Promise<Uint8Array> {
  const stored = await idb.get<Uint8Array>("kv", "wrapped_ask");
  const blob = stored === undefined ? undefined : new Uint8Array(stored);
  if (!blob) throw new ApiError(0, "secret_key_missing");
  const ctx = JSON.parse(c.local_wrap_context(accountId)) as { header: string; aad: string };
  const header = decode(ctx.header);
  if (blob.length < header.length + 12 + 16 || !header.every((b, i) => blob[i] === b)) throw new ApiError(0, "secret_key_missing");
  const iv = blob.slice(header.length, header.length + 12);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: decode(ctx.aad) }, await localWrapKey(), blob.slice(header.length + 12)));
  } catch {
    throw new ApiError(0, "secret_key_missing");
  }
}

// ------------------------------------------------------------------ API

async function api<T>(path: string, body?: unknown, auth: "full" | "recovery" | "none" = "full", retry = true): Promise<T> {
  const headers: Record<string, string> = { "content-type": "application/json", "urkey-client": CLIENT };
  const t = auth === "full" ? token : auth === "recovery" ? recoveryToken : null;
  if (t !== null) headers["authorization"] = `Bearer ${t}`;
  let res: globalThis.Response;
  try {
    res = await fetch(`${API}${path}`, { method: body === undefined ? "GET" : "POST", headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  } catch {
    throw new ApiError(0, "network");
  }
  if (res.ok) return (res.status === 204 ? null : await res.json()) as T;
  const code = ((await res.json().catch(() => ({}))) as { error?: string }).error ?? "unknown";
  if (res.status === 401 && code === "device_revoked") {
    await onRevoked();
  }
  if (res.status === 401 && auth === "full" && retry && code === "unauthorized" && config !== null) {
    token = null;
    await ensureSession();
    return api<T>(path, body, auth, false);
  }
  throw new ApiError(res.status, code);
}

async function ensureSession(): Promise<void> {
  if (token !== null || config === null) return;
  const ch = await api<{ challenge_id: string; nonce: string }>("/v1/auth/challenge", { account_id: config.accountId, purpose: "refresh" }, "none");
  const message = Core.refresh_message(config.accountId, ch.nonce, config.deviceId);
  const sig = await signWithDevice(message);
  const s = await api<{ session_token: string }>(
    "/v1/auth/refresh",
    { account_id: config.accountId, device_id: config.deviceId, challenge_id: ch.challenge_id, sig_device: sig },
    "none",
  );
  token = s.session_token;
}

async function stepup(path: string, operation: string, payloadJson: string): Promise<{ account: Record<string, unknown> }> {
  if (core === null || config === null) throw new ApiError(0, "locked");
  await ensureSession();
  const ch = await api<{ challenge_id: string; nonce: string }>("/v1/auth/challenge", { account_id: config.accountId, purpose: "stepup" });
  const req = JSON.parse(core.stepup_request(operation, payloadJson, ch.challenge_id, ch.nonce)) as unknown;
  return api(path, req);
}

async function fetchAccount(): Promise<{ account: Record<string, unknown>; devices: unknown[] }> {
  await ensureSession();
  return api("/v1/account");
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * A step-up key change whose outcome must never be lost (R-REC-3: there is never a moment when
 * neither the old nor the new secret works).
 *
 * A 4xx is a definite refusal: nothing changed. A network error or 5xx is ambiguous, because the
 * server may have applied the change before the response was lost. In that case the account is
 * re-read a few times and `applied` compares it with the payload we sent. The result is
 * `"unknown"` only if the server can't be reached at all; the caller must then keep both the
 * old and the new secret.
 */
async function keyChange(
  path: string,
  operation: string,
  payloadJson: string,
  applied: (account: Record<string, unknown>) => boolean,
): Promise<{ account: Record<string, unknown> } | "unknown"> {
  try {
    return await stepup(path, operation, payloadJson);
  } catch (e) {
    if (!(e instanceof ApiError) || (e.status >= 400 && e.status < 500)) throw e;
    let reached = false;
    for (const wait of [0, 1000, 3000]) {
      await sleep(wait);
      try {
        const a = await fetchAccount();
        reached = true;
        if (applied(a.account)) return { account: a.account };
      } catch {
        /* still unreachable */
      }
    }
    if (reached) throw e; // the server answered and does not have the change: nothing happened
    return "unknown";
  }
}

const field = (o: unknown, k: string): unknown => (typeof o === "object" && o !== null ? (o as Record<string, unknown>)[k] : undefined);

// ------------------------------------------------------------------ persistence

async function saveSync(): Promise<void> {
  if (core !== null && !keysChanged) await idb.put("kv", "sync", core.export_sync());
}

async function refreshStatus(patch: Partial<SyncStatus> = {}): Promise<SyncStatus> {
  if (core !== null) {
    try {
      syncStatus = { ...syncStatus, ...(JSON.parse(core.status()) as Partial<SyncStatus>), ...patch };
    } catch {
      syncStatus = { ...syncStatus, ...patch };
    }
  }
  notify({ notice: "sync", status: syncStatus });
  return syncStatus;
}

// ------------------------------------------------------------------ sync loop

async function pullAll(): Promise<"ok" | "keys_changed"> {
  if (core === null) return "ok";
  let accountRefreshNeeded = false;
  for (;;) {
    let text: string;
    try {
      text = JSON.stringify(await api(`/v1/sync/changes?since=${String(core.cursor())}&limit=500`));
    } catch (e) {
      if (e instanceof ApiError && e.status === 410) {
        core.begin_resync();
        continue;
      }
      throw e;
    }
    const r = JSON.parse(core.apply_changes(text)) as { outcome: string; events?: number; done?: boolean; rollback?: boolean };
    if (r.outcome === "keyset_changed") return "keys_changed";
    if ((r.events ?? 0) > 0) accountRefreshNeeded = true;
    if (r.done === true || r.rollback === true) break;
  }
  if (accountRefreshNeeded) {
    // Password, Secret Key or Recovery Key may have changed elsewhere (sync.md §8.2).
    const a = await fetchAccount();
    await idb.put("kv", "account", a.account);
    core.set_account(JSON.stringify(a.account));
  }
  return "ok";
}

async function syncNow(): Promise<SyncStatus> {
  if (core === null || !core.is_unlocked() || syncing || keysChanged) return refreshStatus();
  syncing = true;
  await refreshStatus({ state: "syncing" });
  try {
    const run = async () => {
      await ensureSession();
      if ((await pullAll()) === "keys_changed") return onKeysChanged();
      for (let i = 0; i < 50; i++) {
        const reqText = core?.prepare_push() ?? "";
        if (reqText === "") break;
        const resp = await api("/v1/sync/push", JSON.parse(reqText) as unknown);
        const rep = JSON.parse(core?.apply_push(reqText, JSON.stringify(resp)) ?? "{}") as { keyset_changed?: boolean };
        await saveSync();
        if (rep.keyset_changed === true) return onKeysChanged();
      }
      if ((await pullAll()) === "keys_changed") return onKeysChanged();
      await saveSync();
    };
    if ("locks" in navigator) await navigator.locks.request("urkey-sync", run);
    else await run();
    notify({ notice: "items_changed" });
    return await refreshStatus({ state: "synced", lastSyncAt: Date.now() });
  } catch (e) {
    const code = e instanceof ApiError ? e.code : "error";
    return await refreshStatus({ state: code === "network" ? "offline" : code === "update_required" ? "update_required" : "error" });
  } finally {
    syncing = false;
  }
}

async function onKeysChanged(): Promise<void> {
  // Another device changed the vault key. Lock; the next unlock re-derives the old key to keep
  // unsynced edits, then switches to the new key (sync.md §8.4).
  keysChanged = true;
  const a = await fetchAccount();
  await idb.put("kv", "pending_account", a.account);
  stopSync();
  core?.lock();
  setState({ phase: "locked", lockReason: "keys_changed" });
}

async function onRevoked(): Promise<void> {
  stopSync();
  core?.lock();
  token = null;
  setState({ phase: "revoked" });
}

function startSync(): void {
  stopSync();
  syncTimer = setInterval(() => void syncNow(), SYNC_INTERVAL_MS);
  void syncNow();
}

function stopSync(): void {
  if (syncTimer !== null) clearInterval(syncTimer);
  syncTimer = null;
}

let changeTimer: ReturnType<typeof setTimeout> | null = null;
function syncSoon(): void {
  if (changeTimer !== null) clearTimeout(changeTimer);
  changeTimer = setTimeout(() => void syncNow(), 2000);
}

// ------------------------------------------------------------------ handlers

async function newDeviceId(): Promise<string> {
  const existing = await idb.get<string>("kv", "device_id");
  if (existing !== undefined) return existing;
  const id = encode(crypto.getRandomValues(new Uint8Array(16)));
  await idb.put("kv", "device_id", id);
  return id;
}

const need = (): Core => {
  if (core === null || !core.is_unlocked()) throw new ApiError(0, "locked");
  return core;
};

async function afterSignIn(c: Core, cfg: Config, account: Record<string, unknown>, ask: Uint8Array): Promise<void> {
  core = c;
  config = cfg;
  await idb.put("kv", "config", cfg);
  await idb.put("kv", "account", account);
  await wrapSecretKey(c, cfg.accountId, ask);
  await saveSync();
  setState({ phase: "unlocked", email: cfg.email, deviceName: cfg.deviceName, lockReason: null });
  startSync();
}

const handlers: { [M in Method]: (p: Methods[M]["params"]) => Promise<Methods[M]["result"]> } = {
  async init() {
    await init();
    config = (await idb.get<Config>("kv", "config")) ?? null;
    if (config === null) return setState({ phase: "welcome" });
    const account = await idb.get<Record<string, unknown>>("kv", "account");
    core = new Core(config.deviceId);
    if (account !== undefined) core.set_account(JSON.stringify(account));
    core.load_sync((await idb.get<string>("kv", "sync")) ?? "");
    keysChanged = (await idb.get("kv", "pending_account")) !== undefined;
    return setState({ phase: "locked", email: config.email, deviceName: config.deviceName, lockReason: keysChanged ? "keys_changed" : null });
  },

  async createAccount({ email, password, deviceName }) {
    const deviceId = await newDeviceId();
    const c = new Core(deviceId);
    const out = JSON.parse(c.create_account(email, password, JSON.stringify(await deviceInfo(deviceName, deviceId)), false)) as {
      request: Record<string, unknown>;
      message: string;
      account_id: string;
      secret_key: string;
      secret_key_text: string;
      recovery_key_text: string;
    };
    const sig = await signWithDevice(decode(out.message));
    const s = await api<{ session_token: string }>("/v1/accounts", { ...out.request, sig_device: sig }, "none");
    token = s.session_token;
    config = { email: email.trim().toLowerCase(), accountId: out.account_id, deviceId, deviceName };
    const a = await fetchAccount();
    c.set_account(JSON.stringify(a.account));
    await afterSignIn(c, config, a.account, decode(out.secret_key));
    return { secretKeyText: out.secret_key_text, recoveryKeyText: out.recovery_key_text };
  },

  async signIn({ email, secretKey, password, deviceName }) {
    const deviceId = await newDeviceId();
    const pre = await api<Record<string, string>>("/v1/auth/prelogin", { email }, "none");
    const accountId = pre["account_id"] ?? "";
    const ch = await api<{ challenge_id: string; nonce: string }>("/v1/auth/challenge", { account_id: accountId, purpose: "login" }, "none");
    const c = new Core(deviceId);
    const prep = JSON.parse(
      c.prepare_login(JSON.stringify(pre), password, secretKey, ch.challenge_id, ch.nonce, JSON.stringify(await deviceInfo(deviceName, deviceId)), API),
    ) as { request: Record<string, unknown>; message: string; secret_key: string };
    const sig = await signWithDevice(decode(prep.message));
    const s = await api<{ session_token: string }>("/v1/auth/login", { ...prep.request, sig_device: sig }, "none");
    token = s.session_token;
    config = { email: email.trim().toLowerCase(), accountId, deviceId, deviceName };
    const a = await fetchAccount();
    c.set_account(JSON.stringify(a.account));
    const ask = decode(prep.secret_key);
    c.unlock(password, ask);
    await afterSignIn(c, config, a.account, ask);
    return state;
  },

  async unlock({ password }) {
    if (core === null || config === null) throw new ApiError(0, "no_account");
    const ask = await unwrapSecretKey(core, config.accountId);
    try {
      const pending = await idb.get<Record<string, unknown>>("kv", "pending_account");
      if (pending !== undefined) {
        const old = await idb.get<Record<string, unknown>>("kv", "account");
        core.unlock_with_rotation(password, ask, JSON.stringify(old), JSON.stringify(pending));
        keysChanged = false;
        await ensureSession();
        await pullAll();
        core.finish_rotation();
        await idb.put("kv", "account", pending);
        await idb.del("kv", "pending_account");
        await saveSync();
      } else {
        core.unlock(password, ask);
      }
    } finally {
      ask.fill(0);
    }
    setState({ phase: "unlocked", lockReason: null });
    startSync();
    return state;
  },

  async lock({ reason }) {
    stopSync();
    await saveSync();
    core?.lock();
    return setState({ phase: config === null ? "welcome" : "locked", lockReason: reason });
  },

  sync: () => syncNow(),
  status: () => refreshStatus(),
  listItems: async () => JSON.parse(need().list_items()) as Methods["listItems"]["result"],
  getItem: async ({ id }) => JSON.parse(need().get_item(id)) as Methods["getItem"]["result"],
  getItemForEdit: async ({ id }) => JSON.parse(need().get_item_for_edit(id)) as Methods["getItemForEdit"]["result"],
  reveal: async ({ id, field }) => need().reveal_field(id, field),

  async saveItem({ id, item }) {
    const newId = need().save_item(id ?? "", JSON.stringify(item), new Date().toISOString());
    await saveSync();
    notify({ notice: "items_changed" });
    syncSoon();
    return newId;
  },

  async deleteItem({ id }) {
    need().delete_item(id);
    await saveSync();
    notify({ notice: "items_changed" });
    syncSoon();
    return null;
  },

  totp: async ({ id }) => JSON.parse(need().totp(id, Date.now() / 1000)) as Methods["totp"]["result"],
  totpPreview: async ({ config: cfg }) => JSON.parse(Core.totp_preview(JSON.stringify(cfg), Date.now() / 1000)) as Methods["totpPreview"]["result"],
  parseOtpauth: async ({ uri }) => JSON.parse(Core.parse_otpauth(uri)) as Record<string, unknown>,
  generatePassword: async (o) => JSON.parse(Core.generate_password(JSON.stringify(o))) as Methods["generatePassword"]["result"],
  generatePassphrase: async (o) => JSON.parse(Core.generate_passphrase(JSON.stringify(o))) as Methods["generatePassphrase"]["result"],
  importSsh: async ({ pem, passphrase }) => JSON.parse(Core.import_ssh(pem, passphrase)) as Record<string, unknown>,
  conflicts: async () => JSON.parse(need().conflicts()) as Methods["conflicts"]["result"],
  openConflict: async ({ id }) => JSON.parse(need().open_conflict(id)) as Methods["openConflict"]["result"],

  async resolveConflict({ id, choice }) {
    need().resolve_conflict(id, choice);
    await saveSync();
    notify({ notice: "items_changed" });
    syncSoon();
    return null;
  },

  // Encrypted export and restore (ADR 0017). The file holds only ciphertext.
  exportVault: async () => need().export_vault(Date.now()),

  async restoreExport({ json, password, secretKey }) {
    const added = need().restore_export(json, password, secretKey, new Date().toISOString());
    await saveSync();
    notify({ notice: "items_changed" });
    syncSoon();
    return added;
  },

  events: async () => JSON.parse(need().events()) as Methods["events"]["result"],

  async ackEvent({ seq }) {
    need().ack_event(seq);
    await saveSync();
    await refreshStatus();
    return null;
  },

  async clearRollback() {
    need().clear_rollback_warning();
    await saveSync();
    await refreshStatus();
    return null;
  },

  async account() {
    const a = await fetchAccount();
    return { account: a.account, devices: a.devices as Methods["account"]["result"]["devices"], thisDevice: config?.deviceId ?? "" };
  },

  async changePassword({ newPassword }) {
    const c = need();
    const payload = c.prepare_password_change(newPassword);
    const env = field(JSON.parse(payload), "unlock_env");
    try {
      const r = await keyChange("/v1/account/unlock-keys", "change_unlock_keys", payload, (a) => a["unlock_env"] === env);
      if (r === "unknown") {
        c.discard_change();
        // The user knows both passwords; after reconnecting, the vault asks for whichever is live.
        throw new ApiError(0, "unconfirmed");
      }
      c.commit_change(JSON.stringify(r.account));
      await idb.put("kv", "account", r.account);
    } catch (e) {
      c.discard_change();
      throw e;
    }
    return null;
  },

  async rotateSecretKey({ password }) {
    const c = need();
    const out = JSON.parse(c.prepare_secret_key_rotation(password)) as { payload: unknown; secret_key_text: string };
    const env = field(out.payload, "unlock_env");
    try {
      const r = await keyChange("/v1/account/unlock-keys", "change_unlock_keys", JSON.stringify(out.payload), (a) => a["unlock_env"] === env);
      if (r === "unknown") {
        // Show the new Secret Key anyway: the user keeps both until the change is confirmed.
        c.discard_change();
        return { secretKeyText: out.secret_key_text, confirmed: false };
      }
      const ask = c.commit_change(JSON.stringify(r.account));
      await idb.put("kv", "account", r.account);
      if (config !== null && ask !== "") await wrapSecretKey(c, config.accountId, decode(ask));
    } catch (e) {
      c.discard_change();
      throw e;
    }
    return { secretKeyText: out.secret_key_text, confirmed: true };
  },

  async replaceRecoveryKey() {
    const c = need();
    const out = JSON.parse(c.prepare_recovery_key()) as { payload: unknown; recovery_key_text: string };
    const rauth = field(out.payload, "rauth_pk");
    try {
      const r = await keyChange("/v1/account/recovery-key", "replace_recovery_key", JSON.stringify(out.payload), (a) => a["rauth_pk"] === rauth);
      if (r === "unknown") {
        c.discard_change();
        return { recoveryKeyText: out.recovery_key_text, confirmed: false };
      }
      c.commit_change(JSON.stringify(r.account));
    } catch (e) {
      c.discard_change();
      throw e;
    }
    return { recoveryKeyText: out.recovery_key_text, confirmed: true };
  },

  async rotateVaultKey({ password }) {
    const c = need();
    await syncNow();
    const a = await fetchAccount();
    const expected = Number(a.account["vault_seq"]);
    const out = JSON.parse(c.prepare_rekey(password, expected)) as { payload: unknown; recovery_key_text: string };
    const vmk = field(out.payload, "vmk_id");
    stopSync();
    try {
      const r = await keyChange("/v1/account/rekey", "rekey", JSON.stringify(out.payload), (a) => a["vmk_id"] === vmk);
      if (r === "unknown") {
        // If the server did apply it, the next sync sees the new vault key and rebases (sync.md §8.4).
        c.discard_change();
        return { recoveryKeyText: out.recovery_key_text, confirmed: false };
      }
      c.commit_change(JSON.stringify(r.account));
      await idb.put("kv", "account", r.account);
      await pullAll();
      await saveSync();
    } catch (e) {
      c.discard_change();
      throw e;
    } finally {
      startSync();
    }
    notify({ notice: "items_changed" });
    return { recoveryKeyText: out.recovery_key_text, confirmed: true };
  },

  async revokeDevice({ deviceId }) {
    await stepup("/v1/devices/revoke", "revoke_device", JSON.stringify({ device_id: deviceId }));
    return null;
  },

  async renameDevice({ deviceId, name }) {
    await ensureSession();
    await api("/v1/devices/rename", { device_id: deviceId, name });
    return null;
  },

  async recoveryStart({ email, recoveryKey, deviceName }) {
    const deviceId = await newDeviceId();
    const pre = await api<Record<string, string>>("/v1/auth/prelogin", { email }, "none");
    const accountId = pre["account_id"] ?? "";
    const ch = await api<{ challenge_id: string; nonce: string }>("/v1/auth/challenge", { account_id: accountId, purpose: "recovery" }, "none");
    const c = new Core(deviceId);
    const prep = JSON.parse(
      c.prepare_recovery_login(accountId, ch.challenge_id, ch.nonce, recoveryKey, JSON.stringify(await deviceInfo(deviceName, deviceId)), API),
    ) as { request: Record<string, unknown>; message: string };
    const sig = await signWithDevice(decode(prep.message));
    const r = await api<{ session: { session_token: string }; recovery_env: string; vmk_id: string }>(
      "/v1/auth/recovery",
      { ...prep.request, sig_device: sig },
      "none",
    );
    recoveryToken = r.session.session_token;
    c.open_recovery(accountId, r.vmk_id, r.recovery_env, recoveryKey);
    core = c;
    config = { email: email.trim().toLowerCase(), accountId, deviceId, deviceName };
    return null;
  },

  async recoveryFinish({ newPassword }) {
    if (core === null || config === null || recoveryToken === null) throw new ApiError(0, "no_recovery");
    const out = JSON.parse(core.prepare_recovery_setup(newPassword)) as { payload: unknown; secret_key_text: string; recovery_key_text: string };
    const s = await api<{ session_token: string }>("/v1/account/recover", out.payload, "recovery");
    recoveryToken = null;
    token = s.session_token;
    const a = await fetchAccount();
    const ask = core.commit_change(JSON.stringify(a.account));
    core.load_sync("");
    await afterSignIn(core, config, a.account, decode(ask));
    return { secretKeyText: out.secret_key_text, recoveryKeyText: out.recovery_key_text };
  },

  async getSettings() {
    return (await idb.get<Settings>("kv", "settings")) ?? { autoLockMinutes: 10, theme: "system" };
  },

  async setSettings(s) {
    await idb.put("kv", "settings", s);
    return null;
  },

  secretKeyText: async () => need().secret_key_text(),

  async forget() {
    stopSync();
    try {
      if (token !== null) await api("/v1/auth/logout", {});
    } catch {
      /* best effort */
    }
    core?.lock();
    core = null;
    config = null;
    token = null;
    await idb.wipe();
    return setState({ phase: "welcome", email: null, deviceName: null, lockReason: null });
  },
};

// Errors crossing to the UI are short codes only; never messages that could contain data.
function errorCode(e: unknown): string {
  if (e instanceof ApiError) return e.code;
  if (typeof e === "string") return e.startsWith("invalid: ") ? e : e.split(":")[0] ?? "error";
  return "error";
}

self.onmessage = async (ev: MessageEvent<Request>) => {
  const { id, method, params } = ev.data;
  let reply: Response;
  try {
    const handler = handlers[method] as (p: unknown) => Promise<unknown>;
    reply = { id, ok: true, result: await handler(params) };
  } catch (e) {
    reply = { id, ok: false, error: errorCode(e) };
  }
  self.postMessage(reply);
};
