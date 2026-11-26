//! WebAssembly API for the web app (`docs/architecture/overview.md` §5, D-17, ADR 0013).
//!
//! One [`Core`] lives in the app's dedicated Web Worker. It holds every key (VMK, item keys,
//! account auth key, Secret Key) and the sync state; JavaScript receives display data and the
//! exact bytes it must sign (with the non-extractable WebCrypto device key) or store. Concealed
//! values are withheld from item display data and released one at a time by
//! [`Core::reveal_field`] for reveal/copy. Inputs and outputs are JSON strings or byte arrays.
//! Errors are short codes (`locked`, `decrypt`, `invalid: …`), never secrets.

use serde::Serialize;
use serde_json::{Value, json};
use sync_core::vault_core::account::{
    self, NewAccount, RecoverySetup, Rotation, UnlockKeysChange, Unlocked,
};
use sync_core::vault_core::b64::{self, B64};
use sync_core::vault_core::crypto_core::container::Context;
use sync_core::vault_core::crypto_core::encoding;
use sync_core::vault_core::crypto_core::ids::{AccountId, DeviceId, ItemId, KdfSalt, VmkId};
use sync_core::vault_core::crypto_core::kdf::KdfParams;
use sync_core::vault_core::crypto_core::secret::{AccountSecretKey, RecoveryKey};
use sync_core::vault_core::crypto_core::sign;
use sync_core::vault_core::generator::{self, PassphraseOptions, PasswordOptions};
use sync_core::vault_core::item::{Content, Item, TotpConfig};
use sync_core::vault_core::record::{self, VaultKey};
use sync_core::vault_core::search;
use sync_core::vault_core::totp::{self, Totp};
use sync_core::vault_core::wire::{
    AccountState, ChangesResponse, DeviceInfo, PreloginResponse, PushRequest, PushResponse,
    SignedRequest,
};
use sync_core::vault_core::{VaultError, ssh};
use sync_core::{PullOutcome, Resolution, RotationSnapshot, SyncState, Write};
use wasm_bindgen::prelude::*;

type JsResult<T> = Result<T, JsValue>;

fn err(code: &str) -> JsValue {
    JsValue::from_str(code)
}

fn verr(e: VaultError) -> JsValue {
    match e {
        VaultError::Crypto(sync_core::vault_core::crypto_core::CryptoError::Decrypt) => {
            err("decrypt")
        }
        VaultError::UnsupportedSchema => err("read_only"),
        other => err(&format!("invalid: {other}")),
    }
}

fn to_json<T: Serialize>(v: &T) -> JsResult<String> {
    serde_json::to_string(v).map_err(|_| err("invalid: serialization"))
}

fn from_json<T: serde::de::DeserializeOwned>(s: &str) -> JsResult<T> {
    serde_json::from_str(s).map_err(|_| err("invalid: malformed input"))
}

fn bytes(s: &str) -> JsResult<Vec<u8>> {
    b64::decode(s).map_err(|_| err("invalid: base64"))
}

fn arr32(s: &str) -> JsResult<[u8; 32]> {
    bytes(s)?.try_into().map_err(|_| err("invalid: length"))
}

/// Version of the urkey core compiled into this WASM module.
#[wasm_bindgen(js_name = coreVersion)]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

enum PendingChange {
    Unlock(UnlockKeysChange),
    /// The new Recovery Key was shown once; nothing to keep after the server accepts.
    Recovery,
    Rekey(Rotation),
    Recover(RecoverySetup),
}

/// The vault core: all secret state for one account on this device.
#[wasm_bindgen]
pub struct Core {
    account: Option<AccountState>,
    secret_key: Option<AccountSecretKey>,
    unlocked: Option<Unlocked>,
    recovery_vault: Option<VaultKey>,
    sync: SyncState,
    device_id: String,
    pending: Option<PendingChange>,
    rotation: Option<RotationSnapshot>,
}

#[wasm_bindgen]
impl Core {
    /// `device_id` is this device's base64url id (stored by the app).
    #[wasm_bindgen(constructor)]
    pub fn new(device_id: &str) -> Core {
        Core {
            account: None,
            secret_key: None,
            unlocked: None,
            recovery_vault: None,
            sync: SyncState::default(),
            device_id: device_id.to_owned(),
            pending: None,
            rotation: None,
        }
    }

    // ---------------------------------------------------------------- state

    /// Sets the cached public account state (from `GET /v1/account`).
    pub fn set_account(&mut self, account_json: &str) -> JsResult<()> {
        self.account = Some(from_json(account_json)?);
        Ok(())
    }

    /// Loads persisted sync state (JSON) — ciphertext and public data only.
    pub fn load_sync(&mut self, json: &str) -> JsResult<()> {
        self.sync = if json.is_empty() {
            SyncState::default()
        } else {
            from_json(json)?
        };
        Ok(())
    }

    /// Exports sync state for IndexedDB.
    pub fn export_sync(&self) -> JsResult<String> {
        to_json(&self.sync)
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// Wipes every key from memory (R-ACC-5).
    pub fn lock(&mut self) {
        self.unlocked = None;
        self.secret_key = None;
        self.recovery_vault = None;
        self.pending = None;
        self.rotation = None;
    }

    fn vault(&self) -> JsResult<&VaultKey> {
        self.unlocked
            .as_ref()
            .map(|u| &u.vault)
            .ok_or_else(|| err("locked"))
    }

    fn account_id(&self) -> JsResult<AccountId> {
        let a = self
            .account
            .as_ref()
            .ok_or_else(|| err("invalid: no account"))?;
        AccountId::from_slice(&a.account_id.0).map_err(|_| err("invalid: account id"))
    }

    // ---------------------------------------------------------------- local Secret Key wrap

    /// Header (21 bytes) and AAD for wrapping the Secret Key with WebCrypto AES-GCM (crypto §8.1).
    pub fn local_wrap_context(&self, account_id: &str) -> JsResult<String> {
        let ctx = Context::LocalSecretKeyWrap {
            account_id: AccountId::from_slice(&bytes(account_id)?)
                .map_err(|_| err("invalid: account id"))?,
            device_id: DeviceId::from_slice(&bytes(&self.device_id)?)
                .map_err(|_| err("invalid: device id"))?,
        };
        to_json(&json!({ "header": b64::encode(&ctx.header()), "aad": b64::encode(&ctx.aad()) }))
    }

    // ---------------------------------------------------------------- account creation and login

    /// Creates an account (crypto §7.1). Returns the request (JS adds `sig_device` by signing
    /// `message` with the device key) and the Emergency Kit secrets to show once.
    pub fn create_account(
        &mut self,
        email: &str,
        password: &str,
        device_json: &str,
        fast_kdf: bool,
    ) -> JsResult<String> {
        let device: DeviceInfo = from_json(device_json)?;
        let params = if fast_kdf {
            KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1)
                .map_err(|_| err("invalid: params"))?
        } else {
            KdfParams::DEFAULT
        };
        let NewAccount {
            payload,
            secret_key,
            recovery_key,
            vault,
            auth,
        } = account::create_account(email, password, &device, params).map_err(verr)?;
        let payload_bytes = serde_json::to_vec(&payload).map_err(|_| err("invalid: payload"))?;
        let message = sign::create_message(&vault.account_id, &sign::sha256(&payload_bytes));
        let request = SignedRequest {
            payload: B64(payload_bytes),
            challenge_id: None,
            sig_account: B64(auth.sign(&message).to_vec()),
            sig_device: None,
            sig_new: None,
        };
        let out = json!({
            "request": request,
            "message": b64::encode(&message),
            "account_id": b64::encode(vault.account_id.as_bytes()),
            "secret_key": b64::encode(secret_key.expose_secret()),
            "secret_key_text": encoding::format_account_secret_key(&secret_key).as_str(),
            "recovery_key_text": encoding::format_recovery_key(&recovery_key).as_str(),
        });
        self.secret_key = Some(secret_key);
        self.unlocked = Some(Unlocked { vault, auth });
        to_json(&out)
    }

    /// Prepares a login on this device (crypto §7.4). JS signs `message` with the device key.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_login(
        &mut self,
        prelogin_json: &str,
        password: &str,
        secret_key_text: &str,
        challenge_id: &str,
        nonce: &str,
        device_json: &str,
        origin: &str,
    ) -> JsResult<String> {
        let pre: PreloginResponse = from_json(prelogin_json)?;
        let secret_key = encoding::parse_account_secret_key(secret_key_text)
            .map_err(|_| err("invalid: secret key"))?;
        let account_id =
            AccountId::from_slice(&pre.account_id.0).map_err(|_| err("invalid: account id"))?;
        let salt = KdfSalt::from_slice(&pre.kdf_salt.0).map_err(|_| err("invalid: salt"))?;
        let params = KdfParams::decode(&pre.kdf_params.0)
            .map_err(|_| err("invalid: kdf params rejected"))?;
        let auth = account::derive_auth(&account_id, &salt, &params, password, &secret_key)
            .map_err(verr)?;
        let device: DeviceInfo = from_json(device_json)?;
        let device_id =
            DeviceId::from_slice(&device.device_id.0).map_err(|_| err("invalid: device id"))?;
        let device_pk: [u8; 32] = device.device_pk.array().map_err(verr)?;
        let nonce = arr32(nonce)?;
        let message = sign::login_message(&account_id, &nonce, &device_id, &device_pk, origin);
        let request = json!({
            "account_id": b64::encode(account_id.as_bytes()),
            "challenge_id": challenge_id,
            "device": device,
            "sig_account": b64::encode(&auth.sign(&message)),
        });
        let out = json!({ "request": request, "message": b64::encode(&message), "secret_key": b64::encode(secret_key.expose_secret()) });
        to_json(&out)
    }

    /// The refresh message for the device key to sign (crypto §7.9).
    pub fn refresh_message(account_id: &str, nonce: &str, device_id: &str) -> JsResult<Vec<u8>> {
        let a =
            AccountId::from_slice(&bytes(account_id)?).map_err(|_| err("invalid: account id"))?;
        let d = DeviceId::from_slice(&bytes(device_id)?).map_err(|_| err("invalid: device id"))?;
        Ok(sign::refresh_message(&a, &arr32(nonce)?, &d))
    }

    /// Unlocks with the master password and the Secret Key bytes (from the local wrap).
    pub fn unlock(&mut self, password: &str, secret_key: &[u8]) -> JsResult<()> {
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| err("invalid: no account"))?;
        let material = account::material_from_wire(account).map_err(verr)?;
        let ask = AccountSecretKey::from_slice(secret_key).map_err(|_| err("decrypt"))?;
        let unlocked = account::unlock(&material, password, &ask).map_err(verr)?;
        self.unlocked = Some(unlocked);
        self.secret_key = Some(ask);
        Ok(())
    }

    /// Unlock after another device rotated the vault key (sync.md §8.4) without losing unsynced
    /// edits: opens the **old** envelope to snapshot pending edits, then unlocks with the new
    /// account state. Next: pull every page, then `finish_rotation()`.
    pub fn unlock_with_rotation(
        &mut self,
        password: &str,
        secret_key: &[u8],
        old_account_json: &str,
        new_account_json: &str,
    ) -> JsResult<()> {
        self.set_account(old_account_json)?;
        self.unlock(password, secret_key)?;
        self.begin_rotation()?;
        self.set_account(new_account_json)?;
        let rotation = self.rotation.take();
        let result = self.unlock(password, secret_key);
        self.rotation = rotation;
        result
    }

    /// Parses a typed Secret Key into its bytes (for the local wrap).
    pub fn parse_secret_key(text: &str) -> JsResult<Vec<u8>> {
        let k = encoding::parse_account_secret_key(text).map_err(|_| err("invalid: secret key"))?;
        Ok(k.expose_secret().to_vec())
    }

    /// The Secret Key in Emergency Kit format (Settings › Security, recovery.md §1).
    pub fn secret_key_text(&self) -> JsResult<String> {
        let k = self.secret_key.as_ref().ok_or_else(|| err("locked"))?;
        Ok(encoding::format_account_secret_key(k).to_string())
    }

    // ---------------------------------------------------------------- sync

    /// Applies one page of `GET /v1/sync/changes`. Returns `{outcome, …report}`.
    pub fn apply_changes(&mut self, json_text: &str) -> JsResult<String> {
        let resp: ChangesResponse = from_json(json_text)?;
        let vault = self
            .unlocked
            .as_ref()
            .map(|u| &u.vault)
            .ok_or_else(|| err("locked"))?;
        match sync_core::apply_changes(&mut self.sync, vault, &resp).map_err(verr)? {
            PullOutcome::Applied(r) => to_json(&json!({
                "outcome": "applied", "applied": r.applied, "quarantined": r.quarantined, "conflicts": r.conflicts,
                "deletes_overridden": r.deletes_overridden, "events": r.events, "done": r.done, "rollback": r.rollback,
                "cursor": self.sync.cursor,
            })),
            PullOutcome::KeysetChanged { .. } => to_json(&json!({ "outcome": "keyset_changed" })),
        }
    }

    pub fn cursor(&self) -> f64 {
        self.sync.cursor as f64
    }

    /// Prepares the next push request, or an empty string if there is nothing to send.
    pub fn prepare_push(&mut self) -> JsResult<String> {
        match sync_core::prepare_push(&mut self.sync, sync_core::MAX_PUSH) {
            Some(req) => to_json(&req),
            None => Ok(String::new()),
        }
    }

    pub fn apply_push(&mut self, request_json: &str, response_json: &str) -> JsResult<String> {
        let req: PushRequest = from_json(request_json)?;
        let resp: PushResponse = from_json(response_json)?;
        let vault = self
            .unlocked
            .as_ref()
            .map(|u| &u.vault)
            .ok_or_else(|| err("locked"))?;
        let r = sync_core::apply_push_results(&mut self.sync, vault, &req, &resp).map_err(verr)?;
        to_json(
            &json!({ "applied": r.applied, "conflicts": r.conflicts, "invalid": r.invalid, "keyset_changed": r.keyset_changed }),
        )
    }

    pub fn begin_resync(&mut self) {
        sync_core::begin_resync(&mut self.sync);
    }

    /// Starts handling a vault-key rotation made elsewhere: snapshot pending edits with the old
    /// key. Next: `set_account(new)`, `unlock(...)`, pull all pages, `finish_rotation()`.
    pub fn begin_rotation(&mut self) -> JsResult<()> {
        let vault = self
            .unlocked
            .as_ref()
            .map(|u| &u.vault)
            .ok_or_else(|| err("locked"))?;
        self.rotation = Some(sync_core::begin_rotation(&mut self.sync, vault).map_err(verr)?);
        Ok(())
    }

    pub fn finish_rotation(&mut self) -> JsResult<()> {
        let snapshot = self
            .rotation
            .take()
            .ok_or_else(|| err("invalid: no rotation in progress"))?;
        let vault = self
            .unlocked
            .as_ref()
            .map(|u| &u.vault)
            .ok_or_else(|| err("locked"))?;
        sync_core::finish_rotation(&mut self.sync, vault, snapshot).map_err(verr)
    }

    /// Counts for the sync indicator.
    pub fn status(&self) -> JsResult<String> {
        to_json(&json!({
            "pending": self.sync.outbox.len(),
            "conflicts": self.sync.conflicts.len(),
            "quarantined": self.sync.quarantine.len(),
            "failed": self.sync.failed.len(),
            "rollback": self.sync.rollback_warning,
            "unread_events": self.sync.events.iter().filter(|e| !e.acknowledged).count(),
        }))
    }

    // ---------------------------------------------------------------- items

    /// Display list (no concealed values).
    pub fn list_items(&self) -> JsResult<String> {
        let vault = self.vault()?;
        let mut out = Vec::new();
        for (key, e) in sync_core::effective(&self.sync).map_err(verr)? {
            let Ok(opened) = record::open(vault, &e.record) else {
                continue;
            };
            let Some(item) = opened.item else { continue };
            out.push(summary(&key, &item, e.pending, e.conflict));
        }
        to_json(&out)
    }

    /// One item for display: concealed values replaced by `null` (use `reveal_field`).
    pub fn get_item(&self, id: &str) -> JsResult<String> {
        let item = self.load(id)?;
        let mut v: Value = serde_json::from_slice(&item.to_json().map_err(verr)?)
            .map_err(|_| err("invalid: item"))?;
        conceal(&mut v);
        v["id"] = Value::String(id.to_owned());
        v["editable"] = Value::Bool(item.is_editable());
        to_json(&v)
    }

    /// One item with every value, for the edit form.
    pub fn get_item_for_edit(&self, id: &str) -> JsResult<String> {
        let item = self.load(id)?;
        if !item.is_editable() {
            return Err(err("read_only"));
        }
        String::from_utf8(item.to_json().map_err(verr)?).map_err(|_| err("invalid: item"))
    }

    /// Releases one concealed value: `password`, `totp_secret`, `private_key`, `notes`,
    /// `history:<n>` or `custom:<field id>`.
    pub fn reveal_field(&self, id: &str, field: &str) -> JsResult<String> {
        let item = self.load(id)?;
        let value = match (&item.content, field) {
            (Content::Login(l), "password") => l.password.clone(),
            (Content::Login(l), "totp_secret") => l
                .totp
                .as_ref()
                .map(|t| t.secret.clone())
                .unwrap_or_default(),
            (Content::Login(l), "username") => l.username.clone(),
            (Content::SshKey(k), "private_key") => k.private_key.clone(),
            (_, "notes") => item.notes.clone(),
            (_, f) if f.starts_with("history:") => {
                let n: usize = f[8..].parse().map_err(|_| err("invalid: field"))?;
                item.password_history
                    .get(n)
                    .map(|h| h.password.clone())
                    .ok_or_else(|| err("invalid: field"))?
            }
            (_, f) if f.starts_with("custom:") => item
                .custom_fields
                .iter()
                .find(|c| c.id == f[7..])
                .map(|c| c.value.clone())
                .ok_or_else(|| err("invalid: field"))?,
            _ => return Err(err("invalid: field")),
        };
        Ok(value)
    }

    fn load(&self, id: &str) -> JsResult<Item> {
        let vault = self.vault()?;
        let eff = sync_core::effective(&self.sync).map_err(verr)?;
        let e = eff.get(id).ok_or_else(|| err("invalid: unknown item"))?;
        record::open(vault, &e.record)
            .map_err(verr)?
            .item
            .ok_or_else(|| err("invalid: deleted"))
    }

    /// Creates (`id` empty) or updates an item from its JSON body. Returns the item id.
    pub fn save_item(&mut self, id: &str, item_json: &str, now: &str) -> JsResult<String> {
        let mut item = Item::from_json(item_json.as_bytes()).map_err(verr)?;
        item.updated_at = now.to_owned();
        item.updated_by = self.device_id.clone();
        item.validate().map_err(verr)?;
        let vault = self
            .unlocked
            .as_ref()
            .map(|u| &u.vault)
            .ok_or_else(|| err("locked"))?;
        let out = if id.is_empty() {
            item.created_at = now.to_owned();
            sync_core::write(&mut self.sync, vault, Write::Create(&item)).map_err(verr)?
        } else {
            let item_id = ItemId::from_slice(&bytes(id)?).map_err(|_| err("invalid: id"))?;
            let eff = sync_core::effective(&self.sync).map_err(verr)?;
            if let Some(prev) = eff
                .get(id)
                .and_then(|e| record::open(vault, &e.record).ok())
                .and_then(|o| o.item)
            {
                item.created_at = prev.created_at.clone();
                item.record_password_change(&prev, now);
            }
            sync_core::write(&mut self.sync, vault, Write::Update(item_id, &item)).map_err(verr)?
        };
        Ok(b64::encode(out.item_id.as_bytes()))
    }

    pub fn delete_item(&mut self, id: &str) -> JsResult<()> {
        let item_id = ItemId::from_slice(&bytes(id)?).map_err(|_| err("invalid: id"))?;
        let vault = self
            .unlocked
            .as_ref()
            .map(|u| &u.vault)
            .ok_or_else(|| err("locked"))?;
        sync_core::write(&mut self.sync, vault, Write::Delete(item_id)).map_err(verr)?;
        Ok(())
    }

    /// Restores a deleted item (undo): writes the previous content as a new revision.
    pub fn restore_item(&mut self, id: &str, item_json: &str, now: &str) -> JsResult<String> {
        self.save_item(id, item_json, now)
    }

    /// The current TOTP code of an item.
    pub fn totp(&self, id: &str, unix_seconds: f64) -> JsResult<String> {
        let item = self.load(id)?;
        let Content::Login(l) = &item.content else {
            return Err(err("invalid: not a login"));
        };
        let cfg = l.totp.as_ref().ok_or_else(|| err("invalid: no totp"))?;
        totp_json(cfg, unix_seconds)
    }

    /// Validates a TOTP configuration and returns a preview code (edit form).
    pub fn totp_preview(config_json: &str, unix_seconds: f64) -> JsResult<String> {
        let cfg: TotpConfig = from_json(config_json)?;
        totp_json(&cfg, unix_seconds)
    }

    /// Parses an `otpauth://totp/` link into a TOTP configuration.
    pub fn parse_otpauth(uri: &str) -> JsResult<String> {
        to_json(&totp::parse_otpauth_uri(uri).map_err(verr)?)
    }

    pub fn search(&self, query: &str) -> JsResult<String> {
        let vault = self.vault()?;
        let mut ids = Vec::new();
        for (key, e) in sync_core::effective(&self.sync).map_err(verr)? {
            if let Ok(o) = record::open(vault, &e.record)
                && let Some(item) = o.item
                && search::matches(&item, query)
            {
                ids.push(key);
            }
        }
        to_json(&ids)
    }

    pub fn generate_password(options_json: &str) -> JsResult<String> {
        let o: Value = from_json(options_json)?;
        let opts = PasswordOptions {
            length: o["length"].as_u64().unwrap_or(20) as usize,
            digits: o["digits"].as_bool().unwrap_or(true),
            symbols: o["symbols"].as_bool().unwrap_or(true),
            avoid_lookalikes: o["avoid_lookalikes"].as_bool().unwrap_or(false),
        };
        let g = generator::password(&opts).map_err(verr)?;
        to_json(&json!({ "value": g.value.as_str(), "bits": g.bits }))
    }

    pub fn generate_passphrase(options_json: &str) -> JsResult<String> {
        let o: Value = from_json(options_json)?;
        let opts = PassphraseOptions {
            words: o["words"].as_u64().unwrap_or(6) as usize,
            separator: o["separator"].as_str().unwrap_or("-").to_owned(),
            capitalize: o["capitalize"].as_bool().unwrap_or(false),
        };
        let g = generator::passphrase(&opts).map_err(verr)?;
        to_json(&json!({ "value": g.value.as_str(), "bits": g.bits }))
    }

    /// Parses an OpenSSH private key into SSH item fields (R-SSH-1).
    pub fn import_ssh(pem: &str, passphrase: &str) -> JsResult<String> {
        let pass = (!passphrase.is_empty()).then_some(passphrase);
        to_json(&ssh::import_openssh(pem, pass).map_err(verr)?)
    }

    // ---------------------------------------------------------------- conflicts and events

    pub fn conflicts(&self) -> JsResult<String> {
        let out: Vec<Value> = self
            .sync
            .conflicts
            .iter()
            .map(|(id, c)| json!({ "id": id, "reason": c.reason }))
            .collect();
        to_json(&out)
    }

    /// Both versions of a conflict (concealed values withheld).
    pub fn open_conflict(&self, id: &str) -> JsResult<String> {
        let vault = self.vault()?;
        let (server, local) = sync_core::open_conflict(&self.sync, vault, id).map_err(verr)?;
        let show = |i: Option<Item>| -> JsResult<Value> {
            match i {
                Some(i) => {
                    let mut v: Value = serde_json::from_slice(&i.to_json().map_err(verr)?)
                        .map_err(|_| err("invalid: item"))?;
                    conceal(&mut v);
                    Ok(v)
                }
                None => Ok(Value::Null),
            }
        };
        to_json(
            &json!({ "server": show(server)?, "local": show(local)?, "reason": self.sync.conflicts.get(id).map(|c| c.reason) }),
        )
    }

    /// `choice`: `server`, `local` or `both`.
    pub fn resolve_conflict(&mut self, id: &str, choice: &str) -> JsResult<()> {
        let choice = match choice {
            "server" => Resolution::KeepServer,
            "local" => Resolution::KeepLocal,
            "both" => Resolution::KeepBoth,
            _ => return Err(err("invalid: choice")),
        };
        let vault = self
            .unlocked
            .as_ref()
            .map(|u| &u.vault)
            .ok_or_else(|| err("locked"))?;
        sync_core::resolve(&mut self.sync, vault, id, choice).map_err(verr)?;
        Ok(())
    }

    pub fn events(&self) -> JsResult<String> {
        to_json(&self.sync.events)
    }

    pub fn ack_event(&mut self, seq: f64) {
        for e in &mut self.sync.events {
            if e.seq as f64 == seq {
                e.acknowledged = true;
            }
        }
    }

    pub fn clear_rollback_warning(&mut self) {
        self.sync.rollback_warning = false;
    }

    // ---------------------------------------------------------------- step-up key changes

    /// Builds a step-up request (crypto §7.8) for `operation` with `payload_json`. When a pending
    /// unlock-key change exists, adds the new key's proof signature.
    pub fn stepup_request(
        &self,
        operation: &str,
        payload_json: &str,
        challenge_id: &str,
        nonce: &str,
    ) -> JsResult<String> {
        let unlocked = self.unlocked.as_ref().ok_or_else(|| err("locked"))?;
        let payload: Value = from_json(payload_json)?;
        let new_auth = match &self.pending {
            Some(PendingChange::Unlock(c)) if operation == "change_unlock_keys" => {
                Some(&c.new_auth)
            }
            _ => None,
        };
        let req = account::stepup_request(
            &self.account_id()?,
            &bytes(challenge_id)?,
            &arr32(nonce)?,
            operation,
            &payload,
            &unlocked.auth,
            new_auth,
        )
        .map_err(verr)?;
        to_json(&req)
    }

    /// Prepares a master password change (R-ACC-6). Returns the payload JSON.
    pub fn prepare_password_change(&mut self, new_password: &str) -> JsResult<String> {
        let vault = self.vault()?;
        let ask = self.secret_key.as_ref().ok_or_else(|| err("locked"))?;
        let change =
            account::change_password(vault, ask, new_password, KdfParams::DEFAULT).map_err(verr)?;
        let payload = to_json(&change.payload)?;
        self.pending = Some(PendingChange::Unlock(change));
        Ok(payload)
    }

    /// Prepares a Secret Key rotation (R-ACC-7). Returns `{payload, secret_key_text}`.
    pub fn prepare_secret_key_rotation(&mut self, password: &str) -> JsResult<String> {
        let vault = self.vault()?;
        let change =
            account::rotate_secret_key(vault, password, KdfParams::DEFAULT).map_err(verr)?;
        let text = change
            .secret_key
            .as_ref()
            .map(|k| encoding::format_account_secret_key(k).to_string())
            .unwrap_or_default();
        let out = json!({ "payload": change.payload, "secret_key_text": text });
        self.pending = Some(PendingChange::Unlock(change));
        to_json(&out)
    }

    /// Prepares a Recovery Key replacement (R-REC-3). Returns `{payload, recovery_key_text}`.
    pub fn prepare_recovery_key(&mut self) -> JsResult<String> {
        let change = account::replace_recovery_key(self.vault()?).map_err(verr)?;
        let out = json!({ "payload": change.payload, "recovery_key_text": encoding::format_recovery_key(&change.recovery_key).as_str() });
        self.pending = Some(PendingChange::Recovery);
        drop(change);
        to_json(&out)
    }

    /// Prepares a vault-key rotation (R-DEV-3) over every item this device has. Returns
    /// `{payload, recovery_key_text}`. Sync first so `expected_vault_seq` is current.
    pub fn prepare_rekey(&mut self, password: &str, expected_vault_seq: f64) -> JsResult<String> {
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| err("invalid: no account"))?;
        let material = account::material_from_wire(account).map_err(verr)?;
        let ask = self.secret_key.as_ref().ok_or_else(|| err("locked"))?;
        if !self.sync.outbox.is_empty() || !self.sync.conflicts.is_empty() {
            return Err(err(
                "invalid: sync and resolve conflicts before changing the vault key",
            ));
        }
        let records = self
            .sync
            .records
            .values()
            .map(sync_core::record_from_wire)
            .collect::<Result<Vec<_>, _>>()
            .map_err(verr)?;
        let rotation = account::rotate_vmk(
            self.vault()?,
            &material,
            password,
            ask,
            &records,
            expected_vault_seq as u64,
        )
        .map_err(verr)?;
        let out = json!({ "payload": rotation.payload, "recovery_key_text": encoding::format_recovery_key(&rotation.recovery_key).as_str() });
        self.pending = Some(PendingChange::Rekey(rotation));
        to_json(&out)
    }

    /// Call after the server accepted a prepared change, with the new account state. Returns the
    /// new Secret Key bytes (base64url) when it changed, so the app can re-wrap it locally.
    pub fn commit_change(&mut self, account_json: &str) -> JsResult<String> {
        let state: AccountState = from_json(account_json)?;
        let pending = self
            .pending
            .take()
            .ok_or_else(|| err("invalid: nothing to commit"))?;
        let mut new_secret = String::new();
        match pending {
            PendingChange::Unlock(c) => {
                if let Some(k) = c.secret_key {
                    new_secret = b64::encode(k.expose_secret());
                    self.secret_key = Some(k);
                }
                if let Some(u) = self.unlocked.as_mut() {
                    u.auth = c.new_auth;
                }
            }
            PendingChange::Recovery => {}
            PendingChange::Rekey(r) => {
                if let Some(u) = self.unlocked.as_mut() {
                    u.vault = r.vault;
                }
                // Every record changed key: pull everything again with the new key.
                sync_core::begin_resync(&mut self.sync);
            }
            PendingChange::Recover(s) => {
                new_secret = b64::encode(s.secret_key.expose_secret());
                let vault = self
                    .recovery_vault
                    .take()
                    .ok_or_else(|| err("invalid: no recovery"))?;
                self.unlocked = Some(Unlocked {
                    vault,
                    auth: s.auth,
                });
                self.secret_key = Some(s.secret_key);
                sync_core::begin_resync(&mut self.sync);
            }
        }
        self.account = Some(state);
        Ok(new_secret)
    }

    pub fn discard_change(&mut self) {
        self.pending = None;
    }

    // ---------------------------------------------------------------- recovery

    /// Prepares the recovery login (crypto §7.7). JS signs `message` with the device key.
    pub fn prepare_recovery_login(
        &self,
        account_id: &str,
        challenge_id: &str,
        nonce: &str,
        recovery_key_text: &str,
        device_json: &str,
        origin: &str,
    ) -> JsResult<String> {
        let rk = encoding::parse_recovery_key(recovery_key_text)
            .map_err(|_| err("invalid: recovery key"))?;
        let account_id =
            AccountId::from_slice(&bytes(account_id)?).map_err(|_| err("invalid: account id"))?;
        let device: DeviceInfo = from_json(device_json)?;
        let device_pk: [u8; 32] = device.device_pk.array().map_err(verr)?;
        let nonce = arr32(nonce)?;
        let message = sign::recovery_message(&account_id, &nonce, &device_pk, origin);
        let rauth = account::recovery_auth(&account_id, &rk).map_err(verr)?;
        let request = json!({
            "account_id": b64::encode(account_id.as_bytes()),
            "challenge_id": challenge_id,
            "device": device,
            "sig_recovery": b64::encode(&rauth.sign(&message)),
        });
        to_json(&json!({ "request": request, "message": b64::encode(&message) }))
    }

    /// Opens the recovery envelope with the Recovery Key.
    pub fn open_recovery(
        &mut self,
        account_id: &str,
        vmk_id: &str,
        recovery_env: &str,
        recovery_key_text: &str,
    ) -> JsResult<()> {
        let rk: RecoveryKey = encoding::parse_recovery_key(recovery_key_text)
            .map_err(|_| err("invalid: recovery key"))?;
        let vault = account::open_recovery(
            AccountId::from_slice(&bytes(account_id)?).map_err(|_| err("invalid: account id"))?,
            VmkId::from_slice(&bytes(vmk_id)?).map_err(|_| err("invalid: vmk id"))?,
            &bytes(recovery_env)?,
            &rk,
        )
        .map_err(verr)?;
        self.recovery_vault = Some(vault);
        Ok(())
    }

    /// New credentials after recovery (R-REC-2). Returns `{payload, secret_key_text, recovery_key_text}`.
    pub fn prepare_recovery_setup(&mut self, new_password: &str) -> JsResult<String> {
        let vault = self
            .recovery_vault
            .as_ref()
            .ok_or_else(|| err("invalid: no recovery"))?;
        let setup =
            account::setup_after_recovery(vault, new_password, KdfParams::DEFAULT).map_err(verr)?;
        let out = json!({
            "payload": setup.payload,
            "secret_key_text": encoding::format_account_secret_key(&setup.secret_key).as_str(),
            "recovery_key_text": encoding::format_recovery_key(&setup.recovery_key).as_str(),
        });
        self.pending = Some(PendingChange::Recover(setup));
        to_json(&out)
    }
}

fn totp_json(cfg: &TotpConfig, unix_seconds: f64) -> JsResult<String> {
    let t = Totp::from_config(cfg).map_err(verr)?;
    let c = t.code_at(unix_seconds.max(0.0) as u64);
    to_json(
        &json!({ "code": c.code, "seconds_remaining": c.seconds_remaining, "period": c.period }),
    )
}

/// Replaces concealed values by `null` and adds `has_*` flags (design-principles §3.4).
fn conceal(v: &mut Value) {
    if let Some(f) = v.get_mut("fields") {
        for key in ["password", "private_key"] {
            if let Some(x) = f.get_mut(key) {
                let has = x.as_str().is_some_and(|s| !s.is_empty());
                *x = Value::Null;
                f[format!("has_{key}")] = Value::Bool(has);
            }
        }
        if let Some(t) = f.get_mut("totp")
            && t.is_object()
        {
            t["secret"] = Value::Null;
        }
    }
    if let Some(Value::Array(cs)) = v.get_mut("custom_fields") {
        for c in cs {
            if c["kind"] == "concealed" {
                c["value"] = Value::Null;
            }
        }
    }
    if let Some(Value::Array(hs)) = v.get_mut("password_history") {
        for h in hs {
            h["password"] = Value::Null;
        }
    }
}

fn summary(id: &str, item: &Item, pending: bool, conflict: bool) -> Value {
    let (subtitle, has_totp, host) = match &item.content {
        Content::Login(l) => {
            let host = l.urls.first().map(|u| host_of(&u.url)).unwrap_or_default();
            let sub = if l.username.is_empty() {
                host.clone()
            } else {
                l.username.clone()
            };
            (sub, l.totp.is_some(), host)
        }
        Content::Note(_) => (
            item.notes
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(60)
                .collect(),
            false,
            String::new(),
        ),
        Content::SshKey(k) => (
            format!(
                "{} · {}",
                k.key_type,
                k.fingerprint.chars().take(20).collect::<String>()
            ),
            false,
            String::new(),
        ),
        Content::Unknown { .. } => ("Update urkey to view".into(), false, String::new()),
    };
    json!({
        "id": id, "type": item.content.kind(), "title": item.title, "subtitle": subtitle, "favorite": item.favorite,
        "tags": item.tags, "pending": pending, "conflict": conflict, "editable": item.is_editable(),
        "has_totp": has_totp, "host": host, "updated_at": item.updated_at,
    })
}

fn host_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split(['/', '?', '#']).next().unwrap_or("").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_package_version() {
        assert_eq!(core_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn conceal_removes_secrets() {
        let mut v = json!({
            "fields": { "password": "p", "totp": { "secret": "S" }, "private_key": "" },
            "custom_fields": [{ "kind": "concealed", "value": "c" }, { "kind": "text", "value": "t" }],
            "password_history": [{ "password": "old" }]
        });
        conceal(&mut v);
        let s = v.to_string();
        for secret in ["\"p\"", "\"S\"", "\"c\"", "\"old\""] {
            assert!(!s.contains(secret), "{secret} leaked");
        }
        assert_eq!(v["fields"]["has_password"], true);
        assert_eq!(v["fields"]["has_private_key"], false);
        assert_eq!(v["custom_fields"][1]["value"], "t");
    }

    #[test]
    fn host_parsing() {
        assert_eq!(host_of("https://github.com/login?x=1"), "github.com");
        assert_eq!(host_of("example.org/path"), "example.org");
    }
}
