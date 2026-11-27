//! One configured account on this machine: store, secrets, API client, device identity, and the
//! operations that combine them (unlock, session refresh, sync).

use serde::{Deserialize, Serialize};
use sync_core::vault_core::account::{self, Unlocked};
use sync_core::vault_core::b64::{self, B64};
use sync_core::vault_core::crypto_core::ids::{AccountId, DeviceId, ItemId};
use sync_core::vault_core::crypto_core::secret::AccountSecretKey;
use sync_core::vault_core::crypto_core::sign::AuthKey;
use sync_core::vault_core::item::Item;
use sync_core::vault_core::record::{self, VaultKey};
use sync_core::vault_core::wire::{
    AccountResponse, AccountState, ChallengeRequest, ChallengeResponse, ChangesResponse,
    DeviceInfo, PushResponse, SessionResponse,
};
use sync_core::{PullOutcome, SyncState};
use zeroize::Zeroizing;

use crate::api::{Api, ApiError};
use crate::error::{CliError, Result};
use crate::secrets::{self, SecretStore};
use crate::store::Store;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: String,
    pub device_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: B64,
}

pub struct Profile {
    pub store: Store,
    pub secrets: Box<dyn SecretStore>,
    pub api: Api,
    pub config: Config,
    pub dir: std::path::PathBuf,
}

pub const SECRET_KEY: &str = "secret_key";
pub const DEVICE_SEED: &str = "device_seed";
/// The bearer token lives in the secret store (Keychain on macOS), not in `vault.db` (review L-2).
pub const SESSION_TOKEN: &str = "session_token";

/// What `vault.db` keeps about the session: only its expiry. `session_token` is read only to
/// migrate profiles written before review L-2, and is never written back.
#[derive(Serialize, Deserialize)]
struct SessionMeta {
    expires_at: i64,
    #[serde(default, skip_serializing)]
    session_token: Option<String>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl Profile {
    pub fn open() -> Result<Self> {
        let dir = crate::paths::data_dir()?;
        let store = Store::open(&dir)?;
        let config: Config = store
            .get("config")?
            .ok_or_else(|| CliError::new("Not set up yet. Run `urk init --server <url>` first."))?;
        let mut api = Api::new(&config.server);
        let secrets = secrets::open(&dir);
        if let Some(meta) = store.get::<SessionMeta>("session")? {
            if let Some(legacy) = &meta.session_token {
                // Older profile: move the token out of vault.db into the secret store.
                secrets.set(SESSION_TOKEN, legacy.as_bytes())?;
                store.put(
                    "session",
                    &SessionMeta {
                        expires_at: meta.expires_at,
                        session_token: None,
                    },
                )?;
            }
            if meta.expires_at > now_ms() + 30_000
                && let Some(t) = secrets.get(SESSION_TOKEN)?
            {
                api.token = String::from_utf8(t.to_vec()).ok();
            }
        }
        Ok(Self {
            secrets,
            store,
            api,
            config,
            dir,
        })
    }

    pub fn device_id(&self) -> Result<DeviceId> {
        let d: DeviceRecord = self
            .store
            .get("device")?
            .ok_or_else(|| CliError::new("No device identity."))?;
        Ok(DeviceId::from_slice(&d.device_id.0)?)
    }

    /// This device's key, created on first use.
    pub fn device_key(&self) -> Result<AuthKey> {
        if let Some(seed) = self.secrets.get(DEVICE_SEED)? {
            let seed: [u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| CliError::new("device key is damaged"))?;
            return Ok(AuthKey::device_key_from_seed(&seed));
        }
        let seed = AuthKey::generate_device_seed()?;
        self.secrets.set(DEVICE_SEED, seed.as_ref())?;
        self.store.put(
            "device",
            &DeviceRecord {
                device_id: B64(DeviceId::generate()?.as_bytes().to_vec()),
            },
        )?;
        Ok(AuthKey::device_key_from_seed(&seed))
    }

    pub fn device_info(&self, key: &AuthKey) -> Result<DeviceInfo> {
        Ok(DeviceInfo {
            device_id: B64(self.device_id()?.as_bytes().to_vec()),
            device_pk: B64(key.public_key().to_vec()),
            name: self.config.device_name.clone(),
            platform: if cfg!(target_os = "macos") {
                "macos-cli".into()
            } else {
                "linux-cli".into()
            },
            client_version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    pub fn account(&self) -> Result<AccountState> {
        self.store.get("account")?.ok_or_else(|| {
            CliError::new("No account on this device. Run `urk login` or `urk account create`.")
        })
    }

    pub fn secret_key(&self) -> Result<AccountSecretKey> {
        let raw = self
            .secrets
            .get(SECRET_KEY)?
            .ok_or_else(|| CliError::new("Secret Key missing on this device. Run `urk login`."))?;
        Ok(AccountSecretKey::from_slice(&raw)?)
    }

    pub fn save_session(&mut self, s: &SessionResponse) -> Result<()> {
        self.secrets
            .set(SESSION_TOKEN, s.session_token.as_bytes())?;
        self.store.put(
            "session",
            &SessionMeta {
                expires_at: s.expires_at,
                session_token: None,
            },
        )?;
        self.api.token = Some(s.session_token.clone());
        Ok(())
    }

    pub fn challenge(
        &self,
        account_id: &AccountId,
        purpose: &str,
    ) -> std::result::Result<(Vec<u8>, [u8; 32]), ApiError> {
        let r: ChallengeResponse = self.api.post(
            "/v1/auth/challenge",
            &ChallengeRequest {
                account_id: B64(account_id.as_bytes().to_vec()),
                purpose: purpose.into(),
            },
        )?;
        let nonce: [u8; 32] = r.nonce.0.as_slice().try_into().map_err(|_| ApiError {
            status: 0,
            code: "bad_response".into(),
        })?;
        Ok((r.challenge_id.0, nonce))
    }

    /// Makes sure a full session exists, refreshing it with the device key (crypto §7.9).
    pub fn ensure_session(&mut self) -> Result<()> {
        if self.api.token.is_some() {
            return Ok(());
        }
        let state = self.account()?;
        let account_id = AccountId::from_slice(&state.account_id.0)?;
        let device_id = self.device_id()?;
        let key = self.device_key()?;
        let (cid, nonce) = self.challenge(&account_id, "refresh")?;
        let req = account::refresh_request(&account_id, &device_id, &cid, &nonce, &key);
        let s: SessionResponse = self.api.post("/v1/auth/refresh", &req)?;
        self.save_session(&s)
    }

    pub fn refresh_account(&mut self) -> Result<AccountResponse> {
        self.ensure_session()?;
        let r: AccountResponse = self.api.get("/v1/account")?;
        self.store.put("account", &r.account)?;
        Ok(r)
    }

    pub fn unlock(&self, password: &str) -> Result<Unlocked> {
        let material = account::material_from_wire(&self.account()?)?;
        Ok(account::unlock(&material, password, &self.secret_key()?)?)
    }

    pub fn sync_state(&self) -> Result<SyncState> {
        Ok(self.store.get("sync")?.unwrap_or_default())
    }

    pub fn save_sync_state(&self, s: &SyncState) -> Result<()> {
        self.store.put("sync", s)
    }

    /// Full sync cycle (sync.md §10): pull, push, pull. Handles resync and vault-key rotation.
    pub fn sync(&mut self, unlocked: &mut Unlocked, password: &str) -> Result<SyncSummary> {
        self.ensure_session()?;
        let mut state = self.sync_state()?;
        let mut summary = SyncSummary::default();
        self.pull_all(&mut state, unlocked, password, &mut summary)?;
        while let Some(req) = sync_core::prepare_push(&mut state, sync_core::MAX_PUSH) {
            let resp: PushResponse = self.api.post("/v1/sync/push", &req)?;
            let rep = sync_core::apply_push_results(&mut state, &unlocked.vault, &req, &resp)?;
            summary.pushed += rep.applied;
            summary.conflicts += rep.conflicts;
            self.save_sync_state(&state)?;
            if rep.keyset_changed {
                self.pull_all(&mut state, unlocked, password, &mut summary)?;
            } else if rep.applied == 0 && rep.invalid == 0 && rep.conflicts == 0 {
                break; // nothing progressed; try again on the next sync
            }
        }
        self.pull_all(&mut state, unlocked, password, &mut summary)?;
        summary.pending = state.outbox.len();
        summary.open_conflicts = state.conflicts.len();
        summary.rollback = state.rollback_warning;
        self.save_sync_state(&state)?;
        Ok(summary)
    }

    fn pull_all(
        &mut self,
        state: &mut SyncState,
        unlocked: &mut Unlocked,
        password: &str,
        summary: &mut SyncSummary,
    ) -> Result<()> {
        loop {
            let resp: std::result::Result<ChangesResponse, ApiError> = self.api.get(&format!(
                "/v1/sync/changes?since={}&limit=500",
                state.cursor
            ));
            let resp = match resp {
                Err(ApiError { status: 410, .. }) => {
                    sync_core::begin_resync(state);
                    continue;
                }
                other => other?,
            };
            match sync_core::apply_changes(state, &unlocked.vault, &resp)? {
                PullOutcome::Applied(r) => {
                    summary.pulled += r.applied;
                    summary.conflicts += r.conflicts;
                    summary.quarantined += r.quarantined;
                    if r.rollback || r.done {
                        self.save_sync_state(state)?;
                        return Ok(());
                    }
                }
                PullOutcome::KeysetChanged { .. } => {
                    // Another device rotated the vault key (sync.md §8.4): re-unlock, rebase.
                    self.refresh_account()?;
                    let fresh = self.unlock(password)?;
                    let snapshot = sync_core::begin_rotation(state, &unlocked.vault)?;
                    let old = std::mem::replace(unlocked, fresh);
                    drop(old);
                    self.pull_rotation(state, &unlocked.vault)?;
                    sync_core::finish_rotation(state, &unlocked.vault, snapshot)?;
                    summary.rotated = true;
                }
            }
        }
    }

    fn pull_rotation(&mut self, state: &mut SyncState, key: &VaultKey) -> Result<()> {
        loop {
            let resp: ChangesResponse = self.api.get(&format!(
                "/v1/sync/changes?since={}&limit=500",
                state.cursor
            ))?;
            if let PullOutcome::Applied(r) = sync_core::apply_changes(state, key, &resp)? {
                if r.done || r.rollback {
                    return Ok(());
                }
            } else {
                return Err(CliError::new(
                    "the vault key changed again during sync; try again",
                ));
            }
        }
    }

    /// Decrypted items as this device sees them.
    pub fn items(&self, key: &VaultKey) -> Result<Vec<ViewItem>> {
        let state = self.sync_state()?;
        let mut out = Vec::new();
        for (_, e) in sync_core::effective(&state)? {
            let opened = record::open(key, &e.record)?;
            if let Some(item) = opened.item {
                out.push(ViewItem {
                    id: e.record.item_id,
                    item,
                    pending: e.pending,
                    conflict: e.conflict,
                });
            }
        }
        out.sort_by_key(|v| v.item.title.to_lowercase());
        Ok(out)
    }

    /// This device's current encrypted records (for export).
    pub fn records(&self) -> Result<Vec<record::ItemRecord>> {
        let state = self.sync_state()?;
        Ok(sync_core::effective(&state)?
            .into_values()
            .map(|e| e.record)
            .collect())
    }

    pub fn write(&self, key: &VaultKey, change: sync_core::Write<'_>) -> Result<ItemId> {
        let mut state = self.sync_state()?;
        let out = sync_core::write(&mut state, key, change)?;
        self.save_sync_state(&state)?;
        Ok(out.item_id)
    }
}

#[derive(Debug, Default)]
pub struct SyncSummary {
    pub pulled: usize,
    pub pushed: usize,
    pub conflicts: usize,
    pub quarantined: usize,
    pub pending: usize,
    pub open_conflicts: usize,
    pub rollback: bool,
    pub rotated: bool,
}

pub struct ViewItem {
    pub id: ItemId,
    pub item: Item,
    pub pending: bool,
    pub conflict: bool,
}

pub fn short_id(id: &ItemId) -> String {
    b64::encode(id.as_bytes()).chars().take(8).collect()
}

/// Reads the master password: from the first stdin line with `--password-stdin`, else the TTY.
pub fn read_password(from_stdin: bool, prompt: &str) -> Result<Zeroizing<String>> {
    if from_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut line)?;
        let trimmed = Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_owned());
        return Ok(trimmed);
    }
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|_| CliError::new("could not read the password (no terminal?)"))
}
