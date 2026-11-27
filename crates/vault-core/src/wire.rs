//! JSON shapes of the HTTP API (`docs/architecture/api.md`). Binary fields are base64url
//! ([`B64`]); times are Unix milliseconds. The TypeScript Worker implements the same shapes and
//! both sides are checked against `tests/fixtures/api/`.

use serde::{Deserialize, Serialize};

use crate::b64::B64;

/// `POST /v1/auth/prelogin` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginRequest {
    /// Email (normalized by the server: trimmed, lower-case).
    pub email: String,
}

/// `POST /v1/auth/prelogin` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginResponse {
    /// Account id (deterministic fake for unknown emails).
    pub account_id: B64,
    /// Argon2id salt.
    pub kdf_salt: B64,
    /// 13-byte encoded Argon2id parameters.
    pub kdf_params: B64,
}

/// `POST /v1/auth/challenge` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// Account.
    pub account_id: B64,
    /// `login`, `recovery`, `stepup` or `refresh`.
    pub purpose: String,
}

/// `POST /v1/auth/challenge` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Single-use id.
    pub challenge_id: B64,
    /// 32-byte nonce to sign.
    pub nonce: B64,
    /// Expiry (Unix ms).
    pub expires_at: i64,
}

/// A device as it introduces itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Random 16 bytes.
    pub device_id: B64,
    /// Ed25519 public key.
    pub device_pk: B64,
    /// User-chosen name, ≤ 64 chars.
    pub name: String,
    /// `web` or `macos-cli` (`linux-cli` for development).
    pub platform: String,
    /// Semver.
    pub client_version: String,
}

/// A device as the server lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Device.
    pub device_id: B64,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: String,
    /// Client version at last contact.
    pub client_version: String,
    /// `create`, `login` or `recovery`.
    pub enrolled_via: String,
    /// Unix ms.
    pub created_at: i64,
    /// Unix ms.
    pub last_seen_at: i64,
    /// Unix ms, if revoked.
    pub revoked_at: Option<i64>,
}

/// The public account state a full session can read (`GET /v1/account`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    /// Account.
    pub account_id: B64,
    /// Email.
    pub email: String,
    /// Argon2id salt.
    pub kdf_salt: B64,
    /// Encoded Argon2id parameters.
    pub kdf_params: B64,
    /// Account auth public key.
    pub auth_pk: B64,
    /// Recovery auth public key. Lets a client confirm a Recovery Key replacement whose
    /// response was lost (R-REC-3).
    pub rauth_pk: B64,
    /// Unlock envelope (container 0x01).
    pub unlock_env: B64,
    /// Current VMK generation.
    pub vmk_id: B64,
    /// Increments on every key change.
    pub keyset_version: u64,
    /// Head of the change feed.
    pub vault_seq: u64,
    /// Clients below this version must update.
    pub min_client_version: String,
}

/// `GET /v1/account` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountResponse {
    /// Account state.
    pub account: AccountState,
    /// All devices, including revoked ones.
    pub devices: Vec<DeviceRecord>,
}

/// The JSON inside `POST /v1/accounts`' signed payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccountPayload {
    /// Client-chosen account id.
    pub account_id: B64,
    /// Email.
    pub email: String,
    /// Argon2id salt.
    pub kdf_salt: B64,
    /// Encoded parameters.
    pub kdf_params: B64,
    /// Account auth public key.
    pub auth_pk: B64,
    /// Recovery auth public key.
    pub rauth_pk: B64,
    /// Unlock envelope.
    pub unlock_env: B64,
    /// Recovery envelope.
    pub recovery_env: B64,
    /// VMK generation.
    pub vmk_id: B64,
    /// The first device.
    pub device: DeviceInfo,
}

/// A request whose `payload` (JSON bytes) is signed. Signatures cover `SHA-256(payload)` inside the
/// message given in `docs/architecture/api.md` for each endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRequest {
    /// JSON bytes of the operation's payload.
    pub payload: B64,
    /// Challenge (absent for account creation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<B64>,
    /// Signature by the account auth key (or the recovery auth key for recovery).
    pub sig_account: B64,
    /// Signature by the device key, where required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_device: Option<B64>,
    /// Proof signature by a new auth key, for operations that replace it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_new: Option<B64>,
}

/// `POST /v1/auth/login` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Account.
    pub account_id: B64,
    /// Challenge.
    pub challenge_id: B64,
    /// Device (new or known).
    pub device: DeviceInfo,
    /// Account key signature over the login message.
    pub sig_account: B64,
    /// Device key signature over the same message.
    pub sig_device: B64,
}

/// `POST /v1/auth/recovery` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryLoginRequest {
    /// Account.
    pub account_id: B64,
    /// Challenge.
    pub challenge_id: B64,
    /// The new device being set up.
    pub device: DeviceInfo,
    /// Recovery auth key signature over the recovery message.
    pub sig_recovery: B64,
    /// Device key signature over the same message.
    pub sig_device: B64,
}

/// `POST /v1/auth/refresh` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// Account.
    pub account_id: B64,
    /// Device.
    pub device_id: B64,
    /// Challenge.
    pub challenge_id: B64,
    /// Device key signature over the refresh message.
    pub sig_device: B64,
}

/// A session issued by login, refresh, account creation or recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    /// Bearer token (opaque).
    pub session_token: String,
    /// Expiry (Unix ms).
    pub expires_at: i64,
    /// `full` or `recovery`.
    pub scope: String,
}

/// `POST /v1/auth/recovery` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryLoginResponse {
    /// Recovery-scoped session.
    pub session: SessionResponse,
    /// Recovery envelope (container 0x02).
    pub recovery_env: B64,
    /// VMK generation it wraps.
    pub vmk_id: B64,
}

/// Payload replacing the unlock credentials (password change, Secret Key rotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockKeysPayload {
    /// New salt.
    pub kdf_salt: B64,
    /// Parameters.
    pub kdf_params: B64,
    /// New account auth public key.
    pub auth_pk: B64,
    /// New unlock envelope.
    pub unlock_env: B64,
    /// `password` or `secret_key` (for the security event).
    pub reason: String,
}

/// Payload replacing the recovery credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryKeyPayload {
    /// New recovery auth public key.
    pub rauth_pk: B64,
    /// New recovery envelope.
    pub recovery_env: B64,
}

/// Payload completing a recovery (all credentials replaced, crypto §7.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverPayload {
    /// New salt.
    pub kdf_salt: B64,
    /// Parameters.
    pub kdf_params: B64,
    /// New account auth key.
    pub auth_pk: B64,
    /// New unlock envelope.
    pub unlock_env: B64,
    /// New recovery auth key.
    pub rauth_pk: B64,
    /// New recovery envelope.
    pub recovery_env: B64,
}

/// One re-encrypted item in a VMK rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyItem {
    /// Item.
    pub item_id: B64,
    /// New revision (old + 1).
    pub revision: u64,
    /// New DEK wrap.
    pub dek_wrap: B64,
    /// Re-encrypted payload or tombstone.
    pub body: B64,
    /// Hint.
    pub deleted: bool,
}

/// Payload of a VMK rotation (crypto §7.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyPayload {
    /// The vault must not have changed since the client prepared the rotation.
    pub expected_vault_seq: u64,
    /// New VMK generation.
    pub vmk_id: B64,
    /// New unlock envelope.
    pub unlock_env: B64,
    /// New recovery envelope.
    pub recovery_env: B64,
    /// New recovery auth key.
    pub rauth_pk: B64,
    /// Every item, re-encrypted.
    pub items: Vec<RekeyItem>,
}

/// Payload of a device revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeDevicePayload {
    /// Device to revoke.
    pub device_id: B64,
}

/// An item record on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRecord {
    /// Item.
    pub item_id: B64,
    /// Revision.
    pub revision: u64,
    /// Position in the change feed.
    pub seq: u64,
    /// VMK generation.
    pub vmk_id: B64,
    /// DEK wrap.
    pub dek_wrap: B64,
    /// Payload or tombstone.
    pub body: B64,
    /// Hint only.
    pub deleted: bool,
    /// Server time (Unix ms).
    pub updated_at: i64,
    /// Writing device.
    pub updated_by: B64,
}

/// A security event in the change feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEvent {
    /// `device_enrolled`, `device_revoked`, `password_changed`, `secret_key_rotated`,
    /// `recovery_used`, `recovery_key_rotated`, `vmk_rotated`.
    pub kind: String,
    /// Device concerned, if any.
    pub device_id: Option<B64>,
    /// Unix ms.
    pub created_at: i64,
}

/// One entry of `GET /v1/sync/changes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    /// An item record.
    Item {
        /// Feed position.
        seq: u64,
        /// Record.
        item: WireRecord,
    },
    /// A security event.
    Event {
        /// Feed position.
        seq: u64,
        /// Event.
        event: WireEvent,
    },
}

impl Change {
    /// Feed position.
    pub fn seq(&self) -> u64 {
        match self {
            Self::Item { seq, .. } | Self::Event { seq, .. } => *seq,
        }
    }
}

/// `GET /v1/sync/changes` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesResponse {
    /// Head.
    pub vault_seq: u64,
    /// Current keyset version.
    pub keyset_version: u64,
    /// Current VMK generation.
    pub vmk_id: B64,
    /// Ordered by `seq`.
    pub changes: Vec<Change>,
    /// Last `seq` returned (or `since`).
    pub next: u64,
    /// More pages follow.
    pub has_more: bool,
}

/// One mutation in `POST /v1/sync/push`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMutation {
    /// Client-generated, reused on retry.
    pub mutation_id: B64,
    /// Item.
    pub item_id: B64,
    /// Revision the edit was based on (0 = new item).
    pub base_revision: u64,
    /// Must be `base_revision + 1`.
    pub revision: u64,
    /// VMK generation.
    pub vmk_id: B64,
    /// DEK wrap.
    pub dek_wrap: B64,
    /// Payload or tombstone.
    pub body: B64,
    /// Hint.
    pub deleted: bool,
}

/// `POST /v1/sync/push` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    /// ≤ 100 mutations.
    pub mutations: Vec<WireMutation>,
}

/// Result of one mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PushResult {
    /// Stored at `seq`.
    Applied {
        /// Feed position.
        seq: u64,
    },
    /// Already applied earlier; same result.
    Duplicate {
        /// Feed position of the original application.
        seq: u64,
    },
    /// `base_revision` was not current.
    Conflict {
        /// The server's current record.
        current: WireRecord,
    },
    /// The VMK generation changed.
    KeysetChanged {
        /// Current VMK generation.
        vmk_id: B64,
        /// Current keyset version.
        keyset_version: u64,
    },
    /// Malformed or reused id.
    Invalid {
        /// Machine-readable reason.
        code: String,
    },
}

/// `POST /v1/sync/push` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    /// One per mutation, same order.
    pub results: Vec<PushResult>,
}

/// Error body of every non-2xx response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable code, e.g. `resync_required`, `device_revoked`, `update_required`.
    pub error: String,
}
