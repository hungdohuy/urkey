//! Encrypted containers (spec §5–§6).
//!
//! ```text
//! offset size field
//! 0      2    magic      = "UK"
//! 2      1    format_ver = 0x01
//! 3      1    kind
//! 4      1    alg        0x01 XChaCha20-Poly1305, 0x02 AES-256-GCM (local web wrap only)
//! 5      16   key_ref    meaning depends on kind
//! 21     N    nonce      24 for alg 0x01, 12 for alg 0x02
//! 21+N   rest ciphertext ‖ 16-byte tag
//! ```
//!
//! `AAD = header_without_nonce ‖ context(kind)`. The context is always rebuilt from values the
//! caller already trusts ([`Context`]), never read from the container.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::ids::{AccountId, DeviceId, ItemId, KdfSalt, SnapshotId, VmkId};
use crate::kdf::KdfParams;
use crate::lp::push_lp;
use crate::padding;
use crate::secret::{ItemKey, RecoveryKek, UnlockKek, VaultMasterKey};
use crate::{CryptoError, Result, rng};

/// Container magic bytes.
pub const MAGIC: [u8; 2] = *b"UK";
/// Current container format version.
pub const FORMAT_VERSION: u8 = 0x01;
/// Length of the header before the nonce.
pub const HEADER_LEN: usize = 21;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length.
pub const XCHACHA_NONCE_LEN: usize = 24;

/// What a container holds (spec §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// VMK wrapped by the unlock KEK.
    UnlockEnvelope = 0x01,
    /// VMK wrapped by the recovery KEK.
    RecoveryEnvelope = 0x02,
    /// Item key wrapped by the VMK.
    DekWrap = 0x03,
    /// Padded item body encrypted with the item key.
    ItemPayload = 0x04,
    /// Authenticated deletion marker encrypted with the item key.
    Tombstone = 0x05,
    /// Account Secret Key wrapped by a non-extractable WebCrypto key (web only, AES-256-GCM).
    LocalSecretKeyWrap = 0x06,
    /// Encrypted snapshot (roadmap P7).
    Snapshot = 0x07,
}

impl Kind {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::UnlockEnvelope,
            0x02 => Self::RecoveryEnvelope,
            0x03 => Self::DekWrap,
            0x04 => Self::ItemPayload,
            0x05 => Self::Tombstone,
            0x06 => Self::LocalSecretKeyWrap,
            0x07 => Self::Snapshot,
            _ => return None,
        })
    }

    /// The only algorithm allowed for this kind.
    pub const fn alg(self) -> Alg {
        match self {
            Self::LocalSecretKeyWrap => Alg::Aes256Gcm,
            _ => Alg::XChaCha20Poly1305,
        }
    }
}

/// AEAD algorithm identifiers (spec §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Alg {
    /// XChaCha20-Poly1305 (all kinds except the local web wrap).
    XChaCha20Poly1305 = 0x01,
    /// AES-256-GCM, performed by WebCrypto for [`Kind::LocalSecretKeyWrap`] only.
    Aes256Gcm = 0x02,
}

impl Alg {
    /// Nonce length for this algorithm.
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => XCHACHA_NONCE_LEN,
            Self::Aes256Gcm => 12,
        }
    }
}

/// Trusted values that determine a container's kind, `key_ref` and AAD context (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// `account_id ‖ kdf_params ‖ kdf_salt`; key_ref = `vmk_id`.
    UnlockEnvelope {
        /// Account.
        account_id: AccountId,
        /// Id of the wrapped VMK.
        vmk_id: VmkId,
        /// Argon2id parameters used for the KEK.
        kdf_params: KdfParams,
        /// Argon2id salt used for the KEK.
        kdf_salt: KdfSalt,
    },
    /// `account_id`; key_ref = `vmk_id`.
    RecoveryEnvelope {
        /// Account.
        account_id: AccountId,
        /// Id of the wrapped VMK.
        vmk_id: VmkId,
    },
    /// `account_id ‖ item_id`; key_ref = `vmk_id` of the wrapping VMK.
    DekWrap {
        /// Account.
        account_id: AccountId,
        /// Item whose key is wrapped.
        item_id: ItemId,
        /// Id of the wrapping VMK.
        vmk_id: VmkId,
    },
    /// `account_id ‖ item_id ‖ u64be(revision)`; key_ref = `item_id`.
    ItemPayload {
        /// Account.
        account_id: AccountId,
        /// Item.
        item_id: ItemId,
        /// Revision this payload is written as.
        revision: u64,
    },
    /// `account_id ‖ item_id ‖ u64be(revision)`; key_ref = `item_id`.
    Tombstone {
        /// Account.
        account_id: AccountId,
        /// Item.
        item_id: ItemId,
        /// Revision of the deletion.
        revision: u64,
    },
    /// `account_id ‖ LP(snapshot_id)`; key_ref = `snapshot_id`.
    Snapshot {
        /// Account.
        account_id: AccountId,
        /// Snapshot.
        snapshot_id: SnapshotId,
    },
    /// `account_id ‖ LP(device_id)`; key_ref = `device_id`.
    LocalSecretKeyWrap {
        /// Account.
        account_id: AccountId,
        /// This device.
        device_id: DeviceId,
    },
}

impl Context {
    /// The container kind this context belongs to.
    pub const fn kind(&self) -> Kind {
        match self {
            Self::UnlockEnvelope { .. } => Kind::UnlockEnvelope,
            Self::RecoveryEnvelope { .. } => Kind::RecoveryEnvelope,
            Self::DekWrap { .. } => Kind::DekWrap,
            Self::ItemPayload { .. } => Kind::ItemPayload,
            Self::Tombstone { .. } => Kind::Tombstone,
            Self::Snapshot { .. } => Kind::Snapshot,
            Self::LocalSecretKeyWrap { .. } => Kind::LocalSecretKeyWrap,
        }
    }

    /// The `key_ref` header field for this context.
    pub const fn key_ref(&self) -> [u8; 16] {
        match self {
            Self::UnlockEnvelope { vmk_id, .. }
            | Self::RecoveryEnvelope { vmk_id, .. }
            | Self::DekWrap { vmk_id, .. } => *vmk_id.as_bytes(),
            Self::ItemPayload { item_id, .. } | Self::Tombstone { item_id, .. } => {
                *item_id.as_bytes()
            }
            Self::Snapshot { snapshot_id, .. } => *snapshot_id.as_bytes(),
            Self::LocalSecretKeyWrap { device_id, .. } => *device_id.as_bytes(),
        }
    }

    fn context_bytes(&self) -> Vec<u8> {
        let mut c = Vec::with_capacity(48);
        match self {
            Self::UnlockEnvelope {
                account_id,
                kdf_params,
                kdf_salt,
                ..
            } => {
                c.extend_from_slice(account_id.as_bytes());
                c.extend_from_slice(&kdf_params.encode());
                c.extend_from_slice(kdf_salt.as_bytes());
            }
            Self::RecoveryEnvelope { account_id, .. } => c.extend_from_slice(account_id.as_bytes()),
            Self::DekWrap {
                account_id,
                item_id,
                ..
            } => {
                c.extend_from_slice(account_id.as_bytes());
                c.extend_from_slice(item_id.as_bytes());
            }
            Self::ItemPayload {
                account_id,
                item_id,
                revision,
            }
            | Self::Tombstone {
                account_id,
                item_id,
                revision,
            } => {
                c.extend_from_slice(account_id.as_bytes());
                c.extend_from_slice(item_id.as_bytes());
                c.extend_from_slice(&revision.to_be_bytes());
            }
            Self::Snapshot {
                account_id,
                snapshot_id,
            } => {
                c.extend_from_slice(account_id.as_bytes());
                push_lp(&mut c, snapshot_id.as_bytes());
            }
            Self::LocalSecretKeyWrap {
                account_id,
                device_id,
            } => {
                c.extend_from_slice(account_id.as_bytes());
                push_lp(&mut c, device_id.as_bytes());
            }
        }
        c
    }

    /// The header before the nonce: `magic ‖ format_ver ‖ kind ‖ alg ‖ key_ref`.
    pub fn header(&self) -> [u8; HEADER_LEN] {
        let kind = self.kind();
        let mut h = [0u8; HEADER_LEN];
        h[..2].copy_from_slice(&MAGIC);
        h[2] = FORMAT_VERSION;
        h[3] = kind as u8;
        h[4] = kind.alg() as u8;
        h[5..].copy_from_slice(&self.key_ref());
        h
    }

    /// The AEAD associated data: `header_without_nonce ‖ context` (spec §5.2). Public so the web
    /// client can use the same AAD for the WebCrypto local Secret Key wrap.
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = self.header().to_vec();
        aad.extend_from_slice(&self.context_bytes());
        aad
    }
}

/// Header fields read from a container **without authentication**. Use only for routing
/// (e.g. which VMK generation a record claims); always open the container before trusting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnverifiedHeader {
    /// Claimed kind.
    pub kind: Kind,
    /// Claimed algorithm.
    pub alg: Alg,
    /// Claimed key reference.
    pub key_ref: [u8; 16],
}

/// Parses a container header without authenticating it. Errors are [`CryptoError::Decrypt`].
pub fn peek_header(container: &[u8]) -> Result<UnverifiedHeader> {
    let h = container.get(..HEADER_LEN).ok_or(CryptoError::Decrypt)?;
    if h[..2] != MAGIC || h[2] != FORMAT_VERSION {
        return Err(CryptoError::Decrypt);
    }
    let kind = Kind::from_byte(h[3]).ok_or(CryptoError::Decrypt)?;
    let alg = kind.alg();
    if h[4] != alg as u8 || container.len() < HEADER_LEN + alg.nonce_len() + TAG_LEN {
        return Err(CryptoError::Decrypt);
    }
    let mut key_ref = [0u8; 16];
    key_ref.copy_from_slice(&h[5..]);
    Ok(UnverifiedHeader { kind, alg, key_ref })
}

vectors_pub! {
    /// Seals `plaintext` under `key` with an explicit nonce. Production code uses the typed
    /// functions below, which draw a fresh nonce from the CSPRNG for every call (spec §5.1).
    fn seal_with_nonce(
        key: &[u8; 32],
        context: &Context,
        nonce: &[u8; XCHACHA_NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if context.kind().alg() != Alg::XChaCha20Poly1305 {
            return Err(CryptoError::InvalidInput("this container kind is not sealed by crypto-core"));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidInput("key has the wrong length"))?;
        let aad = context.aad();
        let ciphertext = cipher
            .encrypt(&XNonce::from(*nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| CryptoError::InvalidInput("plaintext is too large"))?;
        let mut out = Vec::with_capacity(HEADER_LEN + XCHACHA_NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&context.header());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

fn seal(key: &[u8; 32], context: &Context, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; XCHACHA_NONCE_LEN] = rng::array()?;
    seal_with_nonce(key, context, &nonce, plaintext)
}

/// Opens a container whose expected context the caller supplies (spec §6.2). Every failure —
/// length, magic, version, kind, algorithm, key_ref, tag — is the same [`CryptoError::Decrypt`].
fn open(key: &[u8; 32], context: &Context, container: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let header = peek_header(container)?;
    if header.kind != context.kind()
        || header.alg != Alg::XChaCha20Poly1305
        || header.key_ref != context.key_ref()
    {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ciphertext) = container
        .get(HEADER_LEN..)
        .and_then(|rest| rest.split_at_checked(XCHACHA_NONCE_LEN))
        .ok_or(CryptoError::Decrypt)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::Decrypt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Decrypt)?;
    let aad = context.aad();
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

fn require_revision(revision: u64) -> Result<()> {
    if revision == 0 {
        Err(CryptoError::InvalidInput("revisions start at 1"))
    } else {
        Ok(())
    }
}

/// Wraps the VMK in the unlock envelope (kind 0x01).
pub fn wrap_vmk_unlock(
    kek: &UnlockKek,
    vmk: &VaultMasterKey,
    account_id: AccountId,
    vmk_id: VmkId,
    kdf_params: KdfParams,
    kdf_salt: KdfSalt,
) -> Result<Vec<u8>> {
    let ctx = Context::UnlockEnvelope {
        account_id,
        vmk_id,
        kdf_params,
        kdf_salt,
    };
    seal(kek.expose_secret(), &ctx, vmk.expose_secret())
}

/// Opens the unlock envelope.
pub fn unwrap_vmk_unlock(
    kek: &UnlockKek,
    envelope: &[u8],
    account_id: AccountId,
    vmk_id: VmkId,
    kdf_params: KdfParams,
    kdf_salt: KdfSalt,
) -> Result<VaultMasterKey> {
    let ctx = Context::UnlockEnvelope {
        account_id,
        vmk_id,
        kdf_params,
        kdf_salt,
    };
    let vmk = open(kek.expose_secret(), &ctx, envelope)?;
    VaultMasterKey::from_slice(&vmk).map_err(|_| CryptoError::Decrypt)
}

/// Wraps the VMK in the recovery envelope (kind 0x02).
pub fn wrap_vmk_recovery(
    kek: &RecoveryKek,
    vmk: &VaultMasterKey,
    account_id: AccountId,
    vmk_id: VmkId,
) -> Result<Vec<u8>> {
    seal(
        kek.expose_secret(),
        &Context::RecoveryEnvelope { account_id, vmk_id },
        vmk.expose_secret(),
    )
}

/// Opens the recovery envelope.
pub fn unwrap_vmk_recovery(
    kek: &RecoveryKek,
    envelope: &[u8],
    account_id: AccountId,
    vmk_id: VmkId,
) -> Result<VaultMasterKey> {
    let vmk = open(
        kek.expose_secret(),
        &Context::RecoveryEnvelope { account_id, vmk_id },
        envelope,
    )?;
    VaultMasterKey::from_slice(&vmk).map_err(|_| CryptoError::Decrypt)
}

/// Wraps an item key under the VMK (kind 0x03).
pub fn wrap_item_key(
    vmk: &VaultMasterKey,
    vmk_id: VmkId,
    item_key: &ItemKey,
    account_id: AccountId,
    item_id: ItemId,
) -> Result<Vec<u8>> {
    seal(
        vmk.expose_secret(),
        &Context::DekWrap {
            account_id,
            item_id,
            vmk_id,
        },
        item_key.expose_secret(),
    )
}

/// Unwraps an item key.
pub fn unwrap_item_key(
    vmk: &VaultMasterKey,
    vmk_id: VmkId,
    wrapped: &[u8],
    account_id: AccountId,
    item_id: ItemId,
) -> Result<ItemKey> {
    let key = open(
        vmk.expose_secret(),
        &Context::DekWrap {
            account_id,
            item_id,
            vmk_id,
        },
        wrapped,
    )?;
    ItemKey::from_slice(&key).map_err(|_| CryptoError::Decrypt)
}

/// Pads and encrypts an item body as `revision` (kind 0x04).
pub fn seal_item(
    item_key: &ItemKey,
    account_id: AccountId,
    item_id: ItemId,
    revision: u64,
    body: &[u8],
) -> Result<Vec<u8>> {
    require_revision(revision)?;
    let padded = padding::pad(body)?;
    seal(
        item_key.expose_secret(),
        &Context::ItemPayload {
            account_id,
            item_id,
            revision,
        },
        &padded,
    )
}

/// Creates an authenticated tombstone for `revision` (kind 0x05).
pub fn seal_tombstone(
    item_key: &ItemKey,
    account_id: AccountId,
    item_id: ItemId,
    revision: u64,
) -> Result<Vec<u8>> {
    require_revision(revision)?;
    seal(
        item_key.expose_secret(),
        &Context::Tombstone {
            account_id,
            item_id,
            revision,
        },
        &[],
    )
}

/// The authenticated content of an item record.
pub enum ItemContent {
    /// The decrypted, unpadded body.
    Body(Zeroizing<Vec<u8>>),
    /// The item was deleted at this revision.
    Deleted,
}

/// Opens an item payload or tombstone that the server says is `revision` of `item_id`.
pub fn open_item(
    item_key: &ItemKey,
    account_id: AccountId,
    item_id: ItemId,
    revision: u64,
    container: &[u8],
) -> Result<ItemContent> {
    if revision == 0 {
        return Err(CryptoError::Decrypt);
    }
    // The kind byte is authenticated: it is part of the AAD checked by `open`.
    match peek_header(container)?.kind {
        Kind::ItemPayload => {
            let padded = open(
                item_key.expose_secret(),
                &Context::ItemPayload {
                    account_id,
                    item_id,
                    revision,
                },
                container,
            )?;
            padding::unpad(&padded).map(ItemContent::Body)
        }
        Kind::Tombstone => {
            let empty = open(
                item_key.expose_secret(),
                &Context::Tombstone {
                    account_id,
                    item_id,
                    revision,
                },
                container,
            )?;
            if empty.is_empty() {
                Ok(ItemContent::Deleted)
            } else {
                Err(CryptoError::Decrypt)
            }
        }
        _ => Err(CryptoError::Decrypt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountId = AccountId::from_bytes([1; 16]);
    const ITEM: ItemId = ItemId::from_bytes([2; 16]);
    const VMK_ID: VmkId = VmkId::from_bytes([3; 16]);
    const SALT: KdfSalt = KdfSalt::from_bytes([4; 16]);

    fn keys() -> (UnlockKek, VaultMasterKey, ItemKey) {
        (
            UnlockKek::from_slice(&[10; 32]).unwrap(),
            VaultMasterKey::from_slice(&[11; 32]).unwrap(),
            ItemKey::from_slice(&[12; 32]).unwrap(),
        )
    }

    #[test]
    fn header_layout() {
        let ctx = Context::DekWrap {
            account_id: ACCOUNT,
            item_id: ITEM,
            vmk_id: VMK_ID,
        };
        let h = ctx.header();
        assert_eq!(&h[..5], &[b'U', b'K', 1, 3, 1]);
        assert_eq!(&h[5..], &[3; 16]);
        assert_eq!(ctx.aad().len(), HEADER_LEN + 32);
    }

    #[test]
    fn unlock_envelope_round_trip_and_binding() {
        let (kek, vmk, _) = keys();
        let params = KdfParams::DEFAULT;
        let env = wrap_vmk_unlock(&kek, &vmk, ACCOUNT, VMK_ID, params, SALT).unwrap();
        assert_eq!(env.len(), HEADER_LEN + 24 + 32 + TAG_LEN);
        let got = unwrap_vmk_unlock(&kek, &env, ACCOUNT, VMK_ID, params, SALT).unwrap();
        assert_eq!(got.expose_secret(), vmk.expose_secret());
        // Any change to trusted context fails (T-5: params/salt swapped by a server).
        let weaker = KdfParams::new(32_768, 2, 1).unwrap();
        assert_eq!(
            unwrap_vmk_unlock(&kek, &env, ACCOUNT, VMK_ID, weaker, SALT)
                .err()
                .unwrap(),
            CryptoError::Decrypt
        );
        let salt2 = KdfSalt::from_bytes([5; 16]);
        assert!(unwrap_vmk_unlock(&kek, &env, ACCOUNT, VMK_ID, params, salt2).is_err());
        assert!(
            unwrap_vmk_unlock(
                &kek,
                &env,
                AccountId::from_bytes([9; 16]),
                VMK_ID,
                params,
                SALT
            )
            .is_err()
        );
        assert!(
            unwrap_vmk_unlock(
                &kek,
                &env,
                ACCOUNT,
                VmkId::from_bytes([9; 16]),
                params,
                SALT
            )
            .is_err()
        );
        let wrong = UnlockKek::from_slice(&[99; 32]).unwrap();
        assert!(unwrap_vmk_unlock(&wrong, &env, ACCOUNT, VMK_ID, params, SALT).is_err());
    }

    #[test]
    fn recovery_envelope_round_trip() {
        let (_, vmk, _) = keys();
        let kek = RecoveryKek::from_slice(&[20; 32]).unwrap();
        let env = wrap_vmk_recovery(&kek, &vmk, ACCOUNT, VMK_ID).unwrap();
        assert_eq!(
            unwrap_vmk_recovery(&kek, &env, ACCOUNT, VMK_ID)
                .unwrap()
                .expose_secret(),
            vmk.expose_secret()
        );
        // An unlock envelope can never be opened as a recovery envelope (kind mismatch).
        let unlock_kek = UnlockKek::from_slice(&[20; 32]).unwrap();
        let unlock_env =
            wrap_vmk_unlock(&unlock_kek, &vmk, ACCOUNT, VMK_ID, KdfParams::DEFAULT, SALT).unwrap();
        assert!(unwrap_vmk_recovery(&kek, &unlock_env, ACCOUNT, VMK_ID).is_err());
    }

    #[test]
    fn item_key_is_bound_to_item() {
        let (_, vmk, dek) = keys();
        let wrapped = wrap_item_key(&vmk, VMK_ID, &dek, ACCOUNT, ITEM).unwrap();
        assert_eq!(
            unwrap_item_key(&vmk, VMK_ID, &wrapped, ACCOUNT, ITEM)
                .unwrap()
                .expose_secret(),
            dek.expose_secret()
        );
        // T-4: moving the wrap to another item fails.
        assert!(
            unwrap_item_key(&vmk, VMK_ID, &wrapped, ACCOUNT, ItemId::from_bytes([7; 16])).is_err()
        );
    }

    #[test]
    fn item_payload_round_trip_and_revision_binding() {
        let (_, _, dek) = keys();
        let body = br#"{"schema":1,"type":"login","title":"x"}"#;
        let c = seal_item(&dek, ACCOUNT, ITEM, 5, body).unwrap();
        assert_eq!(c.len(), HEADER_LEN + 24 + 512 + TAG_LEN);
        match open_item(&dek, ACCOUNT, ITEM, 5, &c).unwrap() {
            ItemContent::Body(b) => assert_eq!(b.as_slice(), body),
            ItemContent::Deleted => panic!("expected a body"),
        }
        // T-4: old payload presented as a newer revision fails.
        assert!(open_item(&dek, ACCOUNT, ITEM, 6, &c).is_err());
        assert!(open_item(&dek, ACCOUNT, ITEM, 0, &c).is_err());
        assert!(seal_item(&dek, ACCOUNT, ITEM, 0, body).is_err());
    }

    #[test]
    fn tombstones_are_authenticated() {
        let (_, _, dek) = keys();
        let t = seal_tombstone(&dek, ACCOUNT, ITEM, 3).unwrap();
        assert!(matches!(
            open_item(&dek, ACCOUNT, ITEM, 3, &t).unwrap(),
            ItemContent::Deleted
        ));
        // T-6: a server cannot forge one without the item key.
        let other = ItemKey::from_slice(&[13; 32]).unwrap();
        let forged = seal_tombstone(&other, ACCOUNT, ITEM, 3).unwrap();
        assert!(open_item(&dek, ACCOUNT, ITEM, 3, &forged).is_err());
    }

    #[test]
    fn every_tampering_gives_the_same_error() {
        let (_, _, dek) = keys();
        let c = seal_item(&dek, ACCOUNT, ITEM, 1, b"secret").unwrap();
        for i in 0..c.len() {
            let mut bad = c.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                open_item(&dek, ACCOUNT, ITEM, 1, &bad).err().unwrap(),
                CryptoError::Decrypt,
                "byte {i}"
            );
        }
        for len in [
            0,
            1,
            HEADER_LEN,
            HEADER_LEN + 24,
            HEADER_LEN + 24 + 15,
            c.len() - 1,
        ] {
            assert_eq!(
                open_item(&dek, ACCOUNT, ITEM, 1, &c[..len]).err().unwrap(),
                CryptoError::Decrypt
            );
        }
        let mut longer = c.clone();
        longer.push(0);
        assert_eq!(
            open_item(&dek, ACCOUNT, ITEM, 1, &longer).err().unwrap(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn nonces_are_fresh_per_call() {
        let (_, _, dek) = keys();
        let a = seal_item(&dek, ACCOUNT, ITEM, 1, b"same").unwrap();
        let b = seal_item(&dek, ACCOUNT, ITEM, 1, b"same").unwrap();
        assert_ne!(
            a[HEADER_LEN..HEADER_LEN + 24],
            b[HEADER_LEN..HEADER_LEN + 24]
        );
        assert_ne!(a, b);
    }

    #[test]
    fn local_wrap_is_not_sealed_here_but_has_aad() {
        let ctx = Context::LocalSecretKeyWrap {
            account_id: ACCOUNT,
            device_id: DeviceId::from_bytes([6; 16]),
        };
        assert_eq!(ctx.header()[4], Alg::Aes256Gcm as u8);
        assert_eq!(ctx.aad().len(), HEADER_LEN + 16 + 4 + 16);
        assert!(seal_with_nonce(&[0; 32], &ctx, &[0; 24], b"x").is_err());
    }

    #[test]
    fn peek_rejects_unknown_formats() {
        let (_, _, dek) = keys();
        let c = seal_item(&dek, ACCOUNT, ITEM, 1, b"x").unwrap();
        assert_eq!(peek_header(&c).unwrap().kind, Kind::ItemPayload);
        for (i, v) in [(0, b'X'), (2, 2), (3, 0), (3, 8), (4, 2)] {
            let mut bad = c.clone();
            bad[i] = v;
            assert_eq!(peek_header(&bad).unwrap_err(), CryptoError::Decrypt);
        }
    }
}
