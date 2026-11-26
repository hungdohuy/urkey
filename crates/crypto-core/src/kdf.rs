//! Key derivation (spec §4): the unlock root from master password + Account Secret Key, and the
//! recovery root from the Recovery Key. Each root is expanded with distinct HKDF labels into a
//! key-encryption key and an Ed25519 authentication key (spec §4.4).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::ids::{AccountId, KdfSalt};
use crate::lp::push_lp;
use crate::secret::{AccountSecretKey, RecoveryKek, RecoveryKey, UnlockKek};
use crate::sign::AuthKey;
use crate::{CryptoError, Result};

const LABEL_UNLOCK_ROOT: &[u8] = b"urkey/v1/unlock-root";
const LABEL_KEK_UNLOCK: &[u8] = b"urkey/v1/kek/unlock";
const LABEL_AUTH_ACCOUNT: &[u8] = b"urkey/v1/auth/account-ed25519";
const LABEL_RECOVERY_ROOT: &[u8] = b"urkey/v1/recovery-root";
const LABEL_KEK_RECOVERY: &[u8] = b"urkey/v1/kek/recovery";
const LABEL_AUTH_RECOVERY: &[u8] = b"urkey/v1/auth/recovery-ed25519";

/// Algorithm id for Argon2id v1.3 in the encoded parameters.
const KDF_ALG_ARGON2ID: u8 = 0x01;

/// Argon2id parameters, fixed per account (spec §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl KdfParams {
    /// Encoded length: `alg(1) ‖ u32be(m_kib) ‖ u32be(t) ‖ u32be(p)`.
    pub const ENCODED_LEN: usize = 13;
    /// Default for new accounts: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Self = Self {
        m_kib: 65_536,
        t: 3,
        p: 1,
    };
    /// Lowest memory cost clients accept (downgrade protection).
    pub const MIN_M_KIB: u32 = 32_768;
    /// Lowest pass count clients accept.
    pub const MIN_T: u32 = 2;
    /// Highest memory cost clients accept (exhaustion protection): 1 GiB.
    pub const MAX_M_KIB: u32 = 1_048_576;
    /// Highest pass count clients accept.
    pub const MAX_T: u32 = 20;

    /// Validates parameters against the floor and ceiling.
    pub fn new(m_kib: u32, t: u32, p: u32) -> Result<Self> {
        let ok = (Self::MIN_M_KIB..=Self::MAX_M_KIB).contains(&m_kib)
            && (Self::MIN_T..=Self::MAX_T).contains(&t)
            && p >= 1
            && Params::new(m_kib, t, p, Some(32)).is_ok();
        if ok {
            Ok(Self { m_kib, t, p })
        } else {
            Err(CryptoError::KdfParamsRejected)
        }
    }

    /// Memory cost in KiB.
    pub const fn m_kib(&self) -> u32 {
        self.m_kib
    }
    /// Number of passes.
    pub const fn t(&self) -> u32 {
        self.t
    }
    /// Degree of parallelism (lanes).
    pub const fn p(&self) -> u32 {
        self.p
    }

    /// The 13-byte wire encoding (also part of the unlock envelope's AAD).
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = KDF_ALG_ARGON2ID;
        out[1..5].copy_from_slice(&self.m_kib.to_be_bytes());
        out[5..9].copy_from_slice(&self.t.to_be_bytes());
        out[9..13].copy_from_slice(&self.p.to_be_bytes());
        out
    }

    /// Decodes and validates the wire encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; Self::ENCODED_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::KdfParamsRejected)?;
        if bytes[0] != KDF_ALG_ARGON2ID {
            return Err(CryptoError::KdfParamsRejected);
        }
        let word =
            |i: usize| u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        Self::new(word(1), word(5), word(9))
    }

    /// Builds parameters without the floor check. Only for test vectors that need fast,
    /// deliberately weak parameters.
    #[cfg(feature = "test-vectors")]
    pub fn new_unchecked_for_vectors(m_kib: u32, t: u32, p: u32) -> Self {
        Self { m_kib, t, p }
    }
}

/// Keys derived from the master password and Account Secret Key.
#[derive(Debug)]
pub struct UnlockKeys {
    /// Wraps the VMK in the unlock envelope.
    pub kek: UnlockKek,
    /// Signs login and step-up challenges.
    pub auth: AuthKey,
}

/// Keys derived from the Recovery Key.
#[derive(Debug)]
pub struct RecoveryKeys {
    /// Wraps the VMK in the recovery envelope.
    pub kek: RecoveryKek,
    /// Signs recovery challenges.
    pub auth: AuthKey,
}

/// Normalizes the master password: `UTF-8(NFKC(PW))`, no trimming or case folding (spec §3.1).
fn normalize_password(password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let normalized: Zeroizing<String> = Zeroizing::new(password.nfkc().collect());
    if normalized.is_empty() {
        return Err(CryptoError::InvalidInput("the master password is empty"));
    }
    Ok(Zeroizing::new(normalized.as_bytes().to_vec()))
}

/// Argon2id stage of the unlock derivation: `P` in spec §4.1.
fn stretch_password(
    password: &str,
    salt: &KdfSalt,
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let pw = normalize_password(password)?;
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| CryptoError::KdfParamsRejected)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&pw, salt.as_bytes(), out.as_mut())
        .map_err(|_| CryptoError::KdfParamsRejected)?;
    Ok(out)
}

fn root_salt(label: &[u8], account_id: &AccountId) -> Vec<u8> {
    let mut salt = Vec::with_capacity(4 + label.len() + AccountId::LEN);
    push_lp(&mut salt, label);
    salt.extend_from_slice(account_id.as_bytes());
    salt
}

fn expand_32(hk: &Hkdf<Sha256>, label: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA-256's 8160-byte limit; fail closed regardless.
    hk.expand(label, out.as_mut())
        .map_err(|_| CryptoError::InvalidInput("key derivation failed"))?;
    Ok(out)
}

/// Derives the unlock KEK and account auth key (spec §4.1).
///
/// `params` must come from [`KdfParams::new`]/[`KdfParams::decode`], so weak parameters supplied
/// by a server are rejected before any work is done.
pub fn derive_unlock(
    password: &str,
    secret_key: &AccountSecretKey,
    account_id: &AccountId,
    salt: &KdfSalt,
    params: &KdfParams,
) -> Result<UnlockKeys> {
    let p = stretch_password(password, salt, params)?;
    let mut ikm = Zeroizing::new([0u8; 48]);
    ikm[..32].copy_from_slice(p.as_ref());
    ikm[32..].copy_from_slice(secret_key.expose_secret());
    let (mut prk, hk) = Hkdf::<Sha256>::extract(
        Some(&root_salt(LABEL_UNLOCK_ROOT, account_id)),
        ikm.as_ref(),
    );
    prk.as_mut_slice().zeroize();
    let kek = expand_32(&hk, LABEL_KEK_UNLOCK)?;
    let auth_seed = expand_32(&hk, LABEL_AUTH_ACCOUNT)?;
    Ok(UnlockKeys {
        kek: UnlockKek::from_slice(kek.as_ref())?,
        auth: AuthKey::from_seed(&auth_seed),
    })
}

/// Derives the recovery KEK and recovery auth key (spec §4.3).
pub fn derive_recovery(recovery_key: &RecoveryKey, account_id: &AccountId) -> Result<RecoveryKeys> {
    let (mut prk, hk) = Hkdf::<Sha256>::extract(
        Some(&root_salt(LABEL_RECOVERY_ROOT, account_id)),
        recovery_key.expose_secret(),
    );
    prk.as_mut_slice().zeroize();
    let kek = expand_32(&hk, LABEL_KEK_RECOVERY)?;
    let auth_seed = expand_32(&hk, LABEL_AUTH_RECOVERY)?;
    Ok(RecoveryKeys {
        kek: RecoveryKek::from_slice(kek.as_ref())?,
        auth: AuthKey::from_seed(&auth_seed),
    })
}

/// Intermediate values of the unlock derivation, exposed only for test vectors.
#[cfg(feature = "test-vectors")]
pub fn unlock_intermediates_for_vectors(
    password: &str,
    secret_key: &AccountSecretKey,
    account_id: &AccountId,
    salt: &KdfSalt,
    params: &KdfParams,
) -> Result<([u8; 32], [u8; 32])> {
    let p = stretch_password(password, salt, params)?;
    let mut ikm = Zeroizing::new([0u8; 48]);
    ikm[..32].copy_from_slice(p.as_ref());
    ikm[32..].copy_from_slice(secret_key.expose_secret());
    let (prk, _) = Hkdf::<Sha256>::extract(
        Some(&root_salt(LABEL_UNLOCK_ROOT, account_id)),
        ikm.as_ref(),
    );
    let mut u = [0u8; 32];
    u.copy_from_slice(prk.as_slice());
    Ok((*p, u))
}

/// Recovery root `R`, exposed only for test vectors.
#[cfg(feature = "test-vectors")]
pub fn recovery_root_for_vectors(recovery_key: &RecoveryKey, account_id: &AccountId) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(
        Some(&root_salt(LABEL_RECOVERY_ROOT, account_id)),
        recovery_key.expose_secret(),
    );
    let mut r = [0u8; 32];
    r.copy_from_slice(prk.as_slice());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Weakest accepted parameters, to keep tests fast.
    fn fast() -> KdfParams {
        KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1).unwrap()
    }

    fn inputs() -> (AccountSecretKey, AccountId, KdfSalt) {
        (
            AccountSecretKey::from_slice(&[1; 16]).unwrap(),
            AccountId::from_bytes([2; 16]),
            KdfSalt::from_bytes([3; 16]),
        )
    }

    #[test]
    fn params_floor_and_ceiling() {
        assert!(KdfParams::new(KdfParams::MIN_M_KIB - 1, 3, 1).is_err());
        assert!(KdfParams::new(65_536, 1, 1).is_err());
        assert!(KdfParams::new(KdfParams::MAX_M_KIB + 1, 3, 1).is_err());
        assert!(KdfParams::new(65_536, 21, 1).is_err());
        assert!(KdfParams::new(65_536, 3, 0).is_err());
        assert!(KdfParams::new(65_536, 3, 1).is_ok());
    }

    #[test]
    fn params_encoding_round_trip_and_rejection() {
        let enc = KdfParams::DEFAULT.encode();
        assert_eq!(enc, [1, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1]);
        assert_eq!(KdfParams::decode(&enc).unwrap(), KdfParams::DEFAULT);
        let mut wrong_alg = enc;
        wrong_alg[0] = 2;
        assert_eq!(
            KdfParams::decode(&wrong_alg),
            Err(CryptoError::KdfParamsRejected)
        );
        assert!(KdfParams::decode(&enc[..12]).is_err());
        let weak = [1, 0, 0, 0x10, 0, 0, 0, 0, 1, 0, 0, 0, 1];
        assert_eq!(
            KdfParams::decode(&weak),
            Err(CryptoError::KdfParamsRejected)
        );
    }

    #[test]
    fn unlock_derivation_is_deterministic_and_separated() {
        let (ask, id, salt) = inputs();
        let a = derive_unlock("correct horse", &ask, &id, &salt, &fast()).unwrap();
        let b = derive_unlock("correct horse", &ask, &id, &salt, &fast()).unwrap();
        assert_eq!(a.kek.expose_secret(), b.kek.expose_secret());
        assert_eq!(a.auth.public_key(), b.auth.public_key());
        // KEK and auth seed come from different labels.
        assert_ne!(a.kek.expose_secret(), &a.auth.public_key());
    }

    #[test]
    fn every_unlock_input_matters() {
        let (ask, id, salt) = inputs();
        let base = derive_unlock("pw", &ask, &id, &salt, &fast()).unwrap();
        let other_ask = AccountSecretKey::from_slice(&[9; 16]).unwrap();
        let variants = [
            derive_unlock("pw2", &ask, &id, &salt, &fast()).unwrap(),
            derive_unlock("pw", &other_ask, &id, &salt, &fast()).unwrap(),
            derive_unlock("pw", &ask, &AccountId::from_bytes([7; 16]), &salt, &fast()).unwrap(),
            derive_unlock("pw", &ask, &id, &KdfSalt::from_bytes([8; 16]), &fast()).unwrap(),
            derive_unlock(
                "pw",
                &ask,
                &id,
                &salt,
                &KdfParams::new(32_768, 3, 1).unwrap(),
            )
            .unwrap(),
        ];
        for v in &variants {
            assert_ne!(v.kek.expose_secret(), base.kek.expose_secret());
            assert_ne!(v.auth.public_key(), base.auth.public_key());
        }
    }

    #[test]
    fn password_is_nfkc_normalized_but_not_trimmed() {
        let (ask, id, salt) = inputs();
        // U+FB01 LATIN SMALL LIGATURE FI normalizes to "fi" under NFKC.
        let a = derive_unlock("\u{FB01}", &ask, &id, &salt, &fast()).unwrap();
        let b = derive_unlock("fi", &ask, &id, &salt, &fast()).unwrap();
        assert_eq!(a.kek.expose_secret(), b.kek.expose_secret());
        let c = derive_unlock("fi ", &ask, &id, &salt, &fast()).unwrap();
        assert_ne!(c.kek.expose_secret(), b.kek.expose_secret());
    }

    #[test]
    fn empty_password_is_rejected() {
        let (ask, id, salt) = inputs();
        assert!(matches!(
            derive_unlock("", &ask, &id, &salt, &fast()),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    #[test]
    fn recovery_derivation_is_separated_from_unlock() {
        let (ask, id, salt) = inputs();
        let rk = RecoveryKey::from_slice(&[1; 32]).unwrap();
        let r = derive_recovery(&rk, &id).unwrap();
        let r2 = derive_recovery(&rk, &AccountId::from_bytes([5; 16])).unwrap();
        assert_ne!(r.kek.expose_secret(), r2.kek.expose_secret());
        let u = derive_unlock("pw", &ask, &id, &salt, &fast()).unwrap();
        assert_ne!(r.kek.expose_secret(), u.kek.expose_secret());
        assert_ne!(r.auth.public_key(), u.auth.public_key());
    }
}
