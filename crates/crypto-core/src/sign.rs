//! Ed25519 authentication keys and the exact messages they sign (spec §7.1, §7.4, §7.7–§7.9).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ids::{AccountId, DeviceId};
use crate::lp::push_lp;
use crate::{CryptoError, Result, rng};

const LABEL_CREATE: &[u8] = b"urkey/v1/sig/create";
const LABEL_LOGIN: &[u8] = b"urkey/v1/sig/login";
const LABEL_RECOVERY: &[u8] = b"urkey/v1/sig/recovery";
const LABEL_STEPUP: &[u8] = b"urkey/v1/sig/stepup";
const LABEL_REFRESH: &[u8] = b"urkey/v1/sig/refresh";

/// Length of a server challenge nonce.
pub const CHALLENGE_LEN: usize = 32;

/// An Ed25519 signing key: the account auth key, the recovery auth key, or a device key.
/// The secret half is zeroized on drop; `Debug` shows only the public key.
pub struct AuthKey(SigningKey);

impl AuthKey {
    /// Builds a key from a 32-byte seed (RFC 8032 secret key).
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Generates a random device key (spec §3, device key pair).
    pub fn generate_device_key() -> Result<Self> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(rng::array()?);
        Ok(Self::from_seed(&seed))
    }

    /// Generates a random device key seed to store (Keychain / WebCrypto) and reload later
    /// with [`AuthKey::device_key_from_seed`].
    pub fn generate_device_seed() -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(rng::array()?))
    }

    /// Loads a device key from its stored 32-byte seed. Also used by test vectors.
    pub fn device_key_from_seed(seed: &[u8; 32]) -> Self {
        Self::from_seed(seed)
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs a message built by one of this module's `*_message` functions.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl core::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// Verifies a signature with strict RFC 8032 checks (rejects small-order and non-canonical inputs).
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| CryptoError::InvalidInput("invalid public key"))?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidInput("signature does not verify"))
}

/// SHA-256, used for request-body hashes in signed messages.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `LP("urkey/v1/sig/create") ‖ account_id ‖ SHA-256(request body without signatures)` (§7.1).
pub fn create_message(account_id: &AccountId, body_sha256: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + LABEL_CREATE.len() + 16 + 32);
    push_lp(&mut m, LABEL_CREATE);
    m.extend_from_slice(account_id.as_bytes());
    m.extend_from_slice(body_sha256);
    m
}

/// `LP("urkey/v1/sig/login") ‖ account_id ‖ nonce ‖ device_id ‖ device_pk ‖ LP(api_origin)` (§7.4).
pub fn login_message(
    account_id: &AccountId,
    nonce: &[u8; CHALLENGE_LEN],
    device_id: &DeviceId,
    device_pk: &[u8; 32],
    api_origin: &str,
) -> Vec<u8> {
    let mut m = Vec::new();
    push_lp(&mut m, LABEL_LOGIN);
    m.extend_from_slice(account_id.as_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(device_id.as_bytes());
    m.extend_from_slice(device_pk);
    push_lp(&mut m, api_origin.as_bytes());
    m
}

/// `LP("urkey/v1/sig/recovery") ‖ account_id ‖ nonce ‖ device_pk ‖ LP(api_origin)` (§7.7).
pub fn recovery_message(
    account_id: &AccountId,
    nonce: &[u8; CHALLENGE_LEN],
    device_pk: &[u8; 32],
    api_origin: &str,
) -> Vec<u8> {
    let mut m = Vec::new();
    push_lp(&mut m, LABEL_RECOVERY);
    m.extend_from_slice(account_id.as_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(device_pk);
    push_lp(&mut m, api_origin.as_bytes());
    m
}

/// `LP("urkey/v1/sig/stepup") ‖ account_id ‖ nonce ‖ LP(operation) ‖ SHA-256(request body)` (§7.8).
pub fn stepup_message(
    account_id: &AccountId,
    nonce: &[u8; CHALLENGE_LEN],
    operation: &str,
    body_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::new();
    push_lp(&mut m, LABEL_STEPUP);
    m.extend_from_slice(account_id.as_bytes());
    m.extend_from_slice(nonce);
    push_lp(&mut m, operation.as_bytes());
    m.extend_from_slice(body_sha256);
    m
}

/// `LP("urkey/v1/sig/refresh") ‖ account_id ‖ nonce ‖ device_id` (§7.9).
pub fn refresh_message(
    account_id: &AccountId,
    nonce: &[u8; CHALLENGE_LEN],
    device_id: &DeviceId,
) -> Vec<u8> {
    let mut m = Vec::new();
    push_lp(&mut m, LABEL_REFRESH);
    m.extend_from_slice(account_id.as_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(device_id.as_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let key = AuthKey::generate_device_key().unwrap();
        let msg = refresh_message(
            &AccountId::from_bytes([1; 16]),
            &[2; 32],
            &DeviceId::from_bytes([3; 16]),
        );
        let sig = key.sign(&msg);
        assert!(verify(&key.public_key(), &msg, &sig).is_ok());
        let mut tampered = msg.clone();
        tampered[10] ^= 1;
        assert!(verify(&key.public_key(), &tampered, &sig).is_err());
    }

    #[test]
    fn rfc8032_test_1() {
        // RFC 8032 §7.1 TEST 1 (empty message).
        let seed: [u8; 32] =
            hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let key = AuthKey::from_seed(&seed);
        assert_eq!(
            key.public_key(),
            hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let sig = key.sign(b"");
        assert_eq!(
            sig[..32],
            hex32("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
        );
        assert_eq!(
            sig[32..],
            hex32("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        );
    }

    #[test]
    fn messages_are_domain_separated() {
        let id = AccountId::from_bytes([1; 16]);
        let dev = DeviceId::from_bytes([2; 16]);
        let n = [3; 32];
        let msgs = [
            create_message(&id, &[0; 32]),
            login_message(&id, &n, &dev, &[4; 32], "https://api.example"),
            recovery_message(&id, &n, &[4; 32], "https://api.example"),
            stepup_message(&id, &n, "op", &[0; 32]),
            refresh_message(&id, &n, &dev),
        ];
        for (i, a) in msgs.iter().enumerate() {
            for b in &msgs[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(msgs[1].starts_with(&[0, 0, 0, 18]));
        assert_eq!(&msgs[1][4..22], b"urkey/v1/sig/login");
    }

    #[test]
    fn debug_does_not_show_secret() {
        let key = AuthKey::from_seed(&[0x42; 32]);
        let shown = format!("{key:?}");
        assert!(shown.starts_with("AuthKey { public_key"));
        assert!(!shown.contains("66, 66, 66"));
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
