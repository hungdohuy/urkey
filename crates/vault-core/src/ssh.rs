//! OpenSSH private keys (crypto design §11.3, R-SSH-1): import, and signing for the agent.
//!
//! Supported for signing: Ed25519 and ECDSA P-256. RSA keys can be imported and stored but are
//! never used to sign in V1 (ADR 0008). Passphrase-protected keys are decrypted once at import and
//! stored unencrypted inside the item, which the item key protects.

use signature::Signer;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::item::{SshAgentSettings, SshKeyFields};

use crate::{Result, VaultError};
/// Re-exported so the agent and CLI use exactly the pinned `ssh-key` version (ADR 0016).
pub use ssh_key;

/// The user-facing key type string stored in the item.
fn key_type(alg: &Algorithm) -> Result<&'static str> {
    match alg {
        Algorithm::Ed25519 => Ok("ed25519"),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => Ok("ecdsa-p256"),
        Algorithm::Rsa { .. } => Ok("rsa"),
        _ => Err(VaultError::Invalid(
            "unsupported SSH key type (use Ed25519 or ECDSA P-256)",
        )),
    }
}

/// Parses an OpenSSH private key (decrypting it with `passphrase` if needed) into item fields.
pub fn import_openssh(pem: &str, passphrase: Option<&str>) -> Result<SshKeyFields> {
    let key = PrivateKey::from_openssh(pem.trim())
        .map_err(|_| VaultError::Invalid("not an OpenSSH private key"))?;
    let key = if key.is_encrypted() {
        let pass = passphrase.ok_or(VaultError::Invalid("this key needs its passphrase"))?;
        key.decrypt(pass)
            .map_err(|_| VaultError::Invalid("wrong passphrase"))?
    } else {
        key
    };
    let key_type = key_type(&key.algorithm())?;
    let private_key: Zeroizing<String> = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| VaultError::Invalid("could not re-encode the key"))?;
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|_| VaultError::Invalid("could not encode the public key"))?;
    Ok(SshKeyFields {
        private_key: private_key.to_string(),
        public_key,
        key_type: key_type.to_owned(),
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        comment: key.comment().as_str_lossy().to_owned(),
        agent: SshAgentSettings {
            enabled: key_type != "rsa",
        },
        extra: serde_json::Map::new(),
    })
}

/// A key loaded for the SSH agent. Wiped on drop (by `ssh-key`).
pub struct AgentKey {
    key: PrivateKey,
    comment: String,
}

impl core::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentKey")
            .field("comment", &self.comment)
            .finish_non_exhaustive()
    }
}

impl AgentKey {
    /// Loads a stored key for signing. Re-derives the public key and fingerprint and rejects the
    /// item if they do not match what was stored (data-model §1.4), and rejects RSA (ADR 0008).
    pub fn from_fields(fields: &SshKeyFields) -> Result<Self> {
        let key = PrivateKey::from_openssh(fields.private_key.trim())
            .map_err(|_| VaultError::Invalid("stored SSH key is damaged"))?;
        if key.is_encrypted() {
            return Err(VaultError::Invalid("stored SSH key is damaged"));
        }
        match key.algorithm() {
            Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => {}
            _ => {
                return Err(VaultError::Invalid(
                    "this key type cannot be used by the agent",
                ));
            }
        }
        let public = key
            .public_key()
            .to_openssh()
            .map_err(|_| VaultError::Invalid("stored SSH key is damaged"))?;
        let same_public = public
            .split_whitespace()
            .take(2)
            .eq(fields.public_key.split_whitespace().take(2));
        if !same_public || key.fingerprint(HashAlg::Sha256).to_string() != fields.fingerprint {
            return Err(VaultError::Invalid(
                "stored SSH key does not match its public key",
            ));
        }
        Ok(Self {
            key,
            comment: fields.comment.clone(),
        })
    }

    /// Wraps an already-decrypted key (e.g. received by the agent). Only Ed25519 and ECDSA P-256
    /// are accepted (ADR 0008).
    pub fn from_private_key(key: PrivateKey, comment: String) -> Result<Self> {
        if key.is_encrypted() {
            return Err(VaultError::Invalid("key is encrypted"));
        }
        match key.algorithm() {
            Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => Ok(Self { key, comment }),
            _ => Err(VaultError::Invalid(
                "this key type cannot be used by the agent",
            )),
        }
    }

    /// The decoded private key (to hand to the agent).
    pub fn private_key(&self) -> &PrivateKey {
        &self.key
    }

    /// The SSH wire encoding of the public key (the agent's identity blob).
    pub fn public_key_blob(&self) -> Result<Vec<u8>> {
        self.key
            .public_key()
            .to_bytes()
            .map_err(|_| VaultError::Invalid("could not encode the public key"))
    }

    /// The key comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Signs `data` and returns the SSH signature blob (`string alg ‖ string sig`).
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use ssh_key::encoding::Encode;
        let sig: ssh_key::Signature = self
            .key
            .try_sign(data)
            .map_err(|_| VaultError::Invalid("signing failed"))?;
        sig.encode_vec()
            .map_err(|_| VaultError::Invalid("signing failed"))
    }

    /// Verifies a signature blob produced by [`AgentKey::sign`] (used by tests and the agent's self-check).
    pub fn verify(&self, data: &[u8], blob: &[u8]) -> Result<()> {
        use signature::Verifier;
        use ssh_key::encoding::Decode;
        let sig = ssh_key::Signature::decode(&mut &blob[..])
            .map_err(|_| VaultError::Invalid("bad signature"))?;
        self.key
            .public_key()
            .key_data()
            .verify(data, &sig)
            .map_err(|_| VaultError::Invalid("bad signature"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::getrandom::SysRng;
    use ssh_key::rand_core::UnwrapErr;

    fn generate(alg: Algorithm) -> String {
        let mut key = PrivateKey::random(&mut UnwrapErr(SysRng), alg).unwrap();
        key.set_comment("test-only");
        key.to_openssh(LineEnding::LF).unwrap().to_string()
    }

    #[test]
    fn ed25519_and_p256_import_and_sign() {
        for alg in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        ] {
            let fields = import_openssh(&generate(alg.clone()), None).unwrap();
            assert!(fields.fingerprint.starts_with("SHA256:"));
            assert_eq!(fields.comment, "test-only");
            assert!(fields.agent.enabled);
            let key = AgentKey::from_fields(&fields).unwrap();
            let sig = key.sign(b"session data").unwrap();
            key.verify(b"session data", &sig).unwrap();
            assert!(key.verify(b"other data", &sig).is_err());
        }
    }

    #[test]
    fn encrypted_key_needs_correct_passphrase() {
        let key = PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ed25519).unwrap();
        let pem = key
            .encrypt(&mut SysRng, "test-only-passphrase")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();
        assert!(import_openssh(&pem, None).is_err());
        assert!(import_openssh(&pem, Some("wrong")).is_err());
        let fields = import_openssh(&pem, Some("test-only-passphrase")).unwrap();
        assert!(!fields.private_key.contains("aes256"));
        AgentKey::from_fields(&fields).unwrap();
    }

    #[test]
    fn tampered_public_key_is_rejected() {
        let mut a = import_openssh(&generate(Algorithm::Ed25519), None).unwrap();
        let b = import_openssh(&generate(Algorithm::Ed25519), None).unwrap();
        a.public_key = b.public_key;
        assert!(AgentKey::from_fields(&a).is_err());
    }

    #[test]
    fn garbage_is_rejected_without_echo() {
        let Err(err) = import_openssh("-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETSTUFF\n", None)
        else {
            panic!("garbage was accepted");
        };
        assert!(!err.to_string().contains("SECRET"));
    }

    /// RSA keys are stored but never used for signing (ADR 0008). Uses ssh-keygen when present.
    #[test]
    fn rsa_is_stored_but_not_signable() {
        let dir = std::env::temp_dir().join(format!("urkey-rsa-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "rsa",
                "-b",
                "2048",
                "-N",
                "",
                "-C",
                "test-only",
                "-f",
            ])
            .arg(&path)
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            let pem = std::fs::read_to_string(&path).unwrap();
            let fields = import_openssh(&pem, None).unwrap();
            assert_eq!(fields.key_type, "rsa");
            assert!(!fields.agent.enabled);
            assert!(AgentKey::from_fields(&fields).is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
