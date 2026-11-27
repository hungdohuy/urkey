//! Secret key types (spec §3, §8.3). Every type here zeroizes on drop, is not `Clone`, and has no
//! `Debug` or `Display` at all, so secrets cannot be printed by accident (owner decision O-2; the
//! guard in `no_debug.rs` fails the build if one gains `Debug`).

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result, rng};

macro_rules! secret_bytes {
    ($(#[$meta:meta])* $name:ident, $len:literal) => {
        $(#[$meta])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Generates a new random value from the OS CSPRNG.
            pub fn generate() -> Result<Self> {
                let mut key = Self([0u8; $len]);
                rng::fill(&mut key.0)?;
                Ok(key)
            }

            /// Copies a secret from a slice of exactly the right length. The caller remains
            /// responsible for wiping its own copy.
            pub fn from_slice(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $len {
                    return Err(CryptoError::InvalidInput(concat!(stringify!($name), " has the wrong length")));
                }
                let mut key = Self([0u8; $len]);
                key.0.copy_from_slice(bytes);
                Ok(key)
            }

            /// Borrows the raw secret bytes. Do not copy them into memory that is not wiped.
            pub fn expose_secret(&self) -> &[u8; $len] {
                &self.0
            }
        }
    };
}

secret_bytes!(
    /// Account Secret Key (ASK), 128 bits (spec §3).
    AccountSecretKey, 16
);
secret_bytes!(
    /// Recovery Key (RK), 256 bits (spec §3).
    RecoveryKey, 32
);
secret_bytes!(
    /// Vault Master Key (VMK). Only ever wraps item keys (spec §4.4).
    VaultMasterKey, 32
);
secret_bytes!(
    /// Per-item data-encryption key (DEK).
    ItemKey, 32
);
secret_bytes!(
    /// Key-encryption key derived from password + Secret Key; wraps the VMK in the unlock envelope.
    UnlockKek, 32
);
secret_bytes!(
    /// Key-encryption key derived from the Recovery Key; wraps the VMK in the recovery envelope.
    RecoveryKek, 32
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_length_is_rejected() {
        assert!(AccountSecretKey::from_slice(&[0; 15]).is_err());
        assert!(RecoveryKey::from_slice(&[0; 33]).is_err());
    }

    #[test]
    fn generated_keys_differ() {
        let a = ItemKey::generate().unwrap();
        let b = ItemKey::generate().unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }
}
