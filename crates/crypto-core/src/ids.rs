//! Public 16-byte identifiers and salts (spec §3). These are not secret.

use crate::{CryptoError, Result, rng};

macro_rules! public_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = 16;

            /// Generates a new random value from the OS CSPRNG.
            pub fn generate() -> Result<Self> {
                rng::array().map(Self)
            }

            /// Wraps existing bytes.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Parses from a slice of exactly 16 bytes.
            pub fn from_slice(bytes: &[u8]) -> Result<Self> {
                <[u8; 16]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| CryptoError::InvalidInput(concat!(stringify!($name), " must be 16 bytes")))
            }

            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

public_id!(
    /// Account identifier, chosen by the client at account creation.
    AccountId
);
public_id!(
    /// Item identifier, chosen by the client at item creation.
    ItemId
);
public_id!(
    /// Identifies one generation of the Vault Master Key.
    VmkId
);
public_id!(
    /// Device identifier.
    DeviceId
);
public_id!(
    /// Snapshot identifier.
    SnapshotId
);
public_id!(
    /// Argon2id salt for the unlock derivation (spec §4.1).
    KdfSalt
);
