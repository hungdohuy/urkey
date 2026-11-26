//! Errors. Messages are fixed strings and never contain secrets or item content.

use crypto_core::CryptoError;

/// Every error this crate returns.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// A cryptographic operation failed (see [`CryptoError`]; decryption failures carry no detail).
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The item or input does not satisfy the data model; the reason is a fixed string.
    #[error("invalid: {0}")]
    Invalid(&'static str),
    /// The item body uses a schema newer than this client understands (read-only).
    #[error("this item needs a newer version of urkey to edit")]
    UnsupportedSchema,
    /// The operating system's random number generator failed.
    #[error("secure random number generator unavailable")]
    Rng,
}
