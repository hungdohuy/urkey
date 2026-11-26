//! urkey vault domain logic.
//!
//! - [`item`]: item plaintext model and validation (`docs/architecture/data-model.md` §1)
//! - [`record`]: encrypted item records and their encryption/decryption
//! - [`account`]: account creation, unlock and every key rotation (crypto design §7)
//! - [`totp`]: RFC 6238 one-time codes (crypto design §11.1)
//! - [`generator`]: password and passphrase generator (§11.2)
//! - [`ssh`]: OpenSSH key import and signing (§11.3)
//! - [`search`]: in-memory search of the unlocked vault
//! - [`wire`]: JSON shapes shared with the API and clients (base64url binary fields)
#![forbid(unsafe_code)]

pub mod account;
pub mod b64;
mod error;
pub mod generator;
pub mod item;
pub mod record;
mod rng;
pub mod search;
pub mod ssh;
pub mod totp;
pub mod wire;

pub use crypto_core;
pub use error::VaultError;

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, VaultError>;
