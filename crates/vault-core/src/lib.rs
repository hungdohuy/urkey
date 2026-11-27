//! urkey vault domain logic.
//!
//! - [`item`]: item plaintext model and validation (`docs/architecture/data-model.md` §1)
//! - [`record`]: encrypted item records and their encryption/decryption
//! - [`account`]: account creation, unlock and every key rotation (crypto design §7)
//! - [`export`]: encrypted export files (ADR 0017)
//! - [`totp`]: RFC 6238 one-time codes (crypto design §11.1)
//! - [`generator`]: password and passphrase generator (§11.2)
//! - [`ssh`]: OpenSSH key import and signing (§11.3)
//! - [`search`]: in-memory search of the unlocked vault
//! - [`wire`]: JSON shapes shared with the API and clients (base64url binary fields)
#![forbid(unsafe_code)]

pub mod account;
pub mod b64;
mod error;
pub mod export;
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

/// Compile-time check that no secret-holding type has `Debug` (owner decision O-2).
#[cfg(test)]
mod no_debug {
    use crate::account::{
        NewAccount, RecoveryKeyChange, RecoverySetup, Rotation, UnlockKeysChange, Unlocked,
    };
    use crate::generator::Generated;
    use crate::item::{Content, Item, LoginFields, SshKeyFields};
    use crate::record::{Opened, VaultKey};
    use crate::ssh::AgentKey;
    use crate::totp::{Code, Totp};

    crypto_core::assert_not_debug!(
        VaultKey,
        Opened,
        AgentKey,
        Totp,
        Code,
        Generated,
        Item,
        Content,
        LoginFields,
        SshKeyFields,
        Unlocked,
        NewAccount,
        UnlockKeysChange,
        RecoveryKeyChange,
        RecoverySetup,
        Rotation,
    );
}
