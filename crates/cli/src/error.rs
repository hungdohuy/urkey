//! CLI errors: fixed, human-readable messages. Never include secrets or item content.

use crate::vault_core;
use std::fmt;

/// A CLI failure with a message for the user and an exit code.
#[derive(Debug)]
pub struct CliError {
    pub message: String,
    pub code: u8,
}

impl CliError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<vault_core::VaultError> for CliError {
    fn from(e: vault_core::VaultError) -> Self {
        Self::new(match e {
            vault_core::VaultError::Crypto(vault_core::crypto_core::CryptoError::Decrypt) => {
                "Couldn't unlock. Check your master password and try again.".to_owned()
            }
            other => other.to_string(),
        })
    }
}

impl From<vault_core::crypto_core::CryptoError> for CliError {
    fn from(e: vault_core::crypto_core::CryptoError) -> Self {
        vault_core::VaultError::from(e).into()
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::new(format!("I/O error: {}", e.kind()))
    }
}

impl From<rusqlite::Error> for CliError {
    fn from(_: rusqlite::Error) -> Self {
        Self::new("local database error")
    }
}

impl From<serde_json::Error> for CliError {
    fn from(_: serde_json::Error) -> Self {
        Self::new("local data is damaged")
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
