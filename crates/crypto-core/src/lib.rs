//! urkey cryptographic core.
//!
//! Implements `docs/security/cryptographic-design.md` (v1): secret encodings (§3.2), key
//! derivation (§4), padding (§5.4), encrypted containers (§5–§6) and signature messages (§7).
//!
//! Rules (CLAUDE.md): no I/O, no workspace dependencies, no `unsafe`, secrets are zeroized on
//! drop and never printed, every failure to open protected data is [`CryptoError::Decrypt`].
#![forbid(unsafe_code)]

#[cfg(all(feature = "test-vectors", not(debug_assertions)))]
compile_error!("the `test-vectors` feature must never be enabled in release builds (spec §9)");

/// Declares a function that is `pub` only with the `test-vectors` feature and crate-private
/// otherwise. Used for the explicit-nonce/seed variants behind the public random API.
macro_rules! vectors_pub {
    ($(#[$meta:meta])* fn $($rest:tt)*) => {
        #[cfg(feature = "test-vectors")]
        $(#[$meta])*
        pub fn $($rest)*

        #[cfg(not(feature = "test-vectors"))]
        $(#[$meta])*
        #[allow(dead_code)]
        pub(crate) fn $($rest)*
    };
}

pub mod container;
pub mod encoding;
mod error;
pub mod ids;
pub mod kdf;
mod lp;
#[doc(hidden)]
pub mod no_debug;
pub mod padding;
mod rng;
pub mod secret;
pub mod sign;

pub use error::CryptoError;

/// Result type used throughout the crate.
pub type Result<T> = core::result::Result<T, CryptoError>;
