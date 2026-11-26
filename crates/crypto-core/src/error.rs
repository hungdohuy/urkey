//! Errors (spec §10). Messages are fixed strings: they never contain key material, plaintext,
//! passwords or ciphertext.

/// Every error this crate returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// Any failure to parse, authenticate or decrypt protected data. Deliberately carries no
    /// detail: callers must not learn which input (password, Secret Key, tag, header) was wrong.
    #[error("could not decrypt")]
    Decrypt,
    /// Caller-supplied input is malformed (e.g. a mistyped Secret Key). The reason is a fixed
    /// string and never echoes the input.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// Argon2id parameters are outside the accepted floor/ceiling (spec §4.2).
    #[error("key derivation parameters are not accepted")]
    KdfParamsRejected,
    /// The operating system's random number generator failed; the operation was not performed.
    #[error("secure random number generator unavailable")]
    Rng,
}
