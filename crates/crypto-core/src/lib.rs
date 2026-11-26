//! urkey cryptographic core.
//!
//! Implements `docs/security/cryptographic-design.md`: secret encodings, key derivation,
//! encrypted containers, signature messages and zeroizing secret types.
//!
//! **Empty until the crypto design is approved for implementation (roadmap P1).**
//! This crate must stay free of I/O and must not depend on other workspace crates.
#![forbid(unsafe_code)]
