//! urkey SSH agent (R-SSH-2, R-SSH-3; ADR 0016).
//!
//! Implements the subset of the SSH agent protocol (draft-miller-ssh-agent) that urkey needs:
//! list identities, sign, add (optionally with a lifetime), remove, remove all. `urk unlock` adds
//! keys exactly like `ssh-add -t <lifetime>`; `urk lock` removes them. Keys exist only in this
//! process's memory and are wiped when removed, expired or on exit. Key parsing and signing are
//! done by `ssh-key`; only Ed25519 and ECDSA P-256 are accepted (ADR 0008).
#![forbid(unsafe_code)]

pub mod agent;
pub mod protocol;
pub mod server;

pub use agent::Agent;
