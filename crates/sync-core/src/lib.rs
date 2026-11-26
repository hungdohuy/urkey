//! urkey synchronization engine (`docs/architecture/sync.md`).
//!
//! The engine is *sans-IO*: it never does network or storage I/O. Callers persist
//! [`SyncState`] (it is serde-serializable), send the requests it prepares, and feed the
//! responses back. The same engine runs in the web worker (via WASM) and in the CLI.
//!
//! Invariants it maintains (sync.md §1, §11):
//! - the cursor only advances from pull responses, never from push results;
//! - a pulled record is stored only after it decrypts and verifies, and never replaces a
//!   higher revision (rollback) — failures are quarantined;
//! - a local edit is never dropped silently: it is pending, acknowledged, replaced by a later
//!   unsent edit on the same device, or kept as a conflict.
#![forbid(unsafe_code)]

mod engine;
mod state;

pub use engine::*;
pub use state::*;
pub use vault_core;
