//! urkey synchronization state machine.
//!
//! Outbox, pull/push, conflict handling and integrity checks as specified in
//! `docs/architecture/sync.md`. Storage and HTTP are injected by the caller.
//!
//! Empty until roadmap P4.
#![forbid(unsafe_code)]
