# 0011. CLI local store: SQLite via rusqlite

- Status: Accepted
- Date: 2026-11-26
- Decision: D-13
- Requirements: R-ACC-4

## Context
The CLI and agent need a durable local cache of encrypted records, the outbox and sync state.

## Decision
Use SQLite through `rusqlite` with the `bundled` feature. The database holds only ciphertext and
public data; the Secret Key and device key live in the Keychain.

## Alternatives considered
- JSON files: no transactions, easy to corrupt on crash.
- `redb`/`sled`: pure Rust, less mature or less maintained.

## Consequences
- Bundled SQLite is C code; accepted because it is very mature and only handles ciphertext.
- Migrations via `PRAGMA user_version`.
