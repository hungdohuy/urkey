# 0017. Encrypted export reuses the account's own ciphertext

- Status: Accepted for implementation (owner directive to complete all phases). **Pending owner
  review**, because it is a crypto-adjacent format decision.
- Date: 2026-11-26
- Roadmap: P7 "encrypted export"; acceptance: "restore from an encrypted export into a fresh
  account works". Related open question: crypto spec Q-5 (snapshot DEK wrapping).

## Context
P7 asks for an encrypted export that can be restored into a fresh account. The crypto design
reserves container kind 0x07 (Snapshot) for R2 snapshots. How a snapshot's DEK is wrapped is
still open (Q-5, owner item O-5). CLAUDE.md forbids new cryptographic constructions without
the spec, and asks us to stop rather than guess on uncertain security decisions.

## Decision
An export file (`format: "urkey-export"`, `version: 1`, JSON, base64url binary fields)
contains, unchanged:
- the account id, KDF salt, KDF parameters, VMK id and the unlock envelope (container 0x01);
- every live item record under that VMK: item id, revision, DEK wrap (0x03) and body (0x04).
  Tombstones are left out.

Opening an export runs the normal unlock (crypto §7.3) with the master password and Secret Key
that were current when it was made. Each record is then opened with the normal record check
(§7.2), whose AAD binds account, item, revision and VMK generation. Restoring re-encrypts each
decrypted item as a **new** item in the target vault through the normal write path. Nothing is
replaced; restoring into the same account adds copies.

No new key, KDF use, container kind or AAD context is introduced. Every byte in the file is
something the server already stores (threat model AD-2), so the file is no more sensitive than a
D1 copy.

Implementation: `crates/vault-core/src/export.rs`, CLI `urk export --out` / `urk restore`,
web Settings › Backup (WASM `export_vault` / `restore_export`).

## Rules
- The decoder checks `format` and `version` first and rejects unknown values with a non-secret
  error. Unknown fields are rejected.
- Any authentication failure is the single decryption error: wrong password, wrong Secret Key,
  a changed envelope or record, a duplicate item id, or a tombstone in the file.
- The CLI writes the file with mode 0600 and refuses to overwrite an existing file.

## Alternatives considered
- **Kind 0x07 snapshot with a new DEK wrapping:** this is what Q-5 must decide. It needs a new
  AAD context, test vectors and owner approval. Deferred, together with R2 snapshots.
- **Export protected by a separate export password:** this needs a new KDF use and a new envelope
  context, which is a spec change. It also adds a third secret to keep.
- **Plaintext export (CSV/JSON):** rejected as the default. It may be offered later as an
  explicit, warned action.

## Consequences
- An export opens with the credentials current **at export time**. After a password or
  Secret Key change, an older export still needs the old ones. The UI and CLI say this.
- An export cannot be opened with the Recovery Key, because the client does not hold the
  recovery envelope.
- Someone holding the file can drop whole records without detection (they could also delete the
  file). Changed, swapped or replayed records fail authentication.
- After a vault-key rotation, older exports still open, because they carry their own envelope
  and VMK generation.
- R2 snapshots stay open until Q-5 is decided (PROGRESS.md O-5).
