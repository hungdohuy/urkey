# Architecture Decision Records

One file per decision: `NNNN-short-title.md`, using the template below.
Accepted ADRs are binding; change one only with a new ADR that supersedes it.

| ADR | Title | Decision | Status |
|-----|-------|----------|--------|
| [0001](0001-technology-stack.md) | Technology stack | brief §4 | Accepted |
| [0002](0002-pwa-code-delivery-risk.md) | Accept and mitigate the PWA code-delivery risk | D-1 | Accepted |
| [0003](0003-derived-ed25519-authentication.md) | Account authentication with a derived Ed25519 key | D-2 | Accepted |
| [0004](0004-xchacha20-poly1305.md) | XChaCha20-Poly1305 for all symmetric encryption | D-3 | Accepted |
| [0005](0005-vmk-rotation-in-v1.md) | Vault key (VMK) rotation in V1 | D-4 | Accepted |
| [0006](0006-secret-key-device-storage.md) | Secret Key storage on devices | D-5 | Accepted |
| [0007](0007-macos-v1-scope.md) | macOS V1 scope: Rust CLI and launchd SSH agent | D-6 | Accepted (amended by 0015) |
| [0008](0008-no-rsa-signing-v1.md) | No RSA signing in V1 | D-7 | Accepted |
| [0009](0009-item-ciphertext-in-d1.md) | Item ciphertext in D1, snapshots in R2 | D-8 | Accepted |
| [0010](0010-hand-written-worker-router.md) | Hand-written Worker router | D-9 | Accepted |
| [0011](0011-cli-sqlite-store.md) | CLI local store: SQLite via rusqlite | D-13 | Accepted |
| [0012](0012-web-ui-building-blocks.md) | Web UI building blocks | D-16 | Accepted |
| [0013](0013-wasm-in-web-worker.md) | Run the WASM core in a dedicated Web Worker | D-17 | Accepted |
| [0014](0014-cf-cli-instead-of-wrangler.md) | Use the `cf` CLI instead of Wrangler | D-19 | Accepted |
| [0015](0015-cli-binary-name.md) | CLI binary is named `urk` | D-20 | Accepted |
| [0016](0016-ssh-key-library-and-agent-protocol.md) | SSH key library and agent protocol implementation | Q-4 | Accepted |
| [0017](0017-encrypted-export-format.md) | Encrypted export reuses the account's own ciphertext | P7 export | Accepted |

D-10, D-11, D-12, D-14, D-15 and D-18 are recorded in the documents named in
`docs/architecture/overview.md` §11 rather than as separate ADRs.

## Template

```markdown
# NNNN. Title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD
- Requirements: R-...

## Context
## Decision
## Alternatives considered
## Consequences (security, UX, maintenance)
```
