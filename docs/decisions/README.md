# Architecture Decision Records

One file per decision: `NNNN-short-title.md`, using the template below.
Accepted ADRs are binding; change one only with a new ADR that supersedes it.

| ADR | Title | Status |
|-----|-------|--------|
| 0001 | Technology stack (React/TS, Rust core + WASM, Cloudflare Workers/D1/R2) | To write |
| 0002 | PWA code-delivery risk: accept and mitigate (D-1) | To write |
| 0003 | Account authentication via derived Ed25519 key (D-2) | To write |
| 0004 | XChaCha20-Poly1305 as AEAD (D-3) | To write |
| 0005 | VMK rotation in V1 (D-4) | To write |
| 0006 | Secret Key storage on devices (D-5) | To write |
| 0007 | macOS V1 scope: CLI + launchd agent (D-6) | To write |
| 0008 | No RSA signing in V1 (D-7) | To write |
| 0009 | Item ciphertext in D1, snapshots in R2 (D-8) | To write |
| 0010 | Worker routing approach (D-9) | To write |

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
