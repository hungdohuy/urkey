# Architecture Decision Records

One file per decision: `NNNN-short-title.md`, using the template below.
Accepted ADRs are binding; change one only with a new ADR that supersedes it.

| ADR | Title | Status |
|-----|-------|--------|
| 0001 | Technology stack (React/TS, Rust core + WASM, Cloudflare Workers/D1/R2) | Accepted — file to write |
| 0002 | PWA code-delivery risk: accept and mitigate (D-1) | Accepted — file to write |
| 0003 | Account authentication via derived Ed25519 key (D-2) | Accepted — file to write |
| 0004 | XChaCha20-Poly1305 as AEAD (D-3) | Accepted — file to write |
| 0005 | VMK rotation in V1 (D-4) | Accepted — file to write |
| 0006 | Secret Key storage on devices (D-5) | Accepted — file to write |
| 0007 | macOS V1 scope: CLI + launchd agent (D-6) | Accepted — file to write |
| 0008 | No RSA signing in V1 (D-7) | Accepted — file to write |
| 0009 | Item ciphertext in D1, snapshots in R2 (D-8) | Accepted — file to write |
| 0010 | Hand-written Worker router (D-9) | Accepted — file to write |
| 0011 | CLI local store: SQLite via rusqlite (D-13) | Accepted — file to write |
| 0012 | Web UI building blocks (D-16) | Proposed |
| 0013 | WASM core in a dedicated Web Worker (D-17) | Proposed |

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
