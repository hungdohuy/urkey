# 0001. Technology stack

- Status: Accepted
- Date: 2026-11-26
- Decision: brief §4
- Requirements: R-SEC-3

## Context
The brief prescribes the stack. This ADR records it and the reasons, so later changes are explicit.

## Decision
- Web app: React + TypeScript (strict), built with Vite, delivered as a PWA.
- Security-sensitive and shared logic: Rust crates (`crypto-core`, `vault-core`, `sync-core`), compiled
  to WebAssembly for the web (`wasm-bindgen`, `wasm-pack`) and natively for the CLI and SSH agent.
- Backend: Cloudflare Workers (TypeScript), D1 for metadata and item ciphertext, R2 for encrypted
  snapshots.
- Package managers: Cargo and pnpm workspaces in one monorepo.

## Alternatives considered
- TypeScript-only core: one language, but weaker memory control and no shared native code for the
  SSH agent.
- Native apps per platform: best integration, far more code for one developer.
- Rust Worker (`workers-rs`): shares types with the core, but less mature; the server does no vault
  cryptography, so the benefit is small.

## Consequences
- One implementation of the cryptography for every client; interop tested with shared vectors.
- WASM adds a build step and a JS/WASM boundary (see 0013).
- Workers/D1/R2 tie deployment to Cloudflare; the protocol itself is not Cloudflare-specific.
