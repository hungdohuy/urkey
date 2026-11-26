# CLAUDE.md — urkey

urkey is a personal, local-first, end-to-end encrypted password manager: a React + TS PWA,
a Rust core (compiled to WASM for the web), a Rust CLI + SSH agent for macOS, and a
Cloudflare Workers API that stores ciphertext only.

## Current phase: P1 — crypto core

The owner approved `docs/security/cryptographic-design.md` for implementation on 2026-11-26.
Work follows `docs/roadmap.md`: **only the current phase** (P1: `crates/crypto-core`, its test
vectors, fuzzing and benchmarks). Implement the spec exactly; any deviation or ambiguity is a
spec change that needs the owner's approval first (record it in the spec's change log).
Real credentials must not be stored until milestone M2 (independent review, roadmap).
The owner updates this section when the phase changes.

## Read before working

| Document | Purpose |
|----------|---------|
| `PROGRESS.md` | **Read first.** Current state, next steps, items waiting on the owner, V1 requirement status, session log. |
| `docs/requirements/product-brief.md` | Original brief (do not edit). |
| `docs/requirements/v1.md` | Numbered requirements (R-*), adjustments to the brief, acceptance criteria. Wins over the brief. |
| `docs/architecture/overview.md` | Components, key hierarchy, flows, decisions (D-*). |
| `docs/architecture/data-model.md` | Item plaintext schema, records, D1 tables, local stores. |
| `docs/architecture/sync.md` | Sync protocol, conflicts, idempotency, special situations. |
| `docs/security/` | Threat model, crypto design, recovery, devices. |
| `docs/decisions/` | ADRs. Accepted ADRs are binding. |
| `docs/ux/` | Design principles, design system, screens and components. |
| `docs/roadmap.md` | Phases P0–P7 with acceptance gates; work happens in the current phase only. |

Reference requirement and decision ids (R-SYNC-3, D-2, ...) in code comments, tests and commits
where it helps traceability.

## Workflow for every task

1. Read the relevant docs and existing code before editing.
2. State a short plan: affected files, interfaces, risks.
3. Make one logical change at a time; do not touch unrelated code.
4. Add or update tests with the change.
5. Run format, lint and tests (commands below) and report actual results.
6. Review your own diff for security issues and unnecessary changes.
7. Update docs when behavior or architecture changes; write an ADR for significant decisions.
8. Report what changed, what was tested, and what is still incomplete.
9. Before ending a session, update `PROGRESS.md`: snapshot, "Resume here", owner items,
   requirement statuses that changed, and one session-log line. Commit it with the work.

If a requirement is ambiguous, state the ambiguity and propose a default.
If a security decision is uncertain, stop and explain the risk instead of guessing.
Never silently change an accepted ADR — propose a superseding one.

## Security rules (non-negotiable)

- Never log, print, panic with, or put in URLs/errors/notifications: master passwords, Secret
  Keys, Recovery Keys, VMKs, DEKs, KEKs, TOTP secrets, SSH private keys, or decrypted item content.
  Secret-holding Rust types must not derive `Debug`/`Display` (implement a redacting `Debug`
  if needed) and must use `zeroize`/`ZeroizeOnDrop`.
- No custom cryptographic primitives or constructions. Use RustCrypto crates (`argon2`, `hkdf`,
  `chacha20poly1305`, `ed25519-dalek`, `zeroize`) and only as specified in the crypto design.
- All randomness from the OS CSPRNG (`getrandom` / `crypto.getRandomValues`). Never `Math.random`.
- Every persisted or encrypted format has a version and algorithm id. Decoders reject unknown
  versions with a non-secret error.
- Decryption errors are uniform: do not reveal which input (password vs Secret Key, tag vs
  format) was wrong.
- The Worker never receives plaintext vault data or keys and does no vault cryptography;
  it only verifies Ed25519 signatures.
- The WASM API exposes opaque handles, not raw keys (overview §5).
- No placeholder or "TODO: real crypto later" implementations in security-critical paths.
- Never commit credentials, `.dev.vars`, `.env`, real vault data or real keys. Test keys and
  vectors in `tests/fixtures/` are generated, clearly labelled test-only, and never reused.
- No analytics, telemetry or third-party scripts in the web app.
- A green build is not proof of cryptographic correctness; crypto changes need test vectors and
  owner review.

## Repository layout

```text
apps/web/              React + TS PWA (Vite)
apps/macos/            reserved for V1.1 native app
crates/crypto-core/    KDF, AEAD, envelopes — no I/O, no workspace deps
crates/vault-core/     items, TOTP, generator, SSH key parsing
crates/sync-core/      sync state machine (storage/HTTP injected)
crates/wasm-bindings/  narrow WASM API for apps/web
crates/cli/            `urk` binary (package `urkey-cli`)
crates/ssh-agent/      agent protocol server
cloud/workers/api/     Cloudflare Worker (cloudflare.config.ts) + D1 migrations
docs/                  requirements, architecture, security, decisions, ux
tests/fixtures/        generated test vectors
tests/integration/     cross-component tests
```

Dependency direction: `crypto-core` ← `vault-core` ← `sync-core` ← {`wasm-bindings`, `cli`, `ssh-agent`}.

## Toolchain

- Rust stable (pinned in `rust-toolchain.toml`) with `wasm32-unknown-unknown`, rustfmt, clippy.
- `wasm-bindgen` crate pinned to `=0.2.130` to match the installed `wasm-bindgen-cli 0.2.130`;
  bump both together.
- `wasm-pack 0.15.1`. `wasm-opt` comes from the system `binaryen` package (GitHub release
  downloads are blocked in the cloud environment).
- Node 22, pnpm (workspace).
- Cloudflare tooling is the **`cf` CLI** (`cf@1.0.0-rc.6`, a project dev dependency of
  `cloud/workers/api`) with the Vite bundler (`@cloudflare/vite-plugin` 2.0). **Do not use or
  install Wrangler** and do not add a Wrangler config file (ADR 0014). Worker config lives in
  `cloud/workers/api/cloudflare.config.ts`. Telemetry off: `CF_SEND_TELEMETRY=false`.
- Before running an unfamiliar `cf` command: `cf cli search "<task>"`, then `--help`, and
  `--dry-run` where available.
- `cargo-deny` for advisories and licenses.

## Commands

All of these run and pass on the P0 skeleton (CI runs the same set in
`.github/workflows/ci.yml`). Keep this list in sync with reality.

```bash
# Rust
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo test -p crypto-core --features test-vectors          # crypto vectors (native)
URKEY_WRITE_VECTORS=1 cargo test -p crypto-core --features test-vectors --test vectors  # regenerate: spec change!
wasm-pack test --node crates/crypto-core --features test-vectors --test wasm -- --nocapture
python3 tests/interop/python/verify_crypto_v1.py           # needs tests/interop/python/requirements.txt
cargo test -p crypto-core --release --test bench_argon2 -- --ignored --nocapture
(cd crates/crypto-core && cargo +nightly fuzz run open_container -- -max_total_time=60)

# WASM (output is git-ignored)
pnpm wasm                    # = wasm-pack build crates/wasm-bindings --target web --release --out-dir ../../apps/web/src/wasm

# Web + Worker (from repo root)
pnpm install
pnpm -r lint
pnpm -r typecheck
pnpm -r test
pnpm --filter web build
pnpm audit --prod
pnpm --filter api dev            # cf dev on :8787, local D1; GET /v1/health
pnpm --filter api build          # cf build
pnpm --filter api migrate:local  # cf d1 migrations apply <local id> --local
cargo run -p urkey-cli -- --version   # the `urk` binary
```

Never run `cf deploy` (other than `cf deploy --dry-run`), `cf auth login`, or remote D1/R2
commands (anything without `--local`) unless the owner asks for it in the
current task.

## Conventions

- Rust: edition 2024, `#![forbid(unsafe_code)]` in `crypto-core`, `vault-core`, `sync-core`
  (any exception needs an ADR). Errors via `thiserror`; no `unwrap()` outside tests.
- TypeScript: `strict: true`, no `any` in exported APIs, validate all API input at the Worker
  boundary.
- API and storage schemas are defined once and checked by shared JSON fixtures on both the
  Rust and TS side.
- ADRs: `docs/decisions/NNNN-short-title.md` with Status / Context / Decision / Consequences.
- Lint rules enforce some security rules: no `console`, no `Math.random`, no
  `dangerouslySetInnerHTML`, Rust `unwrap/expect/panic/print` denied outside tests.
- Exact versions everywhere (`save-exact`, pinned toolchain, `wasm-bindgen = "=0.2.130"`).
- Commits: imperative subject, body explains why; reference R-/D- ids where relevant.
- UI: original design system (no 1Password assets, names or copy); sensitive values masked by
  default; every action has visible feedback; keyboard accessible.
