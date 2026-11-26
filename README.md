# urkey

A personal, local-first, end-to-end encrypted password manager:
- a React + TypeScript PWA;
- a Rust core, compiled to WASM for the web;
- a Rust CLI (`urk`) with an SSH agent for macOS;
- a Cloudflare Workers API that stores only ciphertext.

> **Status:** V1 features are implemented, but the security review has not happened yet.
> Do not store real credentials until milestone M2 (see `docs/roadmap.md`). Current state and
> open owner items: [`PROGRESS.md`](PROGRESS.md).

## What it does

- Logins, secure notes and SSH keys, encrypted on the device before they are stored or synced.
- Master password + Secret Key unlock (Argon2id + HKDF), offline unlock, and auto-lock.
- A Recovery Key, plus changes to the password, Secret Key, Recovery Key and vault key.
- Sync across devices, with conflicts that keep both versions and authenticated deletes.
- TOTP codes and a password and passphrase generator.
- An SSH agent for `ssh` and `git` (`urk unlock`, `urk lock`).
- An encrypted export and restore.

## Layout

| Path | What |
|------|------|
| `crates/crypto-core` | KDF, AEAD containers, signatures ([crypto design](docs/security/cryptographic-design.md)) |
| `crates/vault-core` | Items, records, account operations, TOTP, generator, SSH keys, export |
| `crates/sync-core` | Sans-IO sync engine ([sync protocol](docs/architecture/sync.md)) |
| `crates/wasm-bindings` | The narrow WASM API used by the web app |
| `crates/cli`, `crates/ssh-agent` | `urk` and the agent |
| `apps/web` | The PWA ([UX spec](docs/ux/)) |
| `cloud/workers/api` | The API Worker + D1 ([API](docs/architecture/api.md)) |
| `docs/` | Requirements, architecture, security, decisions (ADRs), operations |

## Development

Toolchain and all commands: [`CLAUDE.md`](CLAUDE.md#commands). Short version:

```bash
pnpm install && pnpm wasm
pnpm --filter api dev          # API on :8787 (cf dev, local D1)
pnpm --filter web dev          # app on :5173
cargo test --workspace && pnpm -r test
```

Deployment: [`docs/operations/deploy.md`](docs/operations/deploy.md). Only the owner deploys, with
their own Cloudflare credentials.
