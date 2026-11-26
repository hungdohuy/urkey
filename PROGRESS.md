# Progress

The single place to see where urkey stands and pick up where the last session stopped.
**Read this first; update it at the end of every working session** (see `CLAUDE.md`).

Legend: ✅ done · 🟡 partly done / in progress · ⬜ not started · ⏸ waiting on the owner

## Snapshot

| | |
|--|--|
| Last updated | 2026-11-26 |
| Current phase | **P1 — Crypto core**: implementation done, gate open (see below) |
| Branch | `claude/youthful-archimedes-v6dhz1` (no PR yet) |
| Last commit with green CI | `5bd3e84` — [CI run 4](https://github.com/hungdohuy/urkey/actions/runs/45844937330), all 5 jobs passed |
| V1 requirements | 3 of 48 done, 6 partly done (see [V1 requirements](#v1-requirements)) |

## Resume here (next steps, in order)

1. ⏸ Owner answers the [open decisions](#waiting-on-the-owner) for P1.
2. ⏸ Owner reviews the P1 diff (`crates/crypto-core`, `tests/fixtures/crypto-v1`) — P1 review gate.
3. ⬜ Check the first nightly fuzz run (`.github/workflows/fuzz.yml`) once it has run.
4. ⬜ iPhone unlock benchmark — needs the owner's iPhone. Plan: add a tiny benchmark page in P2
   and record the result in crypto spec §4.2.
5. ⬜ When the P1 gate passes: owner moves `CLAUDE.md` to **P2** (local vault + web UI). P3
   (server, auth, devices) may run in parallel with P2.

## Waiting on the owner

| # | What | Why it matters | Where |
|---|------|----------------|-------|
| O-1 | Approve the Recovery Key display grouping (`…-XXXXC`, check character at the end of the last group) | Spec said "groups of 4", which 53 characters can't be; display only | crypto spec §3.2, §15 |
| O-2 | Accept a redacting `Debug` on secret types (roadmap P1 says "no `Debug`"; `CLAUDE.md` allows redacting) | Decide which wording is binding | roadmap P1, `crates/crypto-core/src/secret.rs` |
| O-3 | Review the P1 code | P1 gate | roadmap P1 |
| O-4 | Measure unlock time on an iPhone PWA | Confirms Argon2id defaults (D-10) | crypto spec §4.2 |
| O-5 | Decide snapshot DEK wrapping (Q-5) | Needed before P7 backups | crypto spec §14 |
| O-6 | Install Xcode Command Line Tools on the Mac (`xcode-select --install`) | Needed before P6 | — |
| O-7 | Turn on Remote Control on the Mac (or run Claude Code locally there) | macOS testing in P6 | — |
| O-8 | Create a Cloudflare API token (Workers, D1, R2 edit) | Needed for deployment in P7 | — |
| O-9 | Arrange the independent security review | Required before real credentials (M2) | crypto spec §13 |

## Phases

| Phase | Status | Notes |
|-------|--------|-------|
| P0 Foundation | ✅ | Docs, ADRs 0001–0015, scaffolding, CI green |
| P1 Crypto core | 🟡 | Code, vectors (native, WASM, Python 102/102), fuzz targets, benchmarks done. Open: O-1…O-4, first nightly fuzz run |
| P2 Local vault + web UI | ⬜ | `vault-core`, `wasm-bindings` (Web Worker), all vault screens, TOTP, generator |
| P3 Server, auth, devices | ⬜ | Worker endpoints, D1 schema, sign-in, Emergency Kit, device list |
| P4 Sync | ⬜ | `sync-core`, outbox, conflicts, simulation tests, D-15 concurrency proof |
| P5 Recovery + rotation | ⬜ | Recovery flow, password / Secret Key / Recovery Key / vault key changes |
| P6 CLI + SSH agent (macOS) | ⬜ | `urk` commands, SQLite cache, Keychain, launchd agent; needs O-6, O-7 |
| P7 Hardening + release | ⬜ | CSP, reproducible builds, SW pinning, export/snapshots, deploy with `cf`; needs O-8 |
| M1 Personal testing | ⬜ | 2 weeks daily use with **test data only** |
| M2 Real credentials | ⬜ | After P7, closed review findings (O-9) and owner approval |

## V1 requirements

From `docs/requirements/v1.md`. "Phase" is where the work is planned.

### Account and recovery
| ID | Requirement | Phase | Status |
|----|-------------|-------|--------|
| R-ACC-1 | Create account locally (keys generated on device) | P3 | ⬜ (crypto building blocks ✅ in P1) |
| R-ACC-2 | Emergency Kit with confirmation | P3 | ⬜ |
| R-ACC-3 | Unlock with password; Secret Key from device storage | P2 | ⬜ |
| R-ACC-4 | Offline unlock | P2 | ⬜ |
| R-ACC-5 | Auto-lock + manual lock, keys zeroized | P2 | ⬜ |
| R-ACC-6 | Password change re-wraps VMK only | P5 | ⬜ |
| R-ACC-7 | Secret Key rotation | P5 | ⬜ |
| R-REC-1 | Recover with Recovery Key only | P5 | ⬜ |
| R-REC-2 | Recovery forces new password, Secret Key, Recovery Key | P5 | ⬜ |
| R-REC-3 | Recovery Key rotation, atomic | P5 | ⬜ |
| R-REC-4 | Clear guidance on each secret | P2/P3 | ⬜ (written in `docs/security/recovery.md`) |

### Authentication and devices
| ID | Requirement | Phase | Status |
|----|-------------|-------|--------|
| R-AUTH-1 | Login by signing a challenge with derived auth key | P3 | ⬜ (key derivation + message format ✅ in P1) |
| R-AUTH-2 | Recovery login with recovery auth key | P5 | ⬜ (derivation ✅ in P1) |
| R-AUTH-3 | Per-device keys, device-bound sessions | P3 | ⬜ |
| R-DEV-1 | Device register / list / revoke | P3 | ⬜ |
| R-DEV-2 | New-device notice on other devices | P3/P4 | ⬜ |
| R-DEV-3 | VMK rotation | P5 | ⬜ |

### Vault items
| ID | Requirement | Phase | Status |
|----|-------------|-------|--------|
| R-ITEM-1 | Login, Secure Note, SSH Key items | P2 | ⬜ |
| R-ITEM-2 | Encrypt before any storage or upload | P2 | ⬜ (container format ✅ in P1) |
| R-ITEM-3 | Local search | P2 | ⬜ |
| R-ITEM-4 | Mask / reveal / copy with feedback | P2 | ⬜ |
| R-ITEM-5 | TOTP (RFC 6238) | P2 | ⬜ |
| R-ITEM-6 | Password generator | P2 | ⬜ |
| R-ITEM-7 (S) | Native clipboard clearing | P6 | ⬜ |

### Sync
| ID | Requirement | Phase | Status |
|----|-------------|-------|--------|
| R-SYNC-1 | End-to-end encrypted sync | P4 | ⬜ |
| R-SYNC-2 | Offline edits queue and sync later | P4 | ⬜ |
| R-SYNC-3 | Optimistic concurrency, conflicts keep both | P4 | ⬜ |
| R-SYNC-4 | Authenticated tombstones, 90-day retention | P4 | ⬜ (authenticated tombstone format ✅ in P1) |
| R-SYNC-5 | Idempotent mutations | P4 | ⬜ |
| R-SYNC-6 | Stale devices / old schema handling | P4 | ⬜ |

### SSH and CLI (macOS)
| ID | Requirement | Phase | Status |
|----|-------------|-------|--------|
| R-SSH-1 | Import OpenSSH keys (Ed25519, ECDSA P-256) | P2/P6 | ⬜ |
| R-SSH-2 | SSH agent on a Unix socket | P6 | ⬜ |
| R-SSH-3 | Keys only while unlocked | P6 | ⬜ |
| R-SSH-4 | CLI commands (`urk unlock`, `lock`, `status`, `sync`, `item`, `ssh`, `agent`) | P6 | 🟡 binary exists (`urk --version` only) |
| R-SSH-5 (S) | Per-use signing confirmation | V1.1 | ⬜ |

### Security
| ID | Requirement | Phase | Status |
|----|-------------|-------|--------|
| R-SEC-1 | No secrets in logs, URLs, errors, … | all | 🟡 redacting secret types, lint rules, fixed error bodies; canary tests in P2/P3 |
| R-SEC-2 | Versioned formats with algorithm ids | all | 🟡 crypto containers ✅; item/API/storage formats later |
| R-SEC-3 | Reviewed crypto libraries only | P1 | ✅ RustCrypto only; OpenSSL banned in `deny.toml` |
| R-SEC-4 | Cross-platform test vectors | P1 | ✅ native ↔ WASM ↔ fixtures, plus independent Python check |
| R-SEC-5 | `cargo deny` + `pnpm audit` in CI | P0 | ✅ |
| R-SEC-10 | Strict CSP, no third-party scripts | P7 | 🟡 API sends strict headers; web CSP in P7 |
| R-SEC-11 | Reproducible web build + published hash | P7 | ⬜ |
| R-SEC-12 (S) | Service worker bundle pinning | P7 | ⬜ |
| R-SEC-13 | Separate app and API hosts | P7 | ⬜ |

### UX
| ID | Requirement | Phase | Status |
|----|-------------|-------|--------|
| R-UX-1 | Responsive desktop / tablet / phone | P2 | 🟡 empty three-pane shell only |
| R-UX-2 | Keyboard + accessible labels | P2 | ⬜ |
| R-UX-3 | Lock / sync / device state indicators | P2–P4 | ⬜ |
| R-UX-4 | Original design system | P2 | 🟡 tokens + contrast test; components in P2 |

## Other open items

- Docs: everything planned for the design phase exists. Keep `docs/` in step with code.
- Environment: the `urkey` cloud environment's updated setup script (installs `cf`, not
  Wrangler) has not yet run in a fresh session.
- Dependencies on the owner's devices: iPhone (O-4), Mac (O-6, O-7).

## Session log

Newest first. One short entry per session: what changed, where it stopped.

- **2026-11-26** — Brief reviewed and adjusted; all design docs and ADRs written; P0 scaffolding
  and CI; switched Worker tooling to `cf` (no Wrangler); CLI binary renamed `urk`; crypto design
  approved; P1 crypto core implemented with vectors (native, WASM, Python), fuzz targets and
  benchmarks; CI green. Stopped at: P1 gate (O-1…O-4). Added this file.
