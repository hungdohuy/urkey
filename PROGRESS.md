# Progress

The single place to see where urkey stands and pick up where the last session stopped.
**Read this first; update it at the end of every working session** (see `CLAUDE.md`).

Legend: ✅ done · 🟡 partly done / in progress · ⬜ not started · ⏸ waiting on the owner

## Snapshot

| | |
|--|--|
| Last updated | 2026-11-26 |
| Current phase | **P2–P7 engineering complete.** Every phase gate still needs owner-only steps (below). |
| Branch | `claude/youthful-archimedes-v6dhz1` (no PR yet) |
| CI | 2 jobs: Linux (`scripts/dev.sh check`, everything incl. e2e) and macOS (CLI + agent). |
| V1 requirements | 45 of 48 done, 2 partly done (R-SSH-2 needs a real Mac, R-SEC-13 needs deployment), 1 open (R-SSH-5, V1.1) |
| Data | **Test data only** until M2. Nothing is deployed. |

## Resume here (next steps, in order)

1. **Owner:** review and decide the items in [Waiting on the owner](#waiting-on-the-owner),
   starting with the code review (O-3).
2. **Owner:** run the manual checklist `docs/operations/manual-test.md` with
   `./scripts/dev.sh dev` (section 5 on the Mac closes O-6; the phone-width check closes O-12).
   `setup` and `dev` were confirmed working on the owner's machine on 2026-11-27.
3. **Owner:** deployment (O-8) following `docs/operations/deploy.md`, then M1 (two weeks with
   test data on two devices plus the CLI).
4. **Engineering, optional before the review:**
   - a parallel-push stress test against deployed D1 (P4);
   - R2 snapshots, once Q-5 is decided (O-5).
5. On each session: run `scripts/dev.sh check` and keep this file current.

## Waiting on the owner

| # | What | Why it matters | Where |
|---|------|----------------|-------|
| O-3 | Review the code (P1 crypto core first, then vault/sync/API/clients) | Every phase gate | roadmap |
| O-4 | Measure unlock time on an iPhone PWA | Confirms Argon2id defaults (D-10) | crypto spec §4.2 |
| O-5 | Decide snapshot DEK wrapping (Q-5) | Blocks R2 snapshots only; export does not need it (ADR 0017) | crypto spec §14 |
| O-6 | Test the CLI on a real Mac: Keychain prompts, `urk agent install` (launchd), `ssh`/`git` through the agent | P6 gate; CI only builds and unit-tests on macOS | `crates/cli`, `crates/ssh-agent` |
| O-7 | Turn on Remote Control on the Mac (or run Claude Code there) if you want help with O-6 | macOS testing | — |
| O-8 | Deploy: domain, origins, Cloudflare token, D1, `PRELOGIN_SECRET` | P7 / M1 | `docs/operations/deploy.md` |
| O-9 | Arrange the independent security review | Required before real credentials (M2) | crypto spec §13, threat model §6/§9a |
| O-11 | Update the phase section in `CLAUDE.md` (it still says P2–P7) | You own that section | `CLAUDE.md` |
| O-12 | Check layouts on a real phone and tablet (Playwright covers desktop Chrome) | R-UX-1 | `docs/ux/screens.md` §8 |
| O-13 | Decide the remaining 2026-11-27 review finding: M-2 (before deploying to Cloudflare, check whether its request logs record the Authorization header; if so turn request logging off). M-1 was accepted on 2026-11-27 (threat model T-17); L-1 and L-2 are fixed | Review follow-up | `docs/security/reviews/2026-11-27-zero-knowledge-review.md` |
| O-15 | Decide whether to close two restore-related findings at the product level. **N-1:** a rollback is not always detected (other devices' writes can raise `vault_seq` back past what a device saw); proposed: a per-account epoch in the change feed that a restore cannot reproduce. **N-2:** the web app cannot re-register a device after a restore without wiping its local copy (the CLI can: `urk login`); proposed: a “sign this device in again, keeping local data” flow. Today both are documented, with a manual resync and export-first guidance | Review findings N-1, N-2 | zero-knowledge review §7, `docs/operations/selfhost.md`, `docs/architecture/sync.md` §7.1 |

## Phases

| Phase | Status | Notes |
|-------|--------|-------|
| P0 Foundation | ✅ | Docs, ADRs, scaffolding, CI |
| P1 Crypto core | 🟡 | Done; O-1 and O-2 decided; gate needs O-3 (review) and O-4 (iPhone timing) |
| P2 Local vault + web UI | 🟡 | Implemented and tested; gate needs O-3, O-12, the canary test |
| P3 Server, auth, devices | 🟡 | Implemented; prelogin timing to measure on a deployed Worker |
| P4 Sync | 🟡 | Implemented, 10,000-scenario simulation; D1 parallel-push stress test after deploy |
| P5 Recovery + rotation | 🟡 | Implemented and fault-injection tested; gate needs the owner review (O-3) |
| P6 CLI + SSH agent (macOS) | 🟡 | Implemented, real-sshd e2e on Linux, macOS CI build; real-Mac test is O-6 |
| P7 Hardening + release | 🟡 | CSP/TT, SW pinning, reproducible hash, export/restore, CI, runbook done; R2 snapshots (O-5), deploy (O-8), review (O-9) |
| M1 Personal testing | ⏸ | After O-8 |
| M2 Real credentials | ⏸ | After P7, closed review findings (O-9) and owner approval |

## V1 requirements

From `docs/requirements/v1.md`. Evidence is the main test that covers each requirement.

### Account and recovery
| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| R-ACC-1 | Create account locally | ✅ | `vault-core` account tests; Playwright "create an account"; `cli_e2e.sh` |
| R-ACC-2 | Emergency Kit with confirmation | ✅ | Onboarding kit step (last 4 characters), Playwright |
| R-ACC-3 | Unlock with password; Secret Key from device storage | ✅ | WebCrypto-wrapped ASK (kind 0x06); Keychain/file store in CLI |
| R-ACC-4 | Offline unlock | ✅ | Playwright production project: offline reload + unlock |
| R-ACC-5 | Auto-lock + manual lock, keys zeroized | ✅ | `Core::lock`, idle timer, Shift+L; Playwright lock test |
| R-ACC-6 | Password change re-wraps VMK only | ✅ | account tests (containers unchanged); Playwright |
| R-ACC-7 | Secret Key rotation | ✅ | account tests; Settings › Security |
| R-REC-1 | Recover with Recovery Key only | ✅ | Playwright recovery test |
| R-REC-2 | Recovery forces new password, Secret Key, Recovery Key | ✅ | `setup_after_recovery`; Playwright |
| R-REC-3 | Recovery Key rotation, atomic | ✅ | D1 guarded batch; lost responses resolved by re-reading the account; fault injection in `e2e/fault.spec.ts` |
| R-REC-4 | Clear guidance on each secret | ✅ | UX copy per `docs/security/recovery.md` |

### Authentication and devices
| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| R-AUTH-1 | Login by signing a challenge | ✅ | Worker tests; CLI + web sign-in |
| R-AUTH-2 | Recovery login with recovery auth key | ✅ | Worker tests; Playwright recovery |
| R-AUTH-3 | Per-device keys, device-bound sessions | ✅ | Non-extractable WebCrypto Ed25519; refresh signed by device key |
| R-DEV-1 | Device register / list / revoke | ✅ | `cli_e2e.sh` revoke → `device_revoked` |
| R-DEV-2 | New-device notice on other devices | ✅ | Security events + Activity tab |
| R-DEV-3 | VMK rotation | ✅ | sync rotation rebase; Playwright vault-key test |

### Vault items
| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| R-ITEM-1 | Login, Secure Note, SSH Key items | ✅ | `vault-core` item tests; editor |
| R-ITEM-2 | Encrypt before any storage or upload | ✅ | IndexedDB inspection test; export plaintext check |
| R-ITEM-3 | Local search | ✅ | `vault-core::search`; search box |
| R-ITEM-4 | Mask / reveal / copy with feedback | ✅ | Playwright (masked until reveal, DOM check) |
| R-ITEM-5 | TOTP (RFC 6238) | ✅ | RFC vectors; live code in UI |
| R-ITEM-6 | Password generator | ✅ | χ² on 10⁶ samples; EFF wordlist |
| R-ITEM-7 (S) | Native clipboard clearing | ✅ | `urk item copy` clears after 90 s if unchanged (`cli_e2e.sh`); real `pbcopy` on macOS is in the manual checklist |

### Sync
| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| R-SYNC-1 | End-to-end encrypted sync | ✅ | two-device Playwright + CLI e2e |
| R-SYNC-2 | Offline edits queue and sync later | ✅ | outbox; simulation |
| R-SYNC-3 | Optimistic concurrency, conflicts keep both | ✅ | simulation (10,000 scenarios); conflict UI |
| R-SYNC-4 | Authenticated tombstones, 90-day retention | ✅ | tombstone containers; scheduled retention job |
| R-SYNC-5 | Idempotent mutations | ✅ | idempotency log; Worker tests |
| R-SYNC-6 | Stale devices / old schema handling | ✅ | 410 resync, `min_client_version`, read-only newer schema |

### SSH and CLI (macOS)
| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| R-SSH-1 | Import OpenSSH keys (Ed25519, ECDSA P-256) | ✅ | `vault-core::ssh` tests; web + CLI import |
| R-SSH-2 | SSH agent on a Unix socket | 🟡 | OpenSSH tests on Linux; macOS launchd untested on a real Mac (O-6) |
| R-SSH-3 | Keys only while unlocked | ✅ | `cli_e2e.sh`: ssh fails after `urk lock` |
| R-SSH-4 | CLI commands | ✅ | `urk init/account/login/unlock/lock/status/sync/item/ssh/device/agent/export/restore/forget` |
| R-SSH-5 (S) | Per-use signing confirmation | ⬜ | V1.1 (native app) |

### Security
| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| R-SEC-1 | No secrets in logs, URLs, errors | ✅ | canary test (`e2e/canary.spec.ts`): console, titles, URLs, request bodies, DOM/attributes, web storage; storage inspection; fixed errors |
| R-SEC-2 | Versioned formats with algorithm ids | ✅ | containers, item `schema`, export `version`, API `/v1` |
| R-SEC-3 | Reviewed crypto libraries only | ✅ | RustCrypto; OpenSSL banned |
| R-SEC-4 | Cross-platform test vectors | ✅ | native ↔ WASM ↔ Python |
| R-SEC-5 | `cargo deny` + `pnpm audit` in CI | ✅ | CI |
| R-SEC-10 | Strict CSP, no third-party scripts | ✅ | `_headers`; Playwright production checks for violations |
| R-SEC-11 | Reproducible web build + published hash | ✅ | CI builds twice; About shows the hash (publishing is part of O-8) |
| R-SEC-12 (S) | Service worker bundle pinning | ✅ | `src/sw/sw.js`; update needs approval |
| R-SEC-13 | Separate app and API hosts | 🟡 | two Workers and origins configured; real hosts with O-8 |

### UX
| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| R-UX-1 | Responsive desktop / tablet / phone | ✅ | breakpoints at 1199/767 px; real devices O-12 |
| R-UX-2 | Keyboard + accessible labels | ✅ | shortcuts; axe in Playwright (no serious issues) |
| R-UX-3 | Lock / sync / device state indicators | ✅ | sync indicator, lock screen, revoked screen, update banner |
| R-UX-4 | Original design system | ✅ | tokens + components in `apps/web/src/ui` |

## Other open items

- No spec changes are pending owner approval. Decided on 2026-11-27: O-1 (Recovery Key grouping) and
  O-10 (ADR 0017, encrypted export) approved; O-2 decided as "no `Debug`" on secret types.
- The `urkey` cloud environment could also install `openssh-server` for `cli_e2e.sh`. In this
  session it was already present.

## Session log

Newest first. One short entry per session: what changed, where it stopped.

- **2026-11-27 (g)** — Owner accepted M-1 and decided O-14 as proposed. Implemented "accept the server's data and
  resync" (sync-core, WASM, web button + permanent Settings › Backup button, `urk sync --resync`): the device's own
  newer content is put back, items only it had are recreated under their old ids, and conflicting content is kept as a copy. Found N-1:
  a rollback is not always detected (now O-15). Tests: 3 new sync simulations, `selfhost_restore.sh`.

- **2026-11-27 (f)** — Self-hosting with Docker Compose (ADR 0018).
  - Setup: `compose.yaml`; Caddy plus the Worker in workerd via Miniflare, D1 in a volume; dev tooling off, API reachable only via Caddy.
  - Tested here: image build, all 14 browser tests against the stack, restart persistence, backup/restore.
  - Fixed the declared Node range: `cf` needs ^22.23/^24.22/^26.12.
  - Found a sync gap (O-14): "resume syncing" can't clear a real rollback.

- **2026-11-27 (e)** — Fixed review L-1 (WASM secret arguments wiped; the new Secret Key returned as wipeable
  bytes; the extra WebCrypto copy wiped; new e2e test for Secret Key rotation) and L-2 (CLI session token in
  the secret store / Keychain). M-1 and M-2 left for the owner.

- **2026-11-27 (d)** — Zero-knowledge self-review: the core property holds (no critical or high findings);
  2 medium and 2 low findings written up for the owner (O-13). It does not replace the independent review (O-9).

- **2026-11-27 (c)** — Owner decisions: O-1 and O-10 approved; O-2: secret types get no `Debug` at all.
  Removed every `Debug` (manual and derived) from secret-holding types in crypto-core, vault-core,
  sync-core and ssh-agent, fixed the tests that relied on it, and added the `assert_not_debug!` compile-time guard.
  Also removed the product-brief 1Password wording at the owner's request (one-time exception).

- **2026-11-27 (b)** — R-SEC-1 canary test (Playwright); R-ITEM-7 `urk item copy` with clearing after 90 s;
  R-REC-3: found and fixed a lost-response gap in all key changes (the client could discard a
  committed Recovery Key or Secret Key). Unclear outcomes are now confirmed by re-reading the account, which
  now returns the public `rauth_pk`; there is a fault-injection test.

- **2026-11-27** — The owner ran `scripts/dev.sh setup` and `dev` successfully (web app + CLI);
  features not yet checked. Fixed the declared Node range (jsdom needs 22.22.2+/24.15+; `.nvmrc`,
  plus a version check in dev.sh). Added `docs/operations/manual-test.md`. CI green on both jobs.

- **2026-11-26 (c)** — Added `scripts/dev.sh` (local setup/dev/preview/test/e2e/check/cli).
  Fixed the Playwright hang after the last test: `cf dev` runs its server in a new session,
  so Playwright's SIGKILL left it orphaned; the web servers are now stopped with SIGTERM. Fixed
  agent socket paths on macOS. CI reduced to 2 jobs; the Linux job runs `scripts/dev.sh check`.
  Before this change, the CI run for `f7240d3` passed every job except the hanging browser step.

- **2026-11-26 (b)** — Owner directive "finish all remaining phases".
  - Built: `vault-core`, `sync-core`, the Worker API, the SSH agent, the `urk` CLI,
    `wasm-bindings` and the full web app.
  - P7: strict CSP + Trusted Types, pinned service worker, reproducible release hash, and
    encrypted export/restore (ADR 0017).
  - CI gained e2e and macOS jobs plus deploy dry runs. Added README and a deployment runbook,
    and refreshed the roadmap and threat model.
  - Stopped at: owner items O-1…O-12; nothing deployed.
- **2026-11-26 (a)** — Brief reviewed and adjusted; all design docs and ADRs written; P0
  scaffolding and CI; switched Worker tooling to `cf`; CLI renamed `urk`; crypto design
  approved; P1 crypto core with vectors (native, WASM, Python), fuzz targets and benchmarks.
