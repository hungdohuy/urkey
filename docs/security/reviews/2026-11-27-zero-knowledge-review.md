# Zero-knowledge review — 2026-11-27

Scope: the implementation on branch `claude/youthful-archimedes-v6dhz1` at `5b5e5e7` (CI green),
checked against the zero-knowledge principle. **The server must never be able to read vault
content or keys, or derive them.** The review reads the code paths themselves, not only the docs.

This is a self-review by the implementing assistant. It is **not** the independent review
required before M2 (O-9). It is written so that review can start from it.

## Verdict

The core property holds. The server receives and stores only:
- ciphertext: containers kind 0x01–0x05, padded to buckets;
- public keys (`auth_pk`, `rauth_pk`, device keys);
- Ed25519 signatures;
- the KDF salt and parameters;
- the metadata listed in §3.

Nothing found lets the server, or someone holding a copy of D1, read items or derive the master
password, Secret Key, Recovery Key, VMK or DEKs. There are no critical or high findings. Two
medium and two low findings concern things around the vault, not the vault itself.

## 1. Verified properties (with evidence)

| # | Property | Evidence |
|---|----------|----------|
| V-1 | No password, Secret Key, Recovery Key, TOTP secret or item text in any request body, URL, title, console output, DOM attribute or web storage | `apps/web/e2e/canary.spec.ts` (plain, base64url and URL-encoded forms); IndexedDB inspection in `vault.spec.ts` |
| V-2 | The server cannot weaken the KDF | `KdfParams::decode` → `new` enforces the floor and ceiling (`crypto-core/src/kdf.rs`); parameters and salt are in the unlock-envelope AAD (crypto §5.2), so supplying weaker values fails decryption |
| V-3 | Login proves knowledge without revealing anything guessable offline | The challenge is signed by `auth_sk` derived from password **and** the 128-bit ASK; the server holds only `auth_pk`. A D1 copy does not allow password guessing without the ASK (T-1, T-2) |
| V-4 | The server cannot forge, swap, replay or forge-delete items | The AAD binds `account_id ‖ item_id ‖ revision` and the VMK generation; tombstones are authenticated with the DEK; failures are quarantined (`sync-core`, 10,000-scenario simulation) |
| V-5 | The server cannot recover or take over the account | Recovery needs a signature by `rauth_sk` (derived from the 256-bit RK); the recovery envelope opens only with the RK |
| V-6 | No account enumeration via prelogin or challenge | Unknown emails get deterministic HMAC fakes (`handlers/auth.ts`); challenges are issued for any account id |
| V-7 | Errors never echo request data | The router's catch-all returns a bare `500 internal_error`; there is no `console` in the Worker; lint forbids `console` |
| V-8 | Secrets are not printable in Rust | No `Debug`/`Display` on secret types, enforced by `assert_not_debug!` at compile time (O-2) |
| V-9 | A lost response never destroys the only working key | `keyChange` in `worker.ts`; `e2e/fault.spec.ts` (R-REC-3) |
| V-10 | Export files add no exposure | They hold only what D1 holds (ADR 0017) and need the password **and** Secret Key |
| V-11 | The web device key cannot be exported | Non-extractable WebCrypto Ed25519 key; the ASK is wrapped by a non-extractable AES-GCM key (kind 0x06) |
| V-12 | Rate limits use an unspoofable client IP | `cf-connecting-ip`, set by Cloudflare's edge; rows holding IPs are deleted after 1 day |

## 2. Findings

### M-1 Account creation reveals whether an email is registered — **accepted 2026-11-27**
`POST /v1/accounts` answers `409 email_taken` (`handlers/auth.ts:71`). Prelogin and challenge
were built so that they reveal nothing (T-17), but this endpoint does. It is rate-limited to
10 attempts per hour per IP, which slows bulk enumeration but does not stop it.
**Impact:** an attacker can learn that someone uses urkey. Vault data is not exposed.
**Options:** (a) accept it and record it in threat-model T-17 (common for products without email
verification); (b) add email verification, so that "create" always answers "check your inbox".
**Owner decision: option (a), accepted 2026-11-27.** Recorded in threat model T-17 and §10 residual risks.

### M-2 Cloudflare observability may log session tokens
`observability: { enabled: true }` is set in `cloud/workers/api/cloudflare.config.ts`. Whether
Workers Logs' invocation logs record request headers, including `Authorization: Bearer`, could
not be checked from this environment: the docs host is unreachable here. If they do, session
tokens would sit in the Cloudflare dashboard logs.
**Impact:** a token gives read access to ciphertext and metadata, and lets someone push records
until it expires (1 h idle, 24 h maximum). It does **not** give plaintext or keys, and key
changes need a step-up signature.
**Fix before deployment (O-8):** check the Workers Logs field list. If headers are recorded,
turn invocation logs off (keep only explicit logs, of which there are none), or turn
observability off.

### L-1 The raw Secret Key crosses the WASM boundary into JavaScript — **fixed 2026-11-27**
Overview §5 says JavaScript gets "opaque handles, never raw keys". Because the local wrap uses
WebCrypto (ADR 0006), the ASK passes through the core worker's JS:
- `Core.parse_secret_key` returns its bytes;
- `Core.unlock(password, secret_key)` takes them;
- `commit_change` returns the new ASK as a **base64 string** after a Secret Key rotation.

`worker.ts` wipes its buffers with `fill(0)`, but:
- `wrapSecretKey` passes a copy (`new Uint8Array(ask)`) to WebCrypto that is never wiped;
- the base64 string cannot be wiped at all;
- `wasm-bindgen` copies `&str`/`&[u8]` arguments (passwords, the ASK) into WASM memory and
  frees them without zeroing. Nine functions take `password: &str`.

**Impact:** extra short-lived copies of secrets in the worker's memory. Only an attacker who
can already read the process's memory benefits, and that attacker could also capture the
password at unlock (T-13, accepted). This is a gap between the spec and the code, not a break.
**Fix (small):**
- record the WebCrypto exception to §5 in the overview;
- wipe the extra copy;
- return the ASK from `commit_change` as bytes, not a string;
- take owned `String`/`Vec<u8>` arguments in `wasm-bindings` and wrap them in `Zeroizing`, so
  the WASM-side copies are wiped.

### L-2 The CLI stores its session token in plaintext — **fixed 2026-11-27**
`urk` keeps the session token in `vault.db` (SQLite, mode 0600; `profile.rs` `save_session`),
while the Secret Key and device key use the Keychain on macOS. Another process running as the
same user could read the token. That's the same impact as M-2, limited to that device.
**Fix:** on macOS, store the token in the Keychain next to the other secrets.

## 3. Metadata the server sees (by design; documented in the overview, "Metadata the server can infer", and threat model §7)

- The email address (needed for sign-in).
- Device names, platform and client version, **in plaintext**. Threat model §7 already lists
  encrypting device names under the VMK as a possible later reduction.
- Number of items, their padded sizes (64 KiB buckets), revisions, and times of change.
- IP addresses: Cloudflare sees them, and rate-limit rows keep them for at most 1 day.
- Security events: type, device and time.

## 4. Accepted risks that still apply (unchanged; owner accepted in the threat model)

- **T-3 code delivery:** a modified web bundle could capture the password and Secret Key. The
  mitigations are separate hosts, CSP and Trusted Types, a reproducible release hash, and
  service-worker pinning with an update approval. All are implemented, but they only help once
  the user has a trusted copy installed.
- **T-9:** the server can hide recent changes from a device that never saw them.
- **T-14:** data a revoked device already decrypted stays exposed.

## 5. Not covered by this review

- A line-by-line audit of the crypto composition against crypto §13. That's the independent
  review, O-9.
- Side channels, WebAssembly memory forensics, browser extensions, and the macOS/iOS native apps
  (not built yet).

## 6. Follow-up (2026-11-27)

- **L-1 fixed.**
  - Every password, Secret Key, Recovery Key, SSH key and passphrase argument of
    `wasm-bindings` is now an owned `String`/`Vec<u8>`, wrapped in `Zeroizing`.
  - `commit_change` returns the new Secret Key as bytes instead of base64 text.
  - `wrapSecretKey` wipes its WebCrypto copy as well.
  - Overview §5 records the WebCrypto exception.
  - A new browser test rotates the Secret Key and unlocks again.
- **L-2 fixed.**
  - The CLI keeps only the session expiry in `vault.db`. The token is in the secret store
    (Keychain on macOS).
  - Older profiles are migrated on first use.
  - `cli_e2e.sh` checks that `vault.db` holds no token.
- **M-1, M-2:** open, waiting on the owner (PROGRESS O-13).

## 7. Follow-up (2026-11-27, later): O-14 and a finding from testing it

- **M-1** is accepted by the owner (see above).
- **O-14 implemented.** "Accept the server's data and resync" (web, `urk sync --resync`)
  re-offers what the device had instead of discarding it: sync.md §7.1; tests in
  `crates/sync-core/tests/simulation.rs` and `tests/integration/selfhost_restore.sh`.
- **N-1 (low, found while testing): a rollback is not always detected.** The check only fires
  when the server's `vault_seq` is *lower* than the device's highest seen. After a restore,
  writes from other devices can raise it back to or past that value. A device then keeps its
  cursor and **never receives the changes whose sequence numbers it had already passed**,
  without any warning. This is the "a client that has never seen the newer state cannot detect
  withholding" limit of T-9, in a restore setting. It cannot lose data (the server and the
  other devices hold the changes) but a device shows stale content. Mitigation today: a
  manual resync is always available (Settings › Backup, `urk sync --resync`), and the
  self-hosting guide tells operators to run it on every device after a restore. A
  protocol-level fix, such as a per-account epoch in the change feed that a restore cannot
  reproduce, needs an API and sync-spec change; left for the owner (PROGRESS O-15).
- **N-2 (low, found while testing): the web app cannot re-register a device after a restore. — fixed 2026-11-27.**
  A device enrolled after the backup is unknown to the restored server, so refresh fails with
  `unauthorized`. The CLI recovers with `urk login` (local data is kept). The web app's only
  path is to sign out (which wipes local data) and sign in anew, so a user must export first or
  newer items that only that device had can be lost. Mitigated by the self-hosting guide; a
  "sign this device in again, keeping local data" flow would remove the risk (PROGRESS O-15).
  **Fix:** when a device's refresh is answered `unauthorized`, the web app shows "The server
  doesn't recognise this device" with **Sign this device in again**. That signs a login with the
  device's own key and the unlocked session's account key (`Core::prepare_relogin`; the account
  id from the server must match the local one), keeps all local data, and then accepts the
  server's data and resyncs (sync.md §7.1). Tests: `e2e/reregister.spec.ts` (the server
  forgets the device, items and counter; a fresh device then sees the note once) and a component
  test.
