# Cryptographic Design (v1)

Status: **Draft — NOT approved for implementation.** The owner accepted the design decisions
(D-1 to D-12) on 2026-11-26; the specification itself still needs the review in §13 before
production cryptography is implemented.

Related: [`threat-model.md`](threat-model.md), [`../architecture/overview.md`](../architecture/overview.md) §4–§7.

This document specifies every key, derivation, encryption and format used by urkey v1.
It composes standard primitives (Argon2id, HKDF-SHA-256, XChaCha20-Poly1305, Ed25519) in
conventional ways; it does not define new primitives. Combining a password with a
high-entropy device secret is a publicly known approach; urkey's construction is its own and
is **not** claimed to be equivalent to any other product's design.

## 1. Notation and conventions

| Notation | Meaning |
|----------|---------|
| `a ‖ b` | Byte concatenation |
| `LP(x)` | `u32be(len(x)) ‖ x` — length-prefixed bytes |
| `u32be`, `u64be` | Unsigned big-endian integers |
| `"..."` | ASCII string, no terminator |
| `HKDF-Extract`, `HKDF-Expand` | RFC 5869 with SHA-256 |
| `AEAD.Seal(k, n, aad, pt)` | XChaCha20-Poly1305: 32-byte key, 24-byte nonce, 16-byte tag appended |
| `RAND(n)` | `n` bytes from the OS CSPRNG (§9) |

All labels start with `urkey/v1/`. A label is never reused for a different purpose.
Fields whose length is fixed by this spec are concatenated directly; variable-length fields
always use `LP`.

## 2. Primitives and libraries

| Primitive | Standard | Rust crate (RustCrypto unless noted) | Used for |
|-----------|----------|--------------------------------------|----------|
| Argon2id v1.3 | RFC 9106 | `argon2` | Stretching the master password |
| HKDF-SHA-256 | RFC 5869 | `hkdf`, `sha2` | Combining secrets, key separation |
| XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha, RFC 8439 | `chacha20poly1305` | All symmetric encryption and key wrapping |
| Ed25519 | RFC 8032 | `ed25519-dalek` | Account, recovery and device authentication |
| HMAC-SHA-1/256/512 | RFC 2104 | `hmac`, `sha1`, `sha2` | TOTP only |
| AES-256-GCM | NIST SP 800-38D | WebCrypto (browser) | Local-only Secret Key wrap on the web (§8.1) |
| CSPRNG | — | `getrandom` (`wasm_js` backend on the web) | All randomness |
| Zeroization | — | `zeroize` | Wiping secrets from memory |
| Constant-time compare | — | `subtle` | Any comparison of secret-derived values |

The Worker uses WebCrypto Ed25519 `verify` only.

**Why XChaCha20-Poly1305 (D-3):** 192-bit random nonces make accidental reuse negligible
without any counter shared between devices or persisted across crashes. AES-GCM's 96-bit
random nonces would need careful per-key message limits.

## 3. Secrets and identifiers

| Name | Size | Generated | Stored where | Leaves the device? |
|------|------|-----------|--------------|--------------------|
| Master password `PW` | user-chosen | user | user's memory | Never |
| Account Secret Key `ASK` | 16 B (128 bit) | account creation / rotation | each enrolled device (§8) + Emergency Kit | Never to the server |
| Recovery Key `RK` | 32 B (256 bit) | account creation / rotation / after recovery | Emergency Kit only | Never |
| Vault Master Key `VMK` | 32 B | account creation / VMK rotation | memory while unlocked; wrapped in envelopes | Only wrapped |
| `vmk_id` | 16 B random | with each VMK | server + client (public) | Yes (public id) |
| Item key `DEK` | 32 B | item creation / VMK rotation | wrapped by VMK | Only wrapped |
| `account_id` | 16 B random | client at account creation (server checks uniqueness) | server + client | Yes (public) |
| `item_id` | 16 B random | client at item creation | server + client | Yes (public) |
| `kdf_salt` | 16 B random | account creation / password change / ASK rotation | server + client | Yes (public) |
| Device key pair | Ed25519 | device enrollment | device (§8) | Public key only |

### 3.1 Master password normalization
`pw_bytes = UTF-8(NFKC(PW))`. No trimming or case folding. Empty passwords are rejected.
Policy (UX, not crypto): minimum 10 characters plus a strength estimate warning; the 128-bit
ASK carries the server-breach protection, the password protects a stolen device.

### 3.2 Human-readable encodings
Both use Crockford base32 (no padding, case-insensitive on input; `I/L→1`, `O→0`; hyphens and
spaces ignored), followed by one Crockford mod-37 check symbol computed over the payload bytes
interpreted as a big-endian integer. The check symbol only catches typos; it is not a security
mechanism.

| Secret | Format | Example shape (not a real key) |
|--------|--------|--------------------------------|
| ASK | `UK1-` + 26 payload chars + 1 check char, grouped 6-5-5-5-6 | `UK1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXXC` |
| RK | `UKR1-` + 52 payload chars + 1 check char, groups of 4 | `UKR1-XXXX-XXXX-…-XXXC` |

The version prefix lets a future format be recognized. Unknown prefixes are rejected.

## 4. Key derivation

### 4.1 Unlock root (password + Secret Key)

```text
P  = Argon2id(password = pw_bytes, salt = kdf_salt,
              m = kdf.m_kib, t = kdf.t, p = kdf.p, version = 0x13, out_len = 32)
U  = HKDF-Extract(salt = LP("urkey/v1/unlock-root") ‖ account_id,
                  ikm  = P ‖ ASK)                       # 32 ‖ 16 bytes, fixed lengths
KEK_unlock   = HKDF-Expand(U, "urkey/v1/kek/unlock",          32)
auth_seed    = HKDF-Expand(U, "urkey/v1/auth/account-ed25519", 32)
(auth_sk, auth_pk) = Ed25519.from_seed(auth_seed)
```

Properties:
- An attacker with the server database needs **both** `PW` and `ASK`. Guessing `PW` offline is
  infeasible without `ASK` (2^128 work).
- An attacker with a device (and so `ASK`) but not the server data or the password must run
  Argon2id per password guess against the locally cached envelope.
- `auth_pk` is public; it reveals nothing useful about `KEK_unlock` because both are independent
  HKDF-Expand outputs.
- `account_id` in the salt binds the derivation to one account.

### 4.2 Argon2id parameters (D-10)

Encoded as `kdf_params` (13 bytes): `alg(1)=0x01 ‖ u32be(m_kib) ‖ u32be(t) ‖ u32be(p)`.

| Field | Default v1 | Minimum accepted by clients |
|-------|-----------|-----------------------------|
| `m_kib` | 65536 (64 MiB) | 32768 (32 MiB) |
| `t` | 3 | 2 |
| `p` | 1 | 1 |

- Parameters are fixed per account (A6): chosen at creation, stored next to `kdf_salt`, and
  authenticated as AAD of the unlock envelope (§6.2), so a server cannot swap them silently.
- Clients **refuse** parameters below the minimum (prevents a downgrade by a malicious server)
  and above `m_kib = 1 GiB` or `t = 20` (prevents memory/CPU exhaustion).
- `p = 1` because WASM runs single-threaded; it also keeps native and web outputs identical.
- Calibration is a benchmark gate, not runtime tuning: before approval, measure on the slowest
  supported device (an iPhone PWA). Target ≤ 2 s unlock there. If 64 MiB fails (memory limit),
  lower `m` toward the minimum and raise `t`, and record the numbers here.
- Upgrades: a client may re-wrap with stronger params during a password change; the old
  envelope is replaced atomically.

### 4.3 Recovery root

```text
R  = HKDF-Extract(salt = LP("urkey/v1/recovery-root") ‖ account_id, ikm = RK)
KEK_recovery   = HKDF-Expand(R, "urkey/v1/kek/recovery",          32)
rauth_seed     = HKDF-Expand(R, "urkey/v1/auth/recovery-ed25519", 32)
(rauth_sk, rauth_pk) = Ed25519.from_seed(rauth_seed)
```

No password stretching: `RK` is 256 bits of CSPRNG output.

### 4.4 Key separation summary

| Key | Derived from / generated | Used ONLY for |
|-----|--------------------------|---------------|
| `KEK_unlock` | `U` | Wrapping `VMK` in the unlock envelope |
| `auth_sk` | `U` | Signing login and step-up challenges |
| `KEK_recovery` | `R` | Wrapping `VMK` in the recovery envelope |
| `rauth_sk` | `R` | Signing recovery challenges |
| `VMK` | `RAND(32)` | Wrapping DEKs (it never encrypts item content directly) |
| `DEK` | `RAND(32)` | Encrypting one item's payloads (or one snapshot) |
| Device key | random Ed25519 | Signing device login / session refresh |
| Local wrap key (web) | WebCrypto AES-256-GCM, non-extractable | Wrapping `ASK` and the cached device state on that browser |

## 5. Encryption

### 5.1 AEAD and nonces
- Every encryption uses `AEAD.Seal` with `nonce = RAND(24)`, generated fresh for every call.
- Nonces are never derived, counted, or reused. With 192-bit random nonces the collision
  probability stays below 2^-80 even after 2^56 messages under one key; urkey's volumes are many
  orders of magnitude smaller.
- Each key encrypts only one kind of object (§4.4).

### 5.2 Associated data (AAD)
`AAD = header_without_nonce ‖ context(kind)`, where the header is defined in §6.1 and the
context is reconstructed by the reader from data it already trusts (never copied from the blob):

| Kind | Context |
|------|---------|
| Unlock envelope | `account_id ‖ kdf_params ‖ kdf_salt` |
| Recovery envelope | `account_id` |
| DEK wrap | `account_id ‖ item_id` |
| Item payload | `account_id ‖ item_id ‖ u64be(revision)` |
| Tombstone | `account_id ‖ item_id ‖ u64be(revision)` |
| Snapshot | `account_id ‖ LP(snapshot_id)` |
| Local ASK wrap (web) | `account_id ‖ LP(device_id)` |

Binding `item_id` stops a server from moving ciphertext between items. Binding `revision`
stops it from presenting an old payload as a newer revision (rollback of a whole item set is
only partly detectable; see threat model T-9).

### 5.3 Key commitment
Poly1305-based AEADs are not key-committing. Partitioning-oracle attacks need a low-entropy
key; every urkey AEAD key is either 256-bit random or derived with ≥128 bits of secret entropy
(`ASK`/`RK`), so the attack does not apply. If a password-only key is ever introduced, this
section must be revisited (add a key commitment).

### 5.4 Item payload plaintext
```text
plaintext = u32be(len(body)) ‖ body ‖ zero padding
body      = UTF-8 JSON, schema in data-model.md: {"schema":1,"type":"login",...}
```
- Item type, title, URLs and all fields are inside the ciphertext.
- Padding: total `plaintext` length = next power of two ≥ 512 bytes, up to 64 KiB; above that,
  next multiple of 64 KiB. Maximum body 1 MiB.
- Readers verify the length prefix and that padding bytes are zero, then parse JSON with a
  strict schema. Any failure → `DecryptError` (§10).

## 6. Formats

### 6.1 Binary container (all encrypted objects)
```text
offset  size  field
0       2     magic        = "UK"
2       1     format_ver   = 0x01
3       1     kind         (table below)
4       1     alg          0x01 = XChaCha20-Poly1305, 0x02 = AES-256-GCM (local web wrap only)
5       16    key_ref      meaning depends on kind
21      N     nonce        N = 24 for alg 0x01, 12 for alg 0x02
21+N    rest  ciphertext ‖ tag (16 B)
```
`header_without_nonce` = bytes 0..21.

| kind | Object | `key_ref` | Encrypting key | Wrapped plaintext |
|------|--------|-----------|----------------|-------------------|
| 0x01 | Unlock envelope | `vmk_id` of the wrapped VMK | `KEK_unlock` | `VMK` (32 B) |
| 0x02 | Recovery envelope | `vmk_id` | `KEK_recovery` | `VMK` |
| 0x03 | DEK wrap | `vmk_id` of the wrapping VMK | `VMK` | `DEK` (32 B) |
| 0x04 | Item payload | `item_id` | item `DEK` | padded body (§5.4) |
| 0x05 | Tombstone | `item_id` | item `DEK` | empty |
| 0x06 | Local ASK wrap | `device_id` | local wrap key | `ASK` (16 B) |
| 0x07 | Snapshot | `snapshot_id` | snapshot `DEK` | compressed export of item records |

On the wire (JSON) containers are base64url without padding.

### 6.2 Parsing rules
1. Check total length ≥ header + nonce + 16.
2. Reject unknown `magic`, `format_ver`, `kind`, or an `alg` not allowed for that kind.
3. Check `key_ref` equals what the reader expects (e.g. the current `vmk_id`).
4. Rebuild AAD from trusted context; open. Any failure → the single `DecryptError`.

### 6.3 Versioning and agility
- `format_ver` changes only for incompatible layout changes; `alg` ids are added by ADR.
- Clients read the current and previous `format_ver`; they always write the current one and
  upgrade old objects when they next rewrite them.
- The API advertises `min_client_version`; clients that are too old must update before syncing.

## 7. Operations

Each operation that replaces envelopes or keys is one atomic server transaction that also
requires a **step-up signature** (§7.8) from a key the user currently controls.

### 7.1 Account creation
1. `ASK, RK, VMK, vmk_id, account_id, kdf_salt ← RAND`; device key pair ← random.
2. Derive §4.1 and §4.3 values.
3. `unlock_env = Seal(KEK_unlock, …, VMK)`, `recovery_env = Seal(KEK_recovery, …, VMK)`.
4. Upload: `account_id, email, kdf_salt, kdf_params, auth_pk, rauth_pk, unlock_env,
   recovery_env, device_pk, device_name`, plus signatures by `auth_sk` and the device key over
   `LP("urkey/v1/sig/create") ‖ account_id ‖ SHA-256(request body without signatures)`.
5. Show the Emergency Kit (ASK, RK, sign-in address); require confirmation before finishing.

### 7.2 Item write
1. New item: `DEK ← RAND(32)`, `item_id ← RAND(16)`, `dek_wrap = Seal(VMK, …, DEK)`.
2. `revision = base_revision + 1` (1 for a new item); `payload = Seal(DEK, …, plaintext)`.
3. Push `{mutation_id, item_id, base_revision, revision, vmk_id, dek_wrap, payload}`.
4. Delete: same, with a tombstone (kind 0x05) instead of a payload. Clients reject tombstones
   that fail to open, so a server cannot forge a deletion the client accepts silently.

### 7.3 Unlock (known device, offline-capable)
Read `ASK` (§8), cached `kdf_salt`, `kdf_params`, `unlock_env`; derive `KEK_unlock`; open.
On failure show one generic "could not unlock" message.

### 7.4 Login / new-device enrollment
1. `POST /auth/prelogin {email}` → `{account_id, kdf_salt, kdf_params}`. For unknown emails the
   server returns `kdf_salt = HMAC-SHA-256(server_secret, email)[0..16]` and default params, so
   responses do not reveal which emails exist.
2. `POST /auth/challenge {account_id}` → `{challenge_id, nonce: 32 B, expires_at}` (≤ 2 min, single use).
3. Client derives `auth_sk` and signs
   `m = LP("urkey/v1/sig/login") ‖ account_id ‖ nonce ‖ device_id ‖ device_pk ‖ LP(api_origin)`
   with **both** `auth_sk` and the device key.
4. Server verifies both, registers the device if new, returns a session token (§7.9).
5. Client fetches `unlock_env`, opens it, stores `ASK` locally (§8). Other devices are told about
   the new device on their next sync.

### 7.5 Master password change
1. Unlock. Generate a new `kdf_salt'` (and optionally stronger params).
2. Derive `U'`, `KEK_unlock'`, `auth_pk'` from the new password and the current ASK.
3. Upload `{kdf_salt', kdf_params', auth_pk', unlock_env'}` with a step-up signature by the
   **old** `auth_sk` and a proof signature by the **new** `auth_sk`.
4. Items, DEKs and the recovery envelope are untouched (R-ACC-6).
5. Other devices pick up the new envelope on next sync. Until then they still unlock offline
   with the old password (documented residual risk).

### 7.6 Account Secret Key rotation
Same as §7.5 with `ASK' ← RAND(16)` (password unchanged). Other devices cannot derive `U'`, so
after syncing they ask the user to enter the new Secret Key from the updated Emergency Kit.

### 7.7 Recovery and Recovery Key rotation
- **Recovery** (R-REC-1/2): sign a challenge with `rauth_sk`
  (`LP("urkey/v1/sig/recovery") ‖ account_id ‖ nonce ‖ device_pk ‖ LP(api_origin)`); the server
  returns a recovery-scoped session that can only (a) fetch `recovery_env` and (b) submit the
  recovery transaction. The client opens `recovery_env`, then **must** create a new password,
  `ASK'`, `RK'`, salt, both envelopes and both auth public keys, uploaded atomically. The server
  revokes every other device. `VMK` is unchanged by default; the UI offers VMK rotation.
- **Rotation** (R-REC-3): unlocked client generates `RK'`, derives `KEK_recovery'`, `rauth_pk'`,
  uploads `{recovery_env', rauth_pk'}` with a step-up signature by `auth_sk`. The old recovery
  envelope and public key are deleted in the same transaction.

### 7.8 Step-up signatures
Sensitive endpoints (envelope replacement, key rotation, device revocation, VMK rotation,
email change) need a fresh challenge signed with `auth_sk`:
`LP("urkey/v1/sig/stepup") ‖ account_id ‖ nonce ‖ LP(operation) ‖ SHA-256(request body)`.
A stolen session token alone cannot change keys or revoke devices.

### 7.9 Sessions
- Session token = `RAND(32)`, sent as `Authorization: Bearer`; the server stores only
  `SHA-256(token)` with `device_id`, `scope`, `expires_at` (idle 1 h, absolute 24 h).
- Refresh without the password: device signs
  `LP("urkey/v1/sig/refresh") ‖ account_id ‖ nonce ‖ device_id` with its device key.
- Revoked devices fail refresh and all their tokens are deleted.

### 7.10 VMK rotation (R-DEV-3)
1. Unlock. `VMK', vmk_id' ← RAND`.
2. For every item: new `DEK'`, re-encrypt the latest payload (or tombstone) at `revision + 1`,
   new `dek_wrap'` under `VMK'`.
3. New `unlock_env'` and `recovery_env'` wrapping `VMK'` (needs the RK only if the user wants
   to keep the same Recovery Key — otherwise generate `RK'` too; default: generate `RK'`).
4. Upload as one transaction with a step-up signature and `expected_vault_seq`; the server
   rejects later pushes that reference the old `vmk_id`, and clients with pending edits
   re-encrypt them after re-unlocking.
5. Old ciphertexts are deleted from D1 and R2 snapshots older than the rotation are deleted.

## 8. Local secret storage (D-5)

### 8.1 Web
- A non-extractable AES-256-GCM `CryptoKey` is generated with WebCrypto and stored in IndexedDB.
- `ASK` is stored only as a kind-0x06 container under that key.
- The device Ed25519 key is a non-extractable WebCrypto key in IndexedDB.
- Limits (stated honestly): non-extractable keys stop JavaScript from exporting the raw key bytes,
  but any script running on the origin can still *use* them, and the browser profile on disk is
  not hardware-protected. On the web, the master password is the real protection for a stolen
  device.

### 8.2 macOS (CLI / agent)
- `ASK` and the device private key are Keychain generic-password items with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, accessible only to the signed `urk` binary.
- The encrypted vault cache lives in `~/Library/Application Support/urkey/` with mode 0700.

### 8.3 In-memory secrets
- `VMK`, DEKs, KEKs, `U`, `R`, `P`, and decrypted items are held in types that implement
  `Zeroize`/`ZeroizeOnDrop` and have no `Debug`/`Display` output.
- Lock (manual or idle) drops the unlocked session, zeroizing all of them.
- Limits: the browser's password input and any JS strings shown in the UI cannot be wiped; the
  web client passes the password to WASM as a `Uint8Array` and zeroes that array after use.
- The macOS agent uses `mlock` for key memory where available (via a reviewed crate; any
  `unsafe` stays out of the core crates per `CLAUDE.md`).

## 9. Randomness
- Only the OS CSPRNG: `getrandom` (native), `crypto.getRandomValues` via `getrandom`'s
  `wasm_js` backend (web). No user-space PRNG, no seeding, no `Math.random`.
- If the CSPRNG is unavailable or fails, the operation fails closed.
- Deterministic randomness exists **only** behind a `test-vectors` cargo feature that is
  rejected in release builds by a compile-time check.

## 10. Errors
- All decrypt/unwrap/parse failures of protected data return one error, `DecryptError`, with no
  detail. Unlock shows one message for wrong password, wrong Secret Key, or corrupt envelope.
- Errors never include key material, plaintext, passwords or ciphertext.
- Auth failures return `401` with a fixed body; timing differences between unknown and known
  accounts are minimized (fake prelogin, verification always performed).

## 11. Application-level crypto

### 11.1 TOTP (R-ITEM-5)
RFC 6238 over RFC 4226 HOTP using `hmac` with SHA-1/SHA-256/SHA-512; 6–8 digits; period
default 30 s; secrets parsed from `otpauth://` URIs (base32). The TOTP secret is item data
and never leaves the unlocked client. Tests: the RFC 6238 Appendix B vectors.

### 11.2 Password generator (R-ITEM-6)
- Characters: default 20 chars from `[A-Za-z0-9]` plus a configurable symbol set; each
  character chosen with uniform rejection sampling from CSPRNG bytes (no modulo bias);
  required classes enforced by regenerating, not by editing output.
- Passphrases: EFF large wordlist (7,776 words, ≈12.9 bits each, CC BY 3.0), default 6 words
  (≈77 bits), uniform rejection sampling.

### 11.3 SSH keys (R-SSH-*)
- Parsing and serialization of OpenSSH private keys: `ssh-key` crate (RustCrypto).
  Passphrase-protected imports are decrypted once at import; the key is stored in the item
  payload without a passphrase (it is protected by the item DEK).
- Signing: Ed25519 (`ed25519-dalek`), ECDSA P-256 (`p256`). RSA signing is not supported in v1
  (D-7, RUSTSEC-2023-0071).
- Agent protocol: a maintained agent-protocol crate (candidate `ssh-agent-lib`, to be confirmed
  by dependency review).

## 12. Test vectors and interoperability (R-SEC-4)

Committed in `tests/fixtures/crypto-v1/*.json`, generated from fixed **test-only** inputs and
clearly labelled. Required sets:

| Set | Covers |
|-----|--------|
| `encoding.json` | ASK/RK Crockford encoding + check symbol, including invalid inputs |
| `kdf-unlock.json` | `(pw, ASK, account_id, salt, params) → P, U, KEK_unlock, auth_pk` (with low test params *and* one default-params case) |
| `kdf-recovery.json` | `(RK, account_id) → R, KEK_recovery, rauth_pk` |
| `containers.json` | Each kind with fixed nonce → exact bytes; plus tampered-header, wrong-AAD, truncated cases that must fail |
| `item.json` | Padding lengths, item payload round-trip |
| `signatures.json` | Login/step-up/refresh messages → exact bytes and signatures (verified by the Worker tests too) |
| `totp.json` | RFC 6238 Appendix B |

Upstream vectors (RFC 5869, RFC 8032, RFC 9106, XChaCha draft) are run against the chosen crates
as a sanity check.

The same JSON files must pass in: native Rust tests, the WASM build (run under Node), and the
Worker's Vitest suite (signature verification only). Decoders are fuzzed with `cargo fuzz`.

## 13. Review checklist (A14)

Before real credentials are stored, a reviewer must check at least:
1. §4 derivations: input ordering, fixed-length concatenation, label uniqueness.
2. §5.2 AAD contexts are complete and reconstructed from trusted data.
3. §7 operations are atomic and step-up protected; no window without a working envelope.
4. §8 local storage claims match browser and Keychain behavior.
5. Test vectors are reproduced by an independent implementation (e.g., a short Python script
   using `cryptography`/`argon2-cffi`), kept in `tests/fixtures/crypto-v1/README.md`.

## 14. Open questions

| ID | Question | Resolution |
|----|----------|------------|
| Q-1 | Argon2id params (D-10) | Accepted: 64 MiB / t=3 / p=1, floor 32 MiB / t=2. Still to confirm with an iPhone PWA benchmark. |
| Q-2 | New Recovery Key on every VMK rotation? | Accepted: yes (D-12, §7.10) |
| Q-3 | Optional recovery delay (threat model T-12) | Accepted: not in v1 (D-11) |
| Q-4 | Agent-protocol crate choice | Open: decide in the dependency-review ADR |
