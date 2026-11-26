# Data Model (v1)

Status: **Draft — awaiting review.**
Related: [`overview.md`](overview.md), [`sync.md`](sync.md),
[`../security/cryptographic-design.md`](../security/cryptographic-design.md) (container formats, AAD, padding).

This document defines three layers:

1. **Item plaintext** — the JSON inside an encrypted item payload (only clients ever see it).
2. **Records** — the encrypted objects stored and synced (server, IndexedDB, CLI cache).
3. **Server tables** (D1) and **local stores** (IndexedDB, SQLite).

Wire-level encoding: binary values (ids, keys, containers) are base64url without padding in
JSON; ids are 16 random bytes; timestamps are RFC 3339 UTC strings in JSON and integer
milliseconds since the Unix epoch in databases.

## 1. Item plaintext

The decrypted `body` of a kind-0x04 container (crypto design §5.4). UTF-8 JSON.

### 1.1 Common envelope

```jsonc
{
  "schema": 1,                     // item body schema version (integer)
  "type": "login",                 // "login" | "note" | "ssh_key"
  "title": "Example",              // 1..200 chars, required
  "favorite": false,
  "tags": ["work"],                // ≤ 20 tags, each 1..50 chars
  "notes": "",                     // ≤ 64 KiB
  "created_at": "2026-11-26T10:00:00Z",   // client clock, informational
  "updated_at": "2026-11-26T10:00:00Z",   // client clock, informational
  "updated_by": "<device_id b64u>",
  "fields": { /* type-specific, §1.2–1.4 */ },
  "custom_fields": [ /* §1.5 */ ],
  "password_history": [ /* §1.6, login only */ ]
}
```

Rules:
- `item_id` and `revision` are **not** in the body; they come from the record and are bound by
  AAD. The body is never trusted for identity.
- Ordering and timestamps in the body are informational. Sync ordering uses server `seq` and
  per-item `revision` only.
- **Unknown keys are preserved.** Clients keep any key they do not understand and write it back
  unchanged on edit (forward compatibility). Rust: `#[serde(flatten)] extra: Map<String, Value>`.
- A body with `schema` higher than the client supports is shown **read-only** with an
  "update urkey to edit this item" message.
- An unknown `type` is shown as a read-only "Unsupported item" with its title.

### 1.2 Login

```jsonc
"fields": {
  "username": "alice",                       // ≤ 500 chars
  "password": "…",                           // ≤ 1,000 chars, concealed
  "urls": [ { "url": "https://example.com", "label": "website" } ],   // ≤ 20
  "totp": {                                  // or null
    "secret": "JBSWY3DPEHPK3PXP",            // base32 (RFC 4648), concealed
    "algorithm": "SHA1",                     // SHA1 | SHA256 | SHA512
    "digits": 6,                             // 6..8
    "period": 30,                            // 15..120 seconds
    "issuer": "Example",                     // optional
    "account": "alice@example.com"           // optional
  }
}
```
- URLs are stored as entered, validated as `http(s)` URLs (other schemes are kept as plain text
  and never opened). Rendered as text; opened with `noopener,noreferrer`.
- `totp` can be created by pasting an `otpauth://totp/...` URI or scanning a QR code (web: local
  image decoding only; no upload).

### 1.3 Secure note

```jsonc
"fields": {}
```
The note content is the common `notes` field (plain text in v1; Markdown rendering is out of
scope).

### 1.4 SSH key

```jsonc
"fields": {
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n…",  // unencrypted OpenSSH format, concealed
  "public_key": "ssh-ed25519 AAAAC3… comment",              // OpenSSH public key line
  "key_type": "ed25519",                                     // ed25519 | ecdsa-p256 | rsa (stored, not usable for signing in v1)
  "fingerprint": "SHA256:…",                                 // computed at import, re-verified on load
  "comment": "alice@laptop",
  "agent": { "enabled": true }                               // offered by the SSH agent when unlocked
}
```
- Passphrase-protected imports are decrypted once at import (crypto design §11.3).
- On load, clients recompute the public key and fingerprint from `private_key` and reject the item
  for agent use if they do not match.

### 1.5 Custom fields

```jsonc
{ "id": "<random 8 B b64u>", "label": "PIN", "kind": "concealed", "value": "…" }
```
`kind`: `text` | `concealed` | `url` | `email`. ≤ 50 per item. `concealed` values are masked by
default like passwords.

### 1.6 Password history (login)

```jsonc
{ "password": "…", "replaced_at": "2026-11-26T10:00:00Z" }
```
Clients append the previous password when it changes; keep the newest 10. Concealed in the UI.

### 1.7 Validation

Validation lives in `vault-core` and runs before encryption and after decryption. Bodies that
fail validation after decryption are shown as "Damaged item" (title if readable) and never
silently rewritten. Size limit: body ≤ 1 MiB (crypto design §5.4).

## 2. Records

A record is what is stored and synced for one item. It never contains plaintext.

```text
ItemRecord {
  item_id:   16 B
  revision:  u64       // 1 for a new item, +1 for every accepted change
  seq:       u64       // server-assigned position in the account's change feed (sync.md §2)
  vmk_id:    16 B      // VMK that wraps the DEK
  dek_wrap:  container kind 0x03
  body:      Payload(container kind 0x04) | Tombstone(container kind 0x05)
  updated_at: server time (ms)
  updated_by: device_id
}
```

- **Tombstone** = authenticated empty payload (crypto design §7.2). After a delete, the DEK wrap
  is kept so the tombstone can be verified.
- **Conflict copies** (sync.md §6) are ordinary new items whose body has an extra
  `"conflict_of": "<item_id b64u>"` key, so the UI can link them.

Other record types:

| Record | Contents | Where |
|--------|----------|-------|
| `AccountState` | `account_id`, `kdf_salt`, `kdf_params`, `auth_pk`, `unlock_env`, `vmk_id`, `keyset_version`, `vault_seq`, `min_client_version` | Server → client (recovery envelope is returned only to recovery sessions) |
| `DeviceRecord` | `device_id`, `name`, `platform`, `client_version`, `created_at`, `last_seen_at`, `revoked_at` | Server → client |
| `SecurityEvent` | `seq`, `kind`, `device_id`, `created_at` | Server → client, in the change feed |
| `Snapshot` | `snapshot_id`, size, `vmk_id`, `created_at`; object body (container kind 0x07) in R2 | Server |

`SecurityEvent.kind`: `device_enrolled`, `device_revoked`, `password_changed`,
`secret_key_rotated`, `recovery_used`, `recovery_key_rotated`, `vmk_rotated`, `email_changed`.

`keyset_version` is an integer incremented on every change to envelopes, auth keys or the VMK.
Clients use it to detect that their cached `AccountState` is stale.

## 3. Server tables (D1)

Migrations live in `cloud/workers/api/migrations/` and are forward-only. All `BLOB` ids are 16 bytes.

```sql
CREATE TABLE accounts (
  account_id          BLOB PRIMARY KEY,
  email               TEXT NOT NULL UNIQUE,      -- lowercase, trimmed; not used in crypto
  kdf_salt            BLOB NOT NULL,
  kdf_params          BLOB NOT NULL,             -- 13 B (crypto §4.2)
  auth_pk             BLOB NOT NULL,             -- Ed25519, 32 B
  rauth_pk            BLOB NOT NULL,
  unlock_env          BLOB NOT NULL,             -- container 0x01
  recovery_env        BLOB NOT NULL,             -- container 0x02
  vmk_id              BLOB NOT NULL,
  keyset_version      INTEGER NOT NULL DEFAULT 1,
  vault_seq           INTEGER NOT NULL DEFAULT 0, -- last assigned seq
  tombstone_horizon   INTEGER NOT NULL DEFAULT 0, -- seq below which tombstones were purged
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL
);

CREATE TABLE devices (
  device_id       BLOB PRIMARY KEY,
  account_id      BLOB NOT NULL REFERENCES accounts(account_id),
  device_pk       BLOB NOT NULL,                 -- Ed25519, 32 B
  name            TEXT NOT NULL,                 -- user-chosen, ≤ 64 chars
  platform        TEXT NOT NULL,                 -- 'web' | 'macos-cli'
  client_version  TEXT NOT NULL,
  enrolled_via    TEXT NOT NULL,                 -- 'create' | 'login' | 'recovery'
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  revoked_at      INTEGER
);
CREATE INDEX devices_account ON devices(account_id);

CREATE TABLE sessions (
  token_hash      BLOB PRIMARY KEY,              -- SHA-256(token)
  account_id      BLOB NOT NULL,
  device_id       BLOB NOT NULL REFERENCES devices(device_id),
  scope           TEXT NOT NULL,                 -- 'full' | 'recovery'
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
);
CREATE INDEX sessions_device ON sessions(device_id);

CREATE TABLE challenges (
  challenge_id    BLOB PRIMARY KEY,
  account_id      BLOB NOT NULL,
  nonce           BLOB NOT NULL,                 -- 32 B
  purpose         TEXT NOT NULL,                 -- 'login' | 'recovery' | 'stepup' | 'refresh'
  expires_at      INTEGER NOT NULL,
  used_at         INTEGER
);

CREATE TABLE items (
  account_id      BLOB NOT NULL,
  item_id         BLOB NOT NULL,
  revision        INTEGER NOT NULL,
  seq             INTEGER NOT NULL,
  vmk_id          BLOB NOT NULL,
  dek_wrap        BLOB NOT NULL,
  body            BLOB NOT NULL,                 -- container 0x04 or 0x05
  deleted         INTEGER NOT NULL,              -- 1 if body is a tombstone (server cannot verify; hint only)
  updated_at      INTEGER NOT NULL,
  updated_by      BLOB NOT NULL,
  PRIMARY KEY (account_id, item_id)
);
CREATE UNIQUE INDEX items_feed ON items(account_id, seq);

CREATE TABLE security_events (
  account_id      BLOB NOT NULL,
  seq             INTEGER NOT NULL,
  kind            TEXT NOT NULL,
  device_id       BLOB,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (account_id, seq)
);

CREATE TABLE mutations (                         -- idempotency log (sync.md §5)
  account_id      BLOB NOT NULL,
  mutation_id     BLOB NOT NULL,
  request_hash    BLOB NOT NULL,                 -- SHA-256 of the canonical mutation
  result          TEXT NOT NULL,                 -- JSON of the stored response
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (account_id, mutation_id)
);

CREATE TABLE snapshots (
  account_id      BLOB NOT NULL,
  snapshot_id     BLOB NOT NULL,
  vmk_id          BLOB NOT NULL,
  size            INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (account_id, snapshot_id)
);
```

Notes:
- Only the latest revision of each item is stored; older revisions are not kept on the server.
  (Password history inside the body covers the common "what was my old password" case.)
- `items.deleted` is a server-side hint for purging and counts; clients ignore it and decide from
  the authenticated container kind.
- R2 object key for snapshots: `snapshots/<account_id hex>/<snapshot_id hex>`. R2 holds no other data.
- Retention jobs (scheduled Worker): delete expired `challenges` and `sessions` daily; delete
  `mutations` older than 30 days; purge tombstones older than 90 days and raise
  `tombstone_horizon` to the highest purged `seq`.
- `email` is the only directly identifying field. No names, phone numbers or IP addresses are
  stored in D1 (Cloudflare request logs are covered in the threat model §7).

## 4. Local stores

Both clients store the same logical data. Everything except settings is ciphertext or public.

### 4.1 Web (IndexedDB database `urkey`, version 1)

| Object store | Key | Value |
|--------------|-----|-------|
| `meta` | `"account"` | `account_id`, `email`, `api_origin`, `device_id`, `AccountState` fields (incl. `unlock_env`), wrapped ASK (container 0x06) |
| `meta` | `"sync"` | `cursor` (last applied `seq`), `highest_vault_seq_seen`, `last_sync_at`, `last_error_code` |
| `meta` | `"settings"` | Non-secret preferences: auto-lock minutes, theme, clipboard notice dismissed |
| `keys` | `"local_wrap"`, `"device"` | Non-extractable `CryptoKey` objects (crypto §8.1) |
| `items` | `item_id` | Latest server-accepted `ItemRecord` |
| `outbox` | `mutation_id` | Pending mutation (sync.md §4) + `item_id` index + `attempts`, `first_sent_at` |
| `conflicts` | `item_id` | `{ server: ItemRecord, local: Mutation, detected_at }` |
| `known_revisions` | `item_id` | Highest `revision` ever verified (rollback detection, sync.md §7) |
| `events` | `seq` | `SecurityEvent` + `acknowledged` flag |

- The **search index and decrypted items exist only in memory** while unlocked; nothing
  decrypted is written to IndexedDB, `localStorage`, the Cache API or service-worker caches.
- Schema changes use IndexedDB `onupgradeneeded`, forward-only, one function per version.

### 4.2 CLI / agent (SQLite, D-13)

File: `~/Library/Application Support/urkey/vault.db`, directory mode 0700, file mode 0600.
Same tables as §4.1 (`meta` as key/value rows, the rest one table each). `ASK` and the device
key are in the Keychain, not in the database (crypto §8.2). Migrations use `PRAGMA user_version`.

## 5. Size and count limits

| Limit | Value | Enforced by |
|-------|-------|-------------|
| Item body | ≤ 1 MiB | client before encrypt; server rejects `body` > 1.1 MiB |
| Items per account | 10,000 (soft) | server returns `429 limit_reached` |
| Mutations per push | ≤ 100 and ≤ 4 MiB request | server |
| Changes per pull page | ≤ 500 | server |
| Devices per account | 20 active | server |
| Snapshot | ≤ 100 MiB | server |

## 6. Versioning summary

| What | Version field | Owner |
|------|---------------|-------|
| Encrypted containers | `format_ver`, `alg` (crypto §6) | `crypto-core` |
| Item body | `schema` | `vault-core` |
| HTTP API | `/v1/` path prefix + `min_client_version` | Worker |
| D1 schema | migration files | Worker |
| IndexedDB / SQLite | DB version / `user_version` | clients |
| Keys and envelopes | `keyset_version`, `vmk_id` | account |
