# HTTP API (v1)

Status: **Implemented** (`cloud/workers/api`). Shapes are mirrored in Rust by
`crates/vault-core/src/wire.rs`. Related: [`sync.md`](sync.md), [`data-model.md`](data-model.md),
[`../security/cryptographic-design.md`](../security/cryptographic-design.md) §7.

## Conventions

- Base path `/v1`. JSON bodies. Binary fields are base64url without padding. Times are Unix ms.
- Errors: non-2xx with body `{"error": "<code>"}`. Bodies never echo request data.
- Auth: `Authorization: Bearer <session_token>` where marked **full** or **recovery** (scope).
- Clients send `Urkey-Client: <platform>/<semver>`; below `MIN_CLIENT_VERSION` → `426 update_required`.
- `API_ORIGIN` (Worker variable) is the exact origin string signed in login and recovery messages.
- CORS: only `APP_ORIGIN` is allowed; no cookies are used (T-26).
- Rate limits → `429 rate_limited`.

## Signed payloads

Sensitive requests carry `SignedRequest`:
```json
{ "payload": "<base64url of JSON bytes>", "challenge_id": "…", "sig_account": "…", "sig_device": "…", "sig_new": "…" }
```
The server parses `payload` from exactly those bytes and verifies signatures over
`SHA-256(payload bytes)` inside the message for that endpoint (crypto §7). This avoids any
JSON canonicalization between languages.

## Endpoints

| Method + path | Auth | Request | Response | Signature message (crypto §) |
|---------------|------|---------|----------|------------------------------|
| `POST /v1/auth/prelogin` | — | `{email}` | `{account_id, kdf_salt, kdf_params}` (deterministic fake for unknown emails) | — |
| `POST /v1/auth/challenge` | — (stepup: **full**) | `{account_id, purpose}` (`login` `recovery` `stepup` `refresh`) | `{challenge_id, nonce, expires_at}`; single use, 2 min | — |
| `POST /v1/accounts` | — | `SignedRequest` with `CreateAccountPayload`; `sig_account` + `sig_device` | `SessionResponse` (full) | `create`: `LP(label) ‖ account_id ‖ SHA-256(payload)` |
| `POST /v1/auth/login` | — | `LoginRequest` | `SessionResponse` (full) | `login` (§7.4), signed by account key **and** device key |
| `POST /v1/auth/refresh` | — | `RefreshRequest` | `SessionResponse` (full) | `refresh` (§7.9), device key |
| `POST /v1/auth/recovery` | — | `RecoveryLoginRequest` | `RecoveryLoginResponse` (recovery session + recovery envelope) | `recovery` (§7.7), recovery key **and** device key |
| `POST /v1/auth/logout` | full/recovery | — | `204` | — |
| `GET /v1/account` | full | — | `AccountResponse` (account state incl. public `auth_pk`, `rauth_pk`, `unlock_env`, `vmk_id`, `keyset_version`; devices) | — |
| `POST /v1/account/unlock-keys` | full | `SignedRequest`(`UnlockKeysPayload`), `sig_account` + `sig_new` | `AccountResponse` | `stepup`, operation `change_unlock_keys` |
| `POST /v1/account/recovery-key` | full | `SignedRequest`(`RecoveryKeyPayload`) | `AccountResponse` | `stepup`, operation `replace_recovery_key` |
| `POST /v1/account/rekey` | full | `SignedRequest`(`RekeyPayload`) | `AccountResponse`; `409 vault_changed` if `expected_vault_seq` is stale | `stepup`, operation `rekey` |
| `POST /v1/account/recover` | recovery | `RecoverPayload` (JSON) | `SessionResponse` (full); all other devices revoked | — (recovery session proves the Recovery Key) |
| `POST /v1/devices/revoke` | full | `SignedRequest`(`RevokeDevicePayload`) | `AccountResponse` | `stepup`, operation `revoke_device` |
| `POST /v1/devices/rename` | full | `{device_id, name}` | `AccountResponse` | — |
| `GET /v1/sync/changes?since=&limit=` | full | — | `ChangesResponse`; `410 resync_required` if `0 < since < tombstone_horizon` | — |
| `POST /v1/sync/push` | full | `PushRequest` (≤ 100) | `PushResponse` | — |
| `GET /v1/health` | — | — | `{status, api, min_client_version}` | — |

After a key change whose response was lost, clients re-read `GET /v1/account` to learn whether it
was applied (recovery.md §4.0); the request itself is not retried.

Step-up endpoints require a `stepup` challenge issued to the same account's full session, and a
signature by the **current** account auth key. `unlock-keys` also requires `sig_new` by the new
key (proof of possession).

## Status codes

`400 invalid_request` · `401 unauthorized` · `401 device_revoked` · `403 forbidden` ·
`404 not_found` · `409 conflict` / `vault_changed` / `email_taken` · `410 resync_required` ·
`413 too_large` · `426 update_required` · `429 rate_limited` · `500 internal_error`.

## Server-side validation

- Containers: magic `UK`, version 1, expected kind, algorithm, minimum length, `key_ref`
  (= `vmk_id` for envelopes and DEK wraps, = `item_id` for bodies). Content is never inspected.
- Ids 16 bytes, public keys 32 bytes, signatures 64 bytes, `kdf_params` 13 bytes with the
  floor/ceiling of crypto §4.2, body ≤ 1.1 MiB, ≤ 20 active devices, ≤ 10,000 items.

## Atomicity (D-15)

Every write that assigns a feed `seq` runs as one D1 batch whose statements share the same
guard condition, so either all apply or none:
- push: `UPDATE accounts SET vault_seq+1 WHERE <revision guard>` → upsert item with
  `seq = vault_seq` under the same guard → insert into the idempotency log;
- key changes: account update + security event in one batch;
- rekey: account update guarded by `vault_seq = expected`, then items and the event guarded on
  the new `vmk_id`.
