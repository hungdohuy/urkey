# Synchronization Protocol (v1)

Status: **Draft — awaiting review.**
Related: [`data-model.md`](data-model.md), [`overview.md`](overview.md) §7.6,
[`../security/cryptographic-design.md`](../security/cryptographic-design.md) §7,
[`../security/threat-model.md`](../security/threat-model.md) (T-4, T-6, T-9, T-14).
Requirements: R-SYNC-1…6, R-DEV-1…3.

## 1. Goals

1. Every enrolled device converges to the same set of items.
2. **No user edit is ever silently lost**: each edit ends up as the current version, in a
   conflict copy, or (for passwords) in password history.
3. Works offline; edits queue and sync later.
4. Every request is safe to retry.
5. The server only orders and stores ciphertext; it cannot forge or reorder changes undetected
   (except withholding, threat model T-9).

Non-goals for v1: field-level merging, real-time push (WebSockets), background sync while locked.

## 2. Model

- **Per-item revision.** Each item has an integer `revision`. A change is accepted only if it says
  which revision it was based on (`base_revision`) and that is still the current one
  (optimistic concurrency). The new revision is `base_revision + 1` and is bound into the
  ciphertext's AAD, so the client chooses it and the server cannot change it.
- **Per-account change feed.** The server keeps `vault_seq`, a counter for the account. Every
  accepted item change and every security event gets the next `seq`. Clients pull "everything
  with `seq > cursor`".
- **Feed invariant (required):** when a client sees `seq = n`, every change with `seq < n` is
  already committed and visible. Otherwise a client could advance its cursor past a change it
  never received. D1 executes writes for a database one at a time and each batch is atomic,
  which provides this if the `seq` is assigned inside the same batch as the write (§9).
- Only the latest revision of each item is kept on the server.

## 3. Endpoints

All under `/v1/`, require a `full`-scope session (`Authorization: Bearer`), and return
`426 update_required` when the client version header `Urkey-Client: <platform>/<semver>` is below
`min_client_version`.

### 3.1 `GET /v1/account`
Returns `AccountState` (data-model §2) and the device list. Used after login, after a
`keyset_changed` response, and after security events.

### 3.2 `GET /v1/sync/changes?since=<seq>&limit=<n>`
```jsonc
{
  "vault_seq": 1042,             // current head
  "keyset_version": 3,
  "vmk_id": "…",
  "changes": [                    // ordered by seq ascending, ≤ limit (max 500)
    { "type": "item", "seq": 1001, "item": { /* ItemRecord */ } },
    { "type": "event", "seq": 1002, "event": { "kind": "device_enrolled", "device_id": "…", "created_at": "…" } }
  ],
  "next": 1002,                   // seq of the last change returned (== since if none)
  "has_more": false
}
```
- If `since < tombstone_horizon` → `410 resync_required` (§8.1).
- An item appears at most once per page, at its latest `seq`.

### 3.3 `POST /v1/sync/push`
```jsonc
{
  "mutations": [                  // ≤ 100, applied in order, each independently
    {
      "mutation_id": "…",         // 16 random bytes, client-generated
      "item_id": "…",
      "base_revision": 4,         // 0 for a new item
      "revision": 5,              // must equal base_revision + 1
      "vmk_id": "…",
      "dek_wrap": "…",            // container 0x03
      "body": "…",                // container 0x04 or 0x05
      "deleted": false            // hint only (data-model §3)
    }
  ]
}
```
Response: one result per mutation, same order:

| `status` | Meaning | Extra fields |
|----------|---------|--------------|
| `applied` | Stored | `seq` |
| `duplicate` | `mutation_id` seen before with the same content; returns the original result | original result |
| `conflict` | `base_revision` ≠ current revision (or item exists when `base_revision = 0`) | `current`: the server `ItemRecord` |
| `keyset_changed` | `vmk_id` is not the account's current VMK | `vmk_id`, `keyset_version` |
| `invalid` | Malformed (bad container header, size, `revision ≠ base+1`, `mutation_id` reused with different content) | `code` |

HTTP status is `200` when the batch was processed (even if some results are `conflict`),
`401` for auth problems, `429`/`5xx` for retryable failures.

### 3.4 Key and device operations
`POST /v1/keys/unlock-envelope`, `/v1/keys/recovery`, `/v1/keys/rekey` (VMK rotation),
`POST /v1/devices/{id}/revoke`, `PATCH /v1/devices/{id}` (rename) — all step-up signed
(crypto §7.8). Each writes a `security_events` row with the next `seq`.
`/v1/keys/rekey` additionally requires `expected_vault_seq` and fails with `409 vault_changed`
if any change happened since the client prepared the rekey.

## 4. Client: the outbox

Local edits never write directly into the `items` store. Each edit becomes a **mutation** in the
`outbox` (data-model §4.1), already encrypted.

- **New item:** `base_revision = 0`, `revision = 1`, new `item_id` and DEK.
- **Edit/delete:** `base_revision = ` the revision the user was editing.
- **Edits to an item that already has a pending mutation:**
  - If that mutation was **never sent**, replace it (same `base_revision`, new body, new `mutation_id`).
  - If it was **sent at least once** (it may already be applied), queue a new mutation based on
    it: `base_revision = pending.revision`. Never change the content of a mutation that may have
    reached the server.
- The UI shows the local result immediately (from the decrypted outbox) with a "not synced" mark.
- Outbox entries leave only when the server answers `applied`, `duplicate`, or the user resolves a
  conflict.

## 5. Idempotency and retries

- `mutation_id` is generated once per mutation and reused on every retry.
- The server stores `(mutation_id, SHA-256(canonical mutation), result)` for 30 days in the same
  D1 batch as the write. A repeated id with the same hash returns the stored result; with a
  different hash it returns `invalid / mutation_id_reused`.
- A client that has not heard back within 30 days resolves the mutation by pulling: if the server
  record has the same `revision` and identical `body` bytes, the mutation was applied.
- Retries: network errors, `429` and `5xx` → exponential backoff with full jitter, 1 s doubling to
  5 min, unlimited while online and unlocked. `4xx` other than `401/409/429` are not retried; the
  mutation is marked failed and shown to the user.
- `401` → refresh the session with the device key (crypto §7.9) once, then retry. If refresh fails
  with `device_revoked` → §8.3.

## 6. Conflicts

### 6.1 Detection
A conflict exists when the server's current revision for an item is higher than a pending
mutation's `base_revision`. It is found either while pulling (before pushing) or from a push
result.

### 6.2 Automatic handling (no user present)
The server version always becomes the item's current state; the local version is kept, never
discarded:

| Local pending | Server current | Automatic result | Shown to user |
|---------------|----------------|------------------|---------------|
| Edit | Edit | Server version is current; local edit stored in `conflicts` | "Edited on two devices" — choose |
| Edit | Delete | Item stays deleted; local edit stored in `conflicts` | "Deleted on another device — restore your version?" |
| Delete | Edit | Server edit is current; local delete dropped | "Not deleted: it was edited on another device" (info) |
| Delete | Delete | Nothing to do | — |
| Edit | VMK-rotation revision with identical content (§8.4) | Not a conflict: rebase and push | — |

If the only difference is the password and the server password is newer, both passwords stay
reachable: the losing one is added to `password_history` when the user resolves.

### 6.3 User resolution
For each entry in `conflicts`, the UI shows both versions side by side (concealed fields masked)
and offers:
- **Keep this device's version** → new mutation with `base_revision = server.revision`.
- **Keep the other version** → drop the local mutation.
- **Keep both** → local version saved as a new item with `"conflict_of"` set and title suffix
  "(conflict copy)".

Unresolved conflicts are listed in a "Needs attention" view and shown as a sync state (R-UX-3).
They do not block syncing other items.

## 7. Integrity checks on pull (threat model T-4, T-6, T-9)

For every pulled item record, before storing it the client:
1. Checks `vmk_id` is the current VMK (otherwise §8.4).
2. Opens `dek_wrap` (AAD: `account_id ‖ item_id`) and the body (AAD includes `revision`).
3. Checks `revision ≥ known_revisions[item_id]`.
4. For equal revision with different bytes → integrity error.

Failures do **not** overwrite local data. The record is quarantined, an "integrity problem"
security notice is shown, and sync continues for other items.

Feed-level checks: the server's `vault_seq` must never be lower than `highest_vault_seq_seen`;
`keyset_version` must never decrease. A decrease shows a "server returned older data" warning
and stops pushing until the user acknowledges.

## 8. Special situations

### 8.1 Stale device / resync
`410 resync_required` (cursor below `tombstone_horizon`, i.e. offline > 90 days):
1. Keep the outbox.
2. Pull from `since=0` into a fresh `items` store.
3. Items present locally but absent from the server are treated as deleted remotely (their
   tombstones were purged); if they have pending edits, those go to `conflicts` as
   "Deleted on another device".
4. Resume normal sync.

Devices not seen for 180 days are marked "inactive" in the device list with a revoke suggestion.
They are not revoked automatically.

### 8.2 Security events
Pulled events are stored and shown as notices (R-DEV-2). Some trigger client actions:

| Event | Client action |
|-------|---------------|
| `device_enrolled` | Notice: "New device: <name>, <platform>" with "Not me? Revoke + rotate" |
| `password_changed` | Refetch `AccountState`; next unlock uses the new password |
| `secret_key_rotated` | Refetch; next unlock asks for the new Secret Key (crypto §7.6) |
| `recovery_used` | High-priority notice (normally this device was revoked too, §8.3) |
| `recovery_key_rotated` | Notice only |
| `vmk_rotated` | §8.4 |
| `device_revoked` | Notice; if it is this device, §8.3 |

### 8.3 This device was revoked
On `401 device_revoked`:
1. Stop syncing and lock.
2. Tell the user the device was removed from the account.
3. If the outbox is not empty, offer **Export unsynced changes** (encrypted export the user can
   import after re-enrolling).
4. Delete the local wrapped ASK, device key, session and vault cache.

An honest client follows this; a compromised one may not, which is why VMK rotation exists
(threat model T-14).

### 8.4 VMK rotated on another device (`keyset_changed` / `vmk_rotated`)
1. Refetch `AccountState`. Keep the old VMK in memory for step 3.
2. Ask the user to unlock again (the new unlock envelope wraps the new VMK).
3. For each outbox mutation: decrypt with the old keys, then re-encrypt against the server's
   rotated record — new `dek_wrap` from the server, `base_revision` = rotated revision. If the
   decrypted content at the old `base_revision` equals the rotated content (rotation does not
   change content), rebase without conflict; otherwise normal conflict handling.
4. Zeroize the old VMK. Resume.

### 8.5 Schema and client upgrades
- `426 update_required` → stop syncing, keep working offline read-write (outbox grows), show
  "Update required to sync".
- Items with a higher body `schema` → read-only until the client updates (data-model §1.1).
- Clients upgrade older-format objects only when they next write them (crypto §6.3).

## 9. Server implementation requirements (D-15)

For each mutation, in **one D1 batch**:
1. Insert/update the item only if the current revision equals `base_revision` (insert only if the
   item does not exist when `base_revision = 0`), setting `seq = vault_seq + 1`.
2. Increment `accounts.vault_seq` only if step 1 changed a row.
3. Insert the `mutations` idempotency row.

If this cannot be expressed so that the batch is atomic and conditional (to be proven by
concurrency tests in Miniflare with parallel pushes), switch to one Durable Object per account
that serializes writes, and record that in an ADR superseding D-8/D-15.

Additional rules:
- Validate every container header (magic, version, kind, alg, sizes, `key_ref` = `item_id` for
  bodies) before storing — the server cannot check content but rejects malformed shapes.
- Never log request bodies.
- Rate limits: push 60/min per device, pull 120/min per device.

## 10. Client sync loop (D-14)

Sync runs only while the vault is unlocked:

```text
on: unlock, local edit (debounced 2 s), every 60 s, network online, tab visible
  1. pull until has_more = false       (verify, apply, update cursor after each page is stored)
  2. detect conflicts for pending mutations against pulled records
  3. push outbox (oldest first, ≤ 100 per request), handle results
  4. if anything was applied: pull once more (picks up our own changes and anything in between)
```
- The cursor is only advanced from **pull** responses, never from push results (push `seq`s can
  skip over other devices' changes).
- Re-applying our own change from a pull is a no-op (same revision, same bytes).
- Only one sync loop runs per device (web: a Web Lock across tabs).

UI sync states (R-UX-3): `synced`, `syncing`, `offline (n pending)`, `needs attention` (conflicts
or integrity notices), `error` (with retry), `update required`, `signed out / revoked`.

## 11. Tests (R-SYNC acceptance)

1. **Simulation tests in `sync-core`** with an in-memory server: N devices, random edits,
   deletes, offline periods, dropped requests and dropped responses, duplicate deliveries and
   rotations. Checked properties:
   - all devices converge after a final sync;
   - every edit is current, in a conflict copy, or in password history (no silent loss);
   - no mutation is applied twice;
   - cursors never skip a change.
2. **Worker tests** (Vitest + Miniflare): conditional writes under parallel pushes, idempotency,
   `410` after purge, `426`, revoked-device `401`, rekey `409`.
3. **Integrity tests**: server returns swapped, rolled-back or forged records → client quarantines
   and warns.
4. **End-to-end**: two browsers (Playwright) + CLI against local `wrangler dev`: offline edits on
   both, reconnect, resolve a conflict.
