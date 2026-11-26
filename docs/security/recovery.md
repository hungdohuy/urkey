# Recovery, Rotation and the Emergency Kit

Status: **Draft — awaiting review.**
Related: [`cryptographic-design.md`](cryptographic-design.md) §7 (exact operations),
[`devices.md`](devices.md), [`threat-model.md`](threat-model.md) (T-11, T-12, T-14, T-22),
[`../ux/screens.md`](../ux/screens.md) §3.2, §3.5, §3.13. Requirements: R-REC-*, R-ACC-6/7, R-DEV-3.

This document describes the user-facing lifecycle of the account secrets: what each one is
for, what happens when one is lost or exposed, and what each rotation changes.

## 1. The three secrets

| Secret | What it does | Where it lives | If lost | If exposed |
|--------|--------------|----------------|---------|------------|
| **Master password** | Unlocks the vault on enrolled devices; with the Secret Key, signs in new devices | User's memory | Recover with the Recovery Key (§3) | Change it (§4.1). Attacker still needs the Secret Key to sign in, but can unlock a stolen device |
| **Secret Key** | Second, high-entropy input to unlock and sign-in; makes a server breach useless for password guessing | Each enrolled device + Emergency Kit | Read it from any enrolled device (Settings › Security) or the Emergency Kit; else recover (§3) | Rotate it (§4.2) |
| **Recovery Key** | Alone, recovers the vault and resets the other two | Emergency Kit only | Replace it from an unlocked device (§4.3) — do this immediately | Replace it (§4.3) **now**; this is the most sensitive secret (T-12) |

The vault key (VMK) is never shown to the user. It changes only through VMK rotation (§4.4).

## 2. Emergency Kit

- Created at account creation, after recovery, and after any Secret Key or Recovery Key change.
- Contains: sign-in address (API origin), email, Secret Key, Recovery Key, the date, and short
  instructions. It never contains the master password (there is a blank line to write it only
  if the user chooses to).
- Rendered locally as a printable page and an optional text download (D-18). It is never
  uploaded, cached by the service worker, or stored by the app after the screen closes.
- Confirmation: the user types the last 4 characters of the Recovery Key before continuing.
- Guidance shown with it: "Print it or store the file offline. Anyone with this kit can open
  your vault. Don't keep it in email or cloud notes."
- A new kit makes the previous one obsolete for the secrets that changed; the screen says which.

## 3. Recovery

### 3.1 When to use it
- Forgot the master password.
- Lost every enrolled device and the Secret Key is unavailable.
- Suspected account takeover (combined with VMK rotation).

### 3.2 Flow (crypto design §7.7)
1. On any device: **Use a Recovery Key** → email + Recovery Key.
2. Client signs a recovery challenge with the recovery auth key; server returns a
   recovery-scoped session that can only fetch the recovery envelope and submit step 4.
3. Client opens the recovery envelope (gets the VMK) and **requires**:
   a new master password, a new Secret Key and a new Recovery Key (generated).
4. Client uploads, in one atomic request: new KDF salt/params, new auth public key, new unlock
   envelope, new recovery auth public key, new recovery envelope.
5. Server, in the same transaction: revokes every other device, deletes their sessions,
   records a `recovery_used` security event.
6. New Emergency Kit (§2), then the vault opens.
7. Offer: "Also change your vault key?" — recommended if the user suspects someone else had
   access (§4.4).

### 3.3 Failure handling
- Wrong Recovery Key or email → one generic message; attempts rate-limited per account and IP.
- If step 4 fails, nothing changed: the old Recovery Key still works and the user can retry.
- If the connection drops after the server committed but before the client saw the response, the
  client retries with the same idempotency key and receives the stored result.
- There is no moment where neither the old nor the new Recovery Key works.

### 3.4 What recovery does not do
- It does not change the VMK unless the user chooses it, so items are not re-encrypted by default.
- It cannot remove data already copied by an attacker or a lost device (T-14).

## 4. Rotations

All rotations require an unlocked vault and a fresh step-up signature (crypto §7.8). Each is one
atomic server transaction, records a security event, and leaves items untouched unless stated.

| Operation | User reason | Changes | Other devices afterwards | Items re-encrypted? |
|-----------|-------------|---------|--------------------------|---------------------|
| 4.1 Change master password | Routine, or password exposed | KDF salt (+params), auth key, unlock envelope | Next sync: must use the new password; until they sync they still accept the old one offline (T-22) | No |
| 4.2 Change Secret Key | Secret Key exposed | Same as 4.1, new Secret Key; new Emergency Kit | Next sync: user enters the new Secret Key | No |
| 4.3 Replace Recovery Key | Kit lost/exposed, routine | Recovery envelope, recovery auth key; new Emergency Kit | Notice only | No |
| 4.4 Change vault key (VMK) | Device lost/stolen, suspected compromise, after recovery | New VMK, new DEK per item, both envelopes, **new Recovery Key** (D-12) | Next sync: re-unlock; pending edits are re-encrypted (sync.md §8.4) | **Yes** |

### 4.4 VMK rotation details
- Shown with progress ("Re-encrypting 412 items…"); the vault stays readable but editing is
  paused until the upload commits.
- Upload uses `expected_vault_seq`; if another device changed something meanwhile, the client
  pulls, redoes the rotation on the new state and retries.
- Old ciphertext is deleted from D1, and R2 snapshots older than the rotation are deleted.
- Limitation: data a removed device already decrypted or copied stays exposed. Rotation protects
  everything written afterwards.

## 5. Recommended actions by situation

| Situation | Do this |
|-----------|---------|
| Forgot master password, have a device | Recovery (§3) |
| Lost one device (others fine) | Remove it (devices.md §4), then change vault key (§4.4) |
| Lost all devices, have the Emergency Kit | Sign in on a new device with the Secret Key + password; if the password is forgotten too, recovery |
| Emergency Kit lost or seen by someone | Replace Recovery Key (§4.3) and change Secret Key (§4.2) |
| Think someone knows your password | Change master password (§4.1) |
| "New device" notice you don't recognise | Remove that device, change master password **and** vault key |
| Lost the Recovery Key **and** forgot the password, no unlocked device | Vault cannot be recovered. This is the cost of end-to-end encryption and is stated during setup |

## 6. Tests (acceptance)
- R-REC-1: fresh device recovers with Recovery Key only and reads all items.
- R-REC-2: after recovery the old Recovery Key, Secret Key and password fail; other devices are revoked.
- R-REC-3: fault injection at each step of replacement — at every point exactly one Recovery Key works.
- R-ACC-6/7: item containers byte-identical across 4.1–4.3.
- R-DEV-3: after 4.4 no container references the old `vmk_id`; the old VMK opens nothing new.
