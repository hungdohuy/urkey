# 0006. Secret Key storage on devices

- Status: Accepted
- Date: 2026-11-26
- Decision: D-5
- Requirements: R-ACC-3/4

## Context
Unlock must work with only the master password on an enrolled device, including offline, so the Secret Key must be stored locally.

## Decision
- Web: the Secret Key is stored wrapped (AES-256-GCM) by a non-extractable WebCrypto key kept in
  IndexedDB; the device Ed25519 key is a non-extractable WebCrypto key.
- macOS: Keychain items with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

## Alternatives considered
- Ask for the Secret Key at every unlock: secure but unusable.
- Plain storage in IndexedDB: simpler, but exportable by any script.

## Consequences
- On the web the protection is limited: same-origin code can still use the keys and the browser
  profile is not hardware-protected. A stolen device is protected mainly by the master password
  (threat model T-11), which the docs state openly.
