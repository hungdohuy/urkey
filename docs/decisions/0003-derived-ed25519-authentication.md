# 0003. Account authentication with a derived Ed25519 key

- Status: Accepted
- Date: 2026-11-26
- Decision: D-2
- Requirements: R-AUTH-1…3

## Context
Authentication must be separate from vault encryption, must not let a server-database thief guess the password offline, and must also work for recovery.

## Decision
- Login signs a server challenge with an Ed25519 key derived (HKDF, separate label) from the same
  root as the unlock KEK: Argon2id(password) combined with the 128-bit Secret Key.
- Recovery signs with an Ed25519 key derived from the Recovery Key.
- Each device has its own random Ed25519 key; logins are signed by both the account key and the device key.
- Sensitive operations need a fresh step-up signature (crypto design §7.8).

## Alternatives considered
- OPAQUE (aPAKE): strong, but its main benefit (no offline guessing from the server's record) is
  already provided by the Secret Key; it adds a less common dependency and protocol complexity.
- SRP: older, similar trade-off.
- Password hash sent to the server: allows offline guessing; rejected.

## Consequences
- Server stores only public keys; a database dump does not enable guessing without the Secret Key.
- The Secret Key must be present to sign in; it is stored on enrolled devices and in the Emergency Kit.
