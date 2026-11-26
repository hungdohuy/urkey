# 0005. Vault key (VMK) rotation in V1

- Status: Accepted
- Date: 2026-11-26
- Decision: D-4
- Requirements: R-DEV-3; threat model T-14

## Context
Revoking a device stops it syncing but not decrypting what it already has, nor anything written later if it kept the VMK.

## Decision
V1 includes VMK rotation: new VMK, new DEK per item, every item re-encrypted, both envelopes
replaced (with a new Recovery Key, see 0012/D-12), uploaded atomically. The UI offers it after
device removal and after recovery.

## Alternatives considered
- Defer to V1.1: simpler V1, but no real answer to a lost device.

## Consequences
- More sync complexity (stale-keyset handling, sync.md §8.4).
- Rotation cost grows with vault size; fine for a personal vault.
