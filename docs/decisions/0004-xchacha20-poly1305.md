# 0004. XChaCha20-Poly1305 for all symmetric encryption

- Status: Accepted
- Date: 2026-11-26
- Decision: D-3
- Requirements: R-SEC-2/3

## Context
Several devices encrypt independently and offline; nonce management must not need coordination.

## Decision
Use XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`) with 32-byte keys and fresh random 24-byte
nonces for every encryption and key wrap. AES-256-GCM is used only for the local web Secret Key
wrap, because WebCrypto must hold that key non-extractably.

## Alternatives considered
- AES-256-GCM everywhere: hardware-accelerated, but 96-bit random nonces need per-key message limits.
- AES-GCM-SIV: misuse-resistant, less common in RustCrypto/WebCrypto.

## Consequences
- Random nonces are safe at any realistic volume (crypto design §5.1).
- Not key-committing; acceptable because every key has ≥ 128 bits of secret entropy (§5.3).
