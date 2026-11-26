# 0008. No RSA signing in V1

- Status: Accepted
- Date: 2026-11-26
- Decision: D-7
- Requirements: R-SSH-6

## Context
The main pure-Rust RSA crate has an open timing side-channel advisory (RUSTSEC-2023-0071, "Marvin").

## Decision
V1 signs with Ed25519 and ECDSA P-256 only. RSA keys can be imported and stored but the agent
does not offer them.

## Alternatives considered
- Use `rsa` anyway: practical risk is lower for local signing, but it conflicts with `cargo deny`
  and the security-first rule.
- Use a C library (OpenSSL): banned by `deny.toml` to keep the tree pure Rust.

## Consequences
- Users with RSA-only servers need another agent for those hosts until this is revisited.
