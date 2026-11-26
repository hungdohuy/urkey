# 0016. SSH key library and agent protocol implementation

- Status: Accepted (owner directive to complete all phases; owner may revisit)
- Date: 2026-11-26
- Decision: resolves crypto spec Q-4
- Requirements: R-SSH-1…3

## Context
`ssh-agent-lib` 0.6 (the maintained agent-protocol crate) depends on `ssh-key` 0.6, whose ECDSA
P-256 stack (`p256` 0.13 → `crypto-bigint` 0.5) is affected by **RUSTSEC-2026-0387**
(non-constant-time operations on secret integers). The fix (`crypto-bigint` ≥ 0.7.6) is only
reachable through the new RustCrypto generation (`p256` 0.14), used by `ssh-key` 0.7, which is
currently a release candidate. That generation is also what `crypto-core` already uses.

## Decision
- Use `ssh-key = "=0.7.0-rc.12"` (exact pin) with only `ed25519`, `p256` and `encryption`
  features; no RSA crate in the tree.
- Implement the SSH agent wire protocol in `crates/ssh-agent` ourselves. Only the messages the
  agent needs are handled (`REQUEST_IDENTITIES`, `SIGN_REQUEST`, extension/other → `FAILURE`);
  key parsing and signing stay in `ssh-key`. The parser is fuzzed.

## Alternatives considered
- `ssh-agent-lib` + `ssh-key` 0.6: stable releases, but ships a known timing advisory on the
  signing path — rejected.
- Ed25519 only (drop P-256): avoids the advisory but drops a V1 requirement.

## Consequences
- A pre-release dependency: re-check on each upgrade, move to `0.7.0` final when released.
- ~200 lines of protocol code we own; covered by unit tests, fuzzing and tests against OpenSSH.
