# 0015. CLI binary is named `urk`

- Status: Accepted
- Date: 2026-11-26
- Decision: D-20 (owner request); amends 0007
- Requirements: R-SSH-4

## Context
The owner asked for a short command name: `urk` or `uk`, not `urkey`.

## Decision
The binary built from `crates/cli` (package `urkey-cli`) is **`urk`**. Examples: `urk unlock`,
`urk lock`, `urk agent start`. The product, repository, data directories and Keychain service
names stay `urkey`.

## Alternatives considered
- `uk`: shorter, but two letters is more likely to clash with other tools and shell aliases, and
  reads as a country code.
- Ship both: more to document and support for no real gain; users can add a shell alias.

## Consequences
- Docs and examples use `urk`. A `uk` alias can be suggested in the install docs.
