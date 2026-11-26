# 0007. macOS V1 scope: Rust CLI and launchd SSH agent

- Status: Accepted
- Date: 2026-11-26
- Decision: D-6
- Requirements: R-SSH-1…4

## Context
The brief asks for a macOS companion where native integration is required. The SSH agent is the only V1 feature that needs it.

## Decision
V1 ships a Rust CLI (`urkey`) and an SSH agent run by launchd, with Keychain storage. A native
app (Touch ID unlock, per-use signing confirmation) is V1.1.

## Alternatives considered
- SwiftUI app in V1: better UX, but a second UI codebase before the core is proven.

## Consequences
- No per-use confirmation in V1 (R-SSH-5 deferred); agent forwarding risk documented (T-19).
