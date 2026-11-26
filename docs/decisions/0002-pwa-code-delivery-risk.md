# 0002. Accept and mitigate the PWA code-delivery risk

- Status: Accepted
- Date: 2026-11-26
- Decision: D-1
- Requirements: R-SEC-10…13; threat model T-3

## Context
Whoever controls the host that serves the web app can ship JavaScript that captures the master password. End-to-end encryption cannot prevent this for a web client.

## Decision
Accept the residual risk for the PWA and reduce it:
- app and API on separate hostnames with separate deploy credentials;
- strict CSP, no third-party scripts, no analytics;
- reproducible builds with published bundle hashes, shown in Settings › About;
- a service worker that pins the installed bundle and warns before activating a changed one;
- the CLI is documented as the more-trusted client.

## Alternatives considered
- Native-only clients: removes the risk but drops the primary cross-platform experience.
- PWA as read-only viewer: reduces impact but makes the main client second-class.

## Consequences
- The threat model lists T-3 as accepted/partly mitigated; users are told plainly.
- Release process must publish hashes (roadmap P7).
