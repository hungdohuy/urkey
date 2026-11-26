# 0010. Hand-written Worker router

- Status: Accepted
- Date: 2026-11-26
- Decision: D-9
- Requirements: —

## Context
The API has a small, fixed set of routes.

## Decision
Use a small hand-written router (`cloud/workers/api/src/router.ts`) with exact method + path
matching and shared response helpers that always add security headers.

## Alternatives considered
- Hono: small and typed, but another dependency on the server for little gain at this size.

## Consequences
- Revisit if the route count or middleware needs grow substantially.
