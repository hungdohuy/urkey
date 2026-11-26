# 0012. Web UI building blocks

- Status: Accepted
- Date: 2026-11-26
- Decision: D-16
- Requirements: R-UX-1…4

## Context
The UI must be accessible, keyboard-friendly and original, without a heavy framework.

## Decision
Radix UI primitives (unstyled, accessible) styled with CSS Modules and CSS-variable tokens;
Lucide icons bundled locally; system fonts only.

## Alternatives considered
- Full component kits (MUI, Chakra): fast, but a recognisable look and large bundles.
- Hand-built primitives: full control, but accessibility details (focus traps, menus) are easy to get wrong.

## Consequences
- Our own visual design on top of proven accessibility behaviour.
- No external font or icon requests (strict CSP).
