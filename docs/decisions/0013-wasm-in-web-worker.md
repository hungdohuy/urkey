# 0013. Run the WASM core in a dedicated Web Worker

- Status: Accepted
- Date: 2026-11-26
- Decision: D-17
- Requirements: R-ACC-3, R-SEC-1

## Context
Argon2id (~1–2 s) and VMK rotation would freeze the page if run on the main thread; keys should stay away from UI code.

## Decision
The WASM core runs in a dedicated Web Worker. The UI sends typed messages and receives display
data only; keys and session handles stay inside the worker. Copying uses `copyField(itemId, field)`.

## Alternatives considered
- WASM on the main thread: simpler, but the UI freezes during unlock.

## Consequences
- Message protocol must be typed and versioned with the app.
- It is not a security boundary against code on the same origin (overview §5); it is hygiene and
  responsiveness.
