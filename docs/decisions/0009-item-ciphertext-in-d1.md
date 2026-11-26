# 0009. Item ciphertext in D1, snapshots in R2

- Status: Accepted
- Date: 2026-11-26
- Decision: D-8
- Requirements: R-SYNC-1

## Context
Items are small (padded to ≥ 512 B, ≤ 1 MiB) and sync needs transactional ordering.

## Decision
Store each item's latest encrypted record in a D1 row with its revision and `seq`. R2 holds only
encrypted snapshots/backups.

## Alternatives considered
- Item blobs in R2 with metadata in D1: two-system writes, no single transaction.
- Whole-vault blob: simple, but every edit uploads everything and conflicts become coarse.

## Consequences
- One atomic write per change (D-15, sync.md §9).
- D1 size limits apply; well within personal use.
