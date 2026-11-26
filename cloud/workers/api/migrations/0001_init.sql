-- urkey D1 schema v1 (docs/architecture/data-model.md §3). Forward-only.
-- Ids are 16-byte BLOBs; times are Unix milliseconds. The server stores ciphertext only.

CREATE TABLE accounts (
  account_id          BLOB PRIMARY KEY,
  email               TEXT NOT NULL UNIQUE,
  kdf_salt            BLOB NOT NULL,
  kdf_params          BLOB NOT NULL,
  auth_pk             BLOB NOT NULL,
  rauth_pk            BLOB NOT NULL,
  unlock_env          BLOB NOT NULL,
  recovery_env        BLOB NOT NULL,
  vmk_id              BLOB NOT NULL,
  keyset_version      INTEGER NOT NULL DEFAULT 1,
  vault_seq           INTEGER NOT NULL DEFAULT 0,
  tombstone_horizon   INTEGER NOT NULL DEFAULT 0,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL
);

CREATE TABLE devices (
  device_id       BLOB PRIMARY KEY,
  account_id      BLOB NOT NULL REFERENCES accounts(account_id),
  device_pk       BLOB NOT NULL,
  name            TEXT NOT NULL,
  platform        TEXT NOT NULL,
  client_version  TEXT NOT NULL,
  enrolled_via    TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  revoked_at      INTEGER
);
CREATE INDEX devices_account ON devices(account_id);

CREATE TABLE sessions (
  token_hash      BLOB PRIMARY KEY,
  account_id      BLOB NOT NULL,
  device_id       BLOB NOT NULL REFERENCES devices(device_id),
  scope           TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
);
CREATE INDEX sessions_device ON sessions(device_id);

CREATE TABLE challenges (
  challenge_id    BLOB PRIMARY KEY,
  account_id      BLOB NOT NULL,
  nonce           BLOB NOT NULL,
  purpose         TEXT NOT NULL,
  expires_at      INTEGER NOT NULL,
  used_at         INTEGER
);

CREATE TABLE items (
  account_id      BLOB NOT NULL,
  item_id         BLOB NOT NULL,
  revision        INTEGER NOT NULL,
  seq             INTEGER NOT NULL,
  vmk_id          BLOB NOT NULL,
  dek_wrap        BLOB NOT NULL,
  body            BLOB NOT NULL,
  deleted         INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  updated_by      BLOB NOT NULL,
  PRIMARY KEY (account_id, item_id)
);
CREATE UNIQUE INDEX items_feed ON items(account_id, seq);

CREATE TABLE security_events (
  account_id      BLOB NOT NULL,
  seq             INTEGER NOT NULL,
  kind            TEXT NOT NULL,
  device_id       BLOB,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (account_id, seq)
);

CREATE TABLE mutations (
  account_id      BLOB NOT NULL,
  mutation_id     BLOB NOT NULL,
  request_hash    BLOB NOT NULL,
  result          TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (account_id, mutation_id)
);

CREATE TABLE snapshots (
  account_id      BLOB NOT NULL,
  snapshot_id     BLOB NOT NULL,
  vmk_id          BLOB NOT NULL,
  size            INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  PRIMARY KEY (account_id, snapshot_id)
);

-- Fixed-window rate-limit counters (keys hash IPs and ids; no raw IPs are stored).
CREATE TABLE rate_limits (
  bucket          BLOB PRIMARY KEY,
  window_start    INTEGER NOT NULL,
  count           INTEGER NOT NULL
);
