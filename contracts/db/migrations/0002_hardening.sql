-- SPDX-FileCopyrightText: 2026 UltimateOTP contributors
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- Server hardening (contract 1.2.0): vault history, temporary client blocks, email change,
-- per-account language, re-authentication sessions. Additive: every existing row survives.
-- A server upgraded from 1.1.0 starts with an empty history; nothing is back-filled (the
-- previous blobs were overwritten in place and are gone).

-- One row per committed vault version the server still remembers. The signed head is kept so a
-- client can verify a past state; `upserted` and `deleted` are JSON arrays of item ids (ids are
-- random UUIDs chosen by the client, not secret). Pruned together with `item_history`.
CREATE TABLE vault_versions (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    key_epoch BIGINT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('commit', 'rotate')),
    signed_by TEXT NOT NULL,
    signature TEXT NOT NULL,
    committed_at BIGINT NOT NULL,
    upserted TEXT NOT NULL,
    deleted TEXT NOT NULL,
    PRIMARY KEY (account_id, version)
);

-- Previous states of items, ciphertext only: the blob an item had until commit `superseded_by`
-- replaced or deleted it. Independent of the tombstone in `items`, so an entry deleted less than
-- the retention ago stays recoverable after its tombstone is compacted.
CREATE TABLE item_history (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    item_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    superseded_by BIGINT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('replaced', 'deleted')),
    blob TEXT NOT NULL,
    blob_sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    PRIMARY KEY (account_id, item_id, version)
);

CREATE INDEX ix_item_history_superseded ON item_history (account_id, superseded_by);

-- Active temporary blocks, so a restart does not wipe a 24 h block. Keyed by the anonymized
-- client id of its UTC day (never an address). Pruned after the back-off decay.
CREATE TABLE client_blocks (
    client_id TEXT NOT NULL PRIMARY KEY,
    level INTEGER NOT NULL,
    blocked_until BIGINT NOT NULL,
    last_event_at BIGINT NOT NULL,
    reason TEXT NOT NULL
);

CREATE INDEX ix_client_blocks_until ON client_blocks (blocked_until);

-- A pending email change: the code went to `new_email`; one per account.
CREATE TABLE email_changes (
    account_id TEXT NOT NULL PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    new_email TEXT NOT NULL,
    salt TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);

-- Language of the emails an account gets without a request to read it from ('en', 'es').
ALTER TABLE accounts ADD COLUMN lang TEXT;

-- Highest version of a tombstone that was compacted away: a client older than this gets the full
-- live set instead of a delta (VaultChanges.full).
ALTER TABLE accounts ADD COLUMN tombstones_compacted_through BIGINT NOT NULL DEFAULT 0;

-- 'login' handshakes come from /srp/session (emailed code checked); 'reauth' ones from a signed
-- device and are only good for the account-management actions, never for /srp/verify.
ALTER TABLE srp_sessions ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login';

-- The server keeps no client IP any more: drop the addresses stored by 1.1.0. From now on
-- `last_ip` holds the opaque daily client id.
UPDATE devices SET last_ip = NULL;
