-- SPDX-FileCopyrightText: 2026 UltimateOTP contributors
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- Initial schema (extended before the first deployment for SRP, email and sessions). Portable SQL (SQLite now, PostgreSQL possible), same rules as UltimateTunes'
-- contracts/db/README.md: TEXT ids, BIGINT counters, INTEGER 0/1 booleans, Unix-seconds BIGINT
-- times written by the application clock, base64url TEXT for every opaque byte string.
-- The server never stores plaintext: blobs, wraps and KDF parameters are client ciphertext.
--
-- One row per account. It also holds the vault head (version, key epoch, signed head) and the
-- password/recovery wraps of the current key epoch (docs/design.md §3.2, decisions 2).
CREATE TABLE accounts (
    id TEXT NOT NULL PRIMARY KEY,
    created_at BIGINT NOT NULL,
    vault_version BIGINT NOT NULL DEFAULT 0,
    key_epoch BIGINT NOT NULL DEFAULT 1,
    head_signed_by TEXT,
    head_signature TEXT,
    head_updated_at BIGINT,
    rotation_required INTEGER NOT NULL DEFAULT 0 CHECK (rotation_required IN (0, 1)),
    devices_revision BIGINT NOT NULL DEFAULT 0,
    keys_revision BIGINT NOT NULL DEFAULT 0,
    password_wrap TEXT,
    password_kdf TEXT,
    recovery_wrap TEXT,
    -- Login identifier (decision 13): lower-case email, verified once.
    email TEXT UNIQUE,
    email_verified_at BIGINT,
    -- Per-account switch for the emailed code at new-device login (decision 13), on by default.
    email_check INTEGER NOT NULL DEFAULT 1 CHECK (email_check IN (0, 1)),
    -- SRP-6a (decision 6): only the client-chosen identity, the salt and the verifier.
    srp_user_id TEXT,
    srp_salt TEXT,
    srp_verifier TEXT,
    srp_failures INTEGER NOT NULL DEFAULT 0,
    srp_locked_until BIGINT
);

CREATE TABLE devices (
    id TEXT NOT NULL PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    ed25519_public_key TEXT NOT NULL UNIQUE,
    x25519_public_key TEXT NOT NULL,
    label TEXT NOT NULL,
    enrolled_via TEXT NOT NULL
        CHECK (enrolled_via IN ('bootstrap', 'token', 'pairing', 'password', 'signup')),
    added_by TEXT,
    added_by_signature TEXT,
    created_at BIGINT NOT NULL,
    last_seen_at BIGINT,
    revoked_at BIGINT,
    -- Session metadata shown in "Active sessions" (decision 9), plain text by design.
    app_version TEXT,
    last_ip TEXT
);

CREATE INDEX ix_devices_account ON devices (account_id);

-- The vault key sealed to a device's X25519 key, per key epoch, signed by the sealing device.
CREATE TABLE device_key_wraps (
    device_id TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    key_epoch BIGINT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sealed_vault_key TEXT NOT NULL,
    sealed_by TEXT NOT NULL,
    seal_signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (device_id, key_epoch)
);

CREATE INDEX ix_device_key_wraps_account ON device_key_wraps (account_id);

-- Encrypted items. `version` is the vault version of the commit that last changed the row;
-- a delete keeps a tombstone (deleted = 1, blob NULL) so other devices learn about it.
CREATE TABLE items (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    item_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    blob TEXT,
    blob_sha256 TEXT,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, item_id)
);

CREATE INDEX ix_items_account_version ON items (account_id, version);

-- Single-use enrollment tokens; only the SHA-256 of the token is stored.
CREATE TABLE enrollment_tokens (
    token_hash TEXT NOT NULL PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_by TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    used_by TEXT,
    recovery_fetches INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX ix_enrollment_tokens_expires ON enrollment_tokens (expires_at);

-- Device-to-device pairing sessions (docs/design.md §3.4); only the secret's SHA-256 is stored.
CREATE TABLE pairings (
    id TEXT NOT NULL PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_by TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'joined', 'approved', 'rejected')),
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    device_id TEXT,
    ed25519_public_key TEXT,
    x25519_public_key TEXT,
    label TEXT,
    device_signature TEXT,
    decided_at BIGINT
);

CREATE INDEX ix_pairings_expires ON pairings (expires_at);

-- Replay protection: nonces seen per signer within the timestamp window.
CREATE TABLE request_nonces (
    signer TEXT NOT NULL,
    nonce TEXT NOT NULL,
    seen_at BIGINT NOT NULL,
    PRIMARY KEY (signer, nonce)
);

CREATE INDEX ix_request_nonces_seen ON request_nonces (seen_at);

-- Emailed one-time codes (decision 13): salted SHA-256 only, one live code per address.
CREATE TABLE email_codes (
    email TEXT NOT NULL PRIMARY KEY,
    salt TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);

-- SRP handshakes between /srp/session and /srp/verify (5 minutes, single use). The server's
-- ephemeral secret b lives here; account_id is NULL for unknown emails (a decoy handshake).
CREATE TABLE srp_sessions (
    id TEXT NOT NULL PRIMARY KEY,
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    srp_a TEXT NOT NULL,
    srp_b_secret TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX ix_srp_sessions_expires ON srp_sessions (expires_at);

-- Server-side random keys (e.g. the HMAC key for decoy SRP attributes of unknown emails).
CREATE TABLE server_secrets (
    name TEXT NOT NULL PRIMARY KEY,
    secret TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
