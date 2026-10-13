BEGIN TRANSACTION;
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
    email TEXT UNIQUE,
    email_verified_at BIGINT,
    email_check INTEGER NOT NULL DEFAULT 1 CHECK (email_check IN (0, 1)),
    srp_user_id TEXT,
    srp_salt TEXT,
    srp_verifier TEXT,
    srp_failures INTEGER NOT NULL DEFAULT 0,
    srp_locked_until BIGINT
);
INSERT INTO "accounts" VALUES('acc_oKte9aPGHpbng6ymgIA69w',1791920625,3,1,'dev_UKpHF1C8mPN7_DX3tCJbMg','dhq06UhWDMOEIZu_exhfPun7SnpnpGpyNJgxRpPBjb6cVuDs3R7uqASXJZQdFccsjoAv1Ss9YXM968vI56DrDQ',1791920625,1,3,1,'AYoMX6aJcLMrTeXhGKicVHwf4aj_YR2mTHXEnb1WPniMmkbR5rE95MV1zpLDClQ4O_7HbUfzJe435-QlNS6Qfp2AhgNw5BXaTwG4oxHPMigBhV8hCrI0rsw94TdK2xdDSHeYLz1cjp8ygocZ4-mDBfbx4KgxLq4hr9Mwb3-gxY0CzmEhbEfjFUUUHrLcpHKQnfk','AgAAAAEAAAAAAAAgANAtOg6W4xOsa4RmXbYWVXs','AZMJH-uIeII3KFcch99OHoDF9ecVYQBczaMnYMEJqP9pRyjmzjAFgQwkWIRTaA1WRFiZV1l9V-na4YJRSPSZspwCbaxd19bXBg','legacy@example.org',NULL,0,'36739354-71bb-4f59-a8b3-a397943986ed','_tKjHp2TJlwu8CiZATrtsQ','ZtfA27rHqpKuuwCOtRlAprWguU_p9fZV1AJ0dfZ_6jZE5IDxdOe-MLcMmATed9WNF4X3x6Tk8efz1Mm1yfLFH1I3u3d9qV9FaHWSJqKTM2W-tyQWAwdNylXUJv5mikpeWF4L671xN6OQKktYidwmYw4Vh_wgt5zVoQHRlt35FsQlvrfmFek_tMHWi_yT7Ziq2GxKctGYmn7fE6aMKi3F5wNuQltOV26Ll6ZGOnCyZq3RE72EsycI76y6-8_EColuGGjwK-9lgYyeb4NVXFh6Yqsx_RNV8UAe8T1V0uD4DPa78PCaedlPGuiVRhodRQn6xbo8UV67WsAwNJBhsxMkCgsJ4ifi0kNrobA9QM3LxAC2PVFqalmaI3PZ__JdmvdaQ4viAaf-ViTJqzn0uWwpIZ_lOgjvHXl4QzXKVXXjLWUkXifDwfM7sg2czuWO5Gdy2CXlVQQWdigHxIb4e3y-J8GueJInHBPUoHKAo0vKQKYy0HQbNJSh2Db9WGLWbOBxeto2DkVMYgkK2J7Fcfjs5n4wWbC3FPYkaAAkNq7UKP4hrHShvOUBvNKWoiquqEd3kVQfwzudvYVz3TEGnAwo_P1pTeKY5GM-ViPkhNWIUkt25vLmaJ1ZJ5cz9bQAC2NwUDM16TFU9dNv_2o8UHRHwp0yvXLkZmMdXHyWuGXb6Mk',0,NULL);
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
    app_version TEXT,
    last_ip TEXT
);
INSERT INTO "devices" VALUES('dev_UKpHF1C8mPN7_DX3tCJbMg','acc_oKte9aPGHpbng6ymgIA69w','ATgiQgBr1YcW_XOybgLQIW3vV6rcS_hgda0an1BgTSM','v57u3y5cgQK-K5vbpA17MNaFpgQ8Q12rFsTHibl4bVg','Legacy phone','bootstrap',NULL,NULL,1791920625,1791920625,NULL,NULL,'192.168.1.10');
INSERT INTO "devices" VALUES('dev_erutBHAkp9DxYbO61c6G8Q','acc_oKte9aPGHpbng6ymgIA69w','6-JULbhKUrsYWRf4r0MtsSKa3ys8V4VjnAC65DsnJk0','yyMII5em-Rdy0VYUwaXn8i8oFUTOdB1uBYu1UMA9uDg','Legacy laptop','password',NULL,NULL,1791920625,1791920625,1791920625,'1.0.0-test','203.0.113.7');
CREATE TABLE email_codes (
    email TEXT NOT NULL PRIMARY KEY,
    salt TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);
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
INSERT INTO "enrollment_tokens" VALUES('cba64d3a93e258b24a91173de4dd539f2a7a0914e8ed64f607d7d782376115ae','acc_oKte9aPGHpbng6ymgIA69w',NULL,1791920625,1791921225,1791920625,'dev_UKpHF1C8mPN7_DX3tCJbMg',0);
INSERT INTO "enrollment_tokens" VALUES('68eeacf7539cfb7fdfa8f161c51897d623296f4db0e02afa77f0851ac6455d2d','acc_oKte9aPGHpbng6ymgIA69w',NULL,1791920625,1791921225,NULL,NULL,0);
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
INSERT INTO "items" VALUES('acc_oKte9aPGHpbng6ymgIA69w','a3abd11f-dcdf-489e-b035-3533bf13a202',1,0,'AQAAAAEBGdGFRIaH0Mmb7B2AuBWJ_zluU6H1AjKrVzwp2ndvFewZ0MdziK1I3irUmXhT1YNZS-M1GVNWOmRd8WCi1SOzeWerUVb_xvAjZ9pSG3rosiNmyXGTO_dl5Rc0PESNSU6aaToxIgZ9ur4O1efJgRiz9LEri06LtBhwR7H7Vw_S4j8yXItUcnDJFcnnYLB3mnS6gZDtvrFSkQVWUZGrjaGg5yl3CmJBHZ8BXut4BvBQPb8NFBv7iUy6XYMCKFWKc8tZYF8HNd97LLHlGBTtM09BNmIOUuUSHBBqOhsjMEKKVS97GabUB8TsRe0y-knFU1KvEpy8wGY7Pmdn5XRpW3cuMPExri6P-i0fMwEOA7uyZJnexWYDSSx0W-FRC-lYYyXCHV2jRn6wKQ','47XpGtfX1V-h5f63P3MWfXZHmchdcZUme--ZVTWkR-8',1791920625);
INSERT INTO "items" VALUES('acc_oKte9aPGHpbng6ymgIA69w','39bba380-d68d-4073-9db5-e9fcde656de0',2,0,'AQAAAAGdjoflNS5DObsmXVE8k69Qiy_1zCcPs0KttbSJkfLKyolkFhEzGUVQ80V5LHFQUsKhy03B0k-liOYqVbyAkQgyve2LcQEcU-wmZ0YhIvjiyrg6zdZEH0sh6VqlQt35nceAptD-d3SVtr4VGpgRUy_YFjhEAdIOnTMfr3BVvV0IeexwpY2B3dsyH8MaIerUcveseWzeDlaEhwgOXIRBkJkKNmTTSZjA8HK6fvY6AmPZpDdPnoOiue44iDbSffRtZYNWY6rQNrWLxUOatSBveh5spUHV4GOqL9ERaPd4LK2KmrDKkGdWzbju0VvpUtEW_8wZbNP1G7wilHrP_3MGI_ZWZnRnByobwoiekmpKEdwmNvIvOSdorZQhRQrUz8A2atct6kyDN4HW9A','hNKsjXFblo_xKhM8ELlnwfZdZe50ZnNSfto230x4k8U',1791920625);
INSERT INTO "items" VALUES('acc_oKte9aPGHpbng6ymgIA69w','529532b4-913e-4c7d-a9eb-b650b5f7dd55',3,1,NULL,NULL,1791920625);
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
CREATE TABLE request_nonces (
    signer TEXT NOT NULL,
    nonce TEXT NOT NULL,
    seen_at BIGINT NOT NULL,
    PRIMARY KEY (signer, nonce)
);
INSERT INTO "request_nonces" VALUES('pending:ATgiQgBr1YcW_XOybgLQIW3vV6rcS_hgda0an1BgTSM','6deQX6qmgPA0rA-tsgozYQ',1791920625);
INSERT INTO "request_nonces" VALUES('dev_UKpHF1C8mPN7_DX3tCJbMg','mWh6yGYHbSnNh1kwGSEIkg',1791920625);
INSERT INTO "request_nonces" VALUES('dev_UKpHF1C8mPN7_DX3tCJbMg','-JXpmZ2kFUPtSl9vRwDlcw',1791920625);
INSERT INTO "request_nonces" VALUES('dev_UKpHF1C8mPN7_DX3tCJbMg','8TE6EzIg8rOXrf6okSrlRA',1791920625);
INSERT INTO "request_nonces" VALUES('pending:6-JULbhKUrsYWRf4r0MtsSKa3ys8V4VjnAC65DsnJk0','q6eDVa1EDYVVGYhtEEoKlQ',1791920625);
INSERT INTO "request_nonces" VALUES('dev_UKpHF1C8mPN7_DX3tCJbMg','DYzxrYUhI1fLbLgf8yciEw',1791920625);
CREATE TABLE schema_migrations ( version INTEGER NOT NULL PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL);
INSERT INTO "schema_migrations" VALUES(1,'0001_init.sql',1791920625);
CREATE TABLE server_secrets (
    name TEXT NOT NULL PRIMARY KEY,
    secret TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE TABLE srp_sessions (
    id TEXT NOT NULL PRIMARY KEY,
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    srp_a TEXT NOT NULL,
    srp_b_secret TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX ix_devices_account ON devices (account_id);
CREATE INDEX ix_device_key_wraps_account ON device_key_wraps (account_id);
CREATE INDEX ix_items_account_version ON items (account_id, version);
CREATE INDEX ix_enrollment_tokens_expires ON enrollment_tokens (expires_at);
CREATE INDEX ix_pairings_expires ON pairings (expires_at);
CREATE INDEX ix_request_nonces_seen ON request_nonces (seen_at);
CREATE INDEX ix_srp_sessions_expires ON srp_sessions (expires_at);
COMMIT;
