-- MedLedger PostgreSQL Schema
-- Reference file — the stores also run these as CREATE TABLE IF NOT EXISTS
-- on first startup, so you only need to run this manually if you want to
-- pre-create the schema before the first boot.
--
-- Run with:
--   psql -U <user> -d <dbname> -f schema.sql

-- ── Users ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id                    SERIAL      PRIMARY KEY,
    email                 TEXT        NOT NULL UNIQUE,
    username              TEXT        NOT NULL,
    full_name             TEXT        NOT NULL DEFAULT '',
    role                  TEXT        NOT NULL DEFAULT 'PATIENT',
    password_hash         TEXT        NOT NULL,
    is_verified           BOOLEAN     NOT NULL DEFAULT FALSE,
    is_active             BOOLEAN     NOT NULL DEFAULT FALSE,
    public_key_hex        TEXT,
    public_key_compressed TEXT,
    public_key_hash       TEXT        UNIQUE,       -- FK into vault_records
    verification_token    TEXT,
    token_expires_at      TEXT,
    created_at            TEXT        NOT NULL,
    last_login            TEXT
);

-- Case-insensitive unique usernames
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower
    ON users (lower(username));

CREATE TABLE IF NOT EXISTS user_audit (
    id          SERIAL  PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    action      TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    timestamp   TEXT    NOT NULL
);

-- ── Vault ─────────────────────────────────────────────────────────────────────

-- Metadata only — no ciphertext here so listing never loads blobs
CREATE TABLE IF NOT EXISTS vault_records (
    record_id             TEXT    PRIMARY KEY,
    owner_key_hash        TEXT    NOT NULL,         -- FK → users.public_key_hash
    owner_public_key_hex  TEXT    NOT NULL,
    filename              TEXT    NOT NULL,
    mime_type             TEXT    NOT NULL,
    size_bytes            INTEGER NOT NULL,
    iv_hex                TEXT    NOT NULL,
    tags                  JSONB   NOT NULL DEFAULT '[]',
    created_at            TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS vault_records_owner_idx
    ON vault_records (owner_key_hash);

-- Encrypted payload — only fetched on download
CREATE TABLE IF NOT EXISTS vault_ciphertext (
    record_id   TEXT  PRIMARY KEY REFERENCES vault_records(record_id) ON DELETE CASCADE,
    ciphertext  BYTEA NOT NULL,                     -- AES-256-GCM ciphertext
    dek_bundle  JSONB NOT NULL                      -- ECIES-wrapped DEK for owner
);

-- ── Grants ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS grants (
    grant_id               TEXT    PRIMARY KEY,
    record_id              TEXT    NOT NULL REFERENCES vault_records(record_id),
    grantor_key_hash       TEXT    NOT NULL,
    grantee_key_hash       TEXT    NOT NULL,
    grantee_public_key_hex TEXT    NOT NULL,
    permission_level       TEXT    NOT NULL,        -- 'view_only' | 'view_download'
    time_start             TEXT    NOT NULL,        -- ISO UTC
    time_end               TEXT    NOT NULL,        -- ISO UTC
    dek_bundle_grantee     JSONB   NOT NULL,        -- ECIES-wrapped DEK for grantee
    signature_hex          TEXT    NOT NULL,        -- ECDSA sig by grantor
    revoked                BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at             TEXT,
    created_at             TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS grants_grantor_idx ON grants (grantor_key_hash);
CREATE INDEX IF NOT EXISTS grants_grantee_idx ON grants (grantee_key_hash);
CREATE INDEX IF NOT EXISTS grants_record_idx  ON grants (record_id);

-- ── Vault Audit ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vault_audit (
    id              SERIAL  PRIMARY KEY,
    action          TEXT    NOT NULL,
    actor_key_hash  TEXT    NOT NULL DEFAULT '',
    record_id       TEXT    NOT NULL DEFAULT '',
    detail          TEXT    NOT NULL DEFAULT '',
    timestamp       TEXT    NOT NULL
);
