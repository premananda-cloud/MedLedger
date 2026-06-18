-- MedLedger Complete Database Schema
-- Run this to initialize or reset the database
-- Usage: psql -U premananda -d medledger_db -f schema.sql

-- =====================================================
-- ENABLE REQUIRED EXTENSIONS
-- =====================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================
-- DROP EXISTING TABLES (if resetting)
-- =====================================================

-- Drop in correct order to avoid foreign key conflicts
DROP TABLE IF EXISTS vault_ciphertext CASCADE;
DROP TABLE IF EXISTS vault_records CASCADE;
DROP TABLE IF EXISTS grants CASCADE;
DROP TABLE IF EXISTS vault_audit CASCADE;
DROP TABLE IF EXISTS share_access_log CASCADE;
DROP TABLE IF EXISTS active_shares CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS rate_limit CASCADE;
DROP TABLE IF EXISTS token_revocations CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS pow_challenges CASCADE;
DROP TABLE IF EXISTS user_audit CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- =====================================================
-- ENUM TYPES
-- =====================================================

CREATE TYPE audit_action AS ENUM (
    'register',
    'login_success',
    'login_failure',
    'logout',
    'share_create',
    'share_retrieve',
    'share_revoke',
    'share_expire',
    'delete_account',
    'vault_unlock',
    'vault_lock',
    'grant_create',
    'grant_revoke'
);

CREATE TYPE share_status AS ENUM (
    'active',
    'retrieved',
    'expired',
    'revoked',
    'deleted'
);

-- =====================================================
-- USERS TABLE (Enhanced with MedLedger crypto)
-- =====================================================

CREATE TABLE users (
    -- Primary identifiers
    id                    SERIAL      PRIMARY KEY,
    user_id_hex           VARCHAR(32) UNIQUE,  -- 32-char hex from BLAKE2b(signingPublicKey)
    username              TEXT        NOT NULL,
    email                 TEXT        NOT NULL,
    full_name             TEXT        NOT NULL DEFAULT '',
    role                  TEXT        NOT NULL DEFAULT 'PATIENT',

    -- Authentication (Argon2id)
    password_hash         TEXT        NOT NULL,
    pwhash_salt           VARCHAR(32),  -- 16-byte hex salt for deterministic derivation

    -- MedLedger Public Keys (replaces public_key_hex)
    signing_public_key    VARCHAR(64),  -- base64url Ed25519 public key
    exchange_public_key   VARCHAR(64),  -- base64url X25519 public key
    public_key_hex        TEXT,         -- Legacy, kept for compatibility
    public_key_compressed TEXT,         -- Legacy
    public_key_hash       TEXT UNIQUE,  -- Legacy FK into vault_records

    -- Key derivation (deterministic keys)
    server_salt           VARCHAR(64) NOT NULL DEFAULT encode(gen_random_bytes(32), 'hex'),

    -- Email for rate-limiting (hashed)
    email_hash            VARCHAR(64) GENERATED ALWAYS AS (encode(sha256(email::bytea), 'hex')) STORED,

    -- Account status
    is_verified           BOOLEAN     NOT NULL DEFAULT FALSE,
    is_active             BOOLEAN     NOT NULL DEFAULT TRUE,
    account_deleted       BOOLEAN     NOT NULL DEFAULT FALSE,

    -- Verification tokens (legacy, kept for now)
    verification_token    TEXT,
    token_expires_at      TEXT,

    -- Metadata
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login_at         TIMESTAMP WITH TIME ZONE,
    last_login_ip         INET,
    deleted_at            TIMESTAMP WITH TIME ZONE,

    -- Indexes
    CONSTRAINT users_username_unique UNIQUE (username)
);

-- Case-insensitive unique usernames
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username));
CREATE INDEX IF NOT EXISTS idx_users_user_id_hex ON users(user_id_hex);
CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- =====================================================
-- USER AUDIT (Enhanced)
-- =====================================================

CREATE TABLE user_audit (
    id          SERIAL  PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action      TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    ip_address  INET,
    user_agent  TEXT,
    timestamp   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_audit_user_id ON user_audit(user_id);
CREATE INDEX idx_user_audit_timestamp ON user_audit(timestamp);

-- =====================================================
-- VAULT RECORDS (Metadata only - no ciphertext)
-- =====================================================

CREATE TABLE vault_records (
    record_id             TEXT    PRIMARY KEY,
    owner_key_hash        TEXT    NOT NULL REFERENCES users(public_key_hash),
    owner_user_id_hex     VARCHAR(32) REFERENCES users(user_id_hex),
    owner_public_key_hex  TEXT    NOT NULL,
    filename              TEXT    NOT NULL,
    mime_type             TEXT    NOT NULL,
    size_bytes            INTEGER NOT NULL,
    iv_hex                TEXT    NOT NULL,
    tags                  JSONB   NOT NULL DEFAULT '[]',
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_vault_records_owner ON vault_records(owner_key_hash);
CREATE INDEX idx_vault_records_owner_user ON vault_records(owner_user_id_hex);
CREATE INDEX idx_vault_records_created ON vault_records(created_at);

-- =====================================================
-- VAULT CIPHERTEXT (Separate for blob storage)
-- =====================================================

CREATE TABLE vault_ciphertext (
    record_id   TEXT    PRIMARY KEY REFERENCES vault_records(record_id) ON DELETE CASCADE,
    ciphertext  BYTEA   NOT NULL,  -- AES-256-GCM ciphertext
    dek_bundle  JSONB   NOT NULL   -- ECIES-wrapped DEK for owner
);

-- =====================================================
-- GRANTS (Share permissions - Enhanced for MedLedger)
-- =====================================================

CREATE TABLE grants (
    grant_id               TEXT    PRIMARY KEY,
    record_id              TEXT    NOT NULL REFERENCES vault_records(record_id) ON DELETE CASCADE,
    grantor_key_hash       TEXT    NOT NULL,
    grantee_key_hash       TEXT    NOT NULL,
    grantee_user_id_hex    VARCHAR(32) REFERENCES users(user_id_hex),
    grantee_public_key_hex TEXT    NOT NULL,
    permission_level       TEXT    NOT NULL CHECK (permission_level IN ('view_only', 'view_download')),
    time_start             TIMESTAMP WITH TIME ZONE NOT NULL,
    time_end               TIMESTAMP WITH TIME ZONE NOT NULL,
    dek_bundle_grantee     JSONB   NOT NULL,  -- ECIES-wrapped DEK for grantee
    signature_hex          TEXT    NOT NULL,  -- Ed25519 signature by grantor
    revoked                BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at             TIMESTAMP WITH TIME ZONE,
    created_at             TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    retrieved_at           TIMESTAMP WITH TIME ZONE,

    CONSTRAINT chk_grant_time CHECK (time_end > time_start)
);

CREATE INDEX idx_grants_grantor ON grants(grantor_key_hash);
CREATE INDEX idx_grants_grantee ON grants(grantee_key_hash);
CREATE INDEX idx_grants_record ON grants(record_id);
CREATE INDEX idx_grants_grantee_user ON grants(grantee_user_id_hex);
CREATE INDEX idx_grants_time_range ON grants(time_start, time_end);

-- =====================================================
-- ACTIVE SHARES (New MedLedger share system)
-- =====================================================

CREATE TABLE active_shares (
    -- Primary identifiers
    id                      SERIAL PRIMARY KEY,
    share_id                UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    short_code              VARCHAR(16) UNIQUE,

    -- Participants
    owner_user_id_hex       VARCHAR(32) NOT NULL REFERENCES users(user_id_hex),
    grantee_user_id_hex     VARCHAR(32) NOT NULL REFERENCES users(user_id_hex),

    -- Encrypted data (server never sees plaintext)
    ciphertext              BYTEA NOT NULL,  -- XSalsa20 encrypted file
    dek_bundle              TEXT NOT NULL,   -- Sealed box containing DEK, base64url
    nonce                   VARCHAR(32) NOT NULL,  -- XSalsa20 nonce, base64url

    -- File metadata
    filename                VARCHAR(255) NOT NULL,
    mime_type               VARCHAR(100),
    size_bytes              INTEGER NOT NULL,
    file_hash               VARCHAR(64),  -- BLAKE2b-256 hex

    -- Share metadata
    signature               TEXT NOT NULL,  -- Ed25519 signature, base64url
    payload_canon           TEXT,           -- Canonical JSON of signed payload

    -- Lifecycle
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at              TIMESTAMP WITH TIME ZONE NOT NULL,
    retrieved_at            TIMESTAMP WITH TIME ZONE,
    delete_on_download      BOOLEAN DEFAULT TRUE,

    -- Status
    status                  share_status DEFAULT 'active',

    -- Indexes
    CONSTRAINT chk_share_expires CHECK (expires_at > created_at),
    CONSTRAINT chk_share_ttl CHECK (EXTRACT(DAY FROM (expires_at - created_at)) <= 90)
);

CREATE INDEX idx_shares_owner ON active_shares(owner_user_id_hex, created_at DESC);
CREATE INDEX idx_shares_grantee ON active_shares(grantee_user_id_hex, status, created_at DESC);
CREATE INDEX idx_shares_share_id ON active_shares(share_id);
CREATE INDEX idx_shares_short_code ON active_shares(short_code);
CREATE INDEX idx_shares_expires_at ON active_shares(expires_at);
CREATE INDEX idx_shares_status ON active_shares(status);
CREATE INDEX idx_shares_owner_status ON active_shares(owner_user_id_hex, status, created_at);

-- =====================================================
-- SHARE ACCESS LOG
-- =====================================================

CREATE TABLE share_access_log (
    id                      SERIAL PRIMARY KEY,
    share_id                UUID NOT NULL REFERENCES active_shares(share_id) ON DELETE CASCADE,
    grantee_user_id_hex     VARCHAR(32) NOT NULL,
    access_ip               INET NOT NULL,
    user_agent              TEXT,
    accessed_at             TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_share_access_share ON share_access_log(share_id);
CREATE INDEX idx_share_access_grantee ON share_access_log(grantee_user_id_hex);
CREATE INDEX idx_share_access_accessed ON share_access_log(accessed_at);

-- =====================================================
-- VAULT AUDIT (Enhanced)
-- =====================================================

CREATE TABLE vault_audit (
    id                  SERIAL PRIMARY KEY,
    action              TEXT NOT NULL,
    actor_key_hash      TEXT NOT NULL DEFAULT '',
    actor_user_id_hex   VARCHAR(32) REFERENCES users(user_id_hex),
    record_id           TEXT NOT NULL DEFAULT '',
    share_id            UUID REFERENCES active_shares(share_id),
    detail              TEXT NOT NULL DEFAULT '',
    ip_address          INET,
    user_agent          TEXT,
    timestamp           TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vault_audit_actor ON vault_audit(actor_key_hash);
CREATE INDEX idx_vault_audit_record ON vault_audit(record_id);
CREATE INDEX idx_vault_audit_timestamp ON vault_audit(timestamp);

-- =====================================================
-- AUDIT LOG (Append-only, compliance)
-- =====================================================

CREATE TABLE audit_log (
    id                  SERIAL PRIMARY KEY,
    event_id            UUID DEFAULT gen_random_uuid() UNIQUE NOT NULL,
    actor_user_id_hex   VARCHAR(32) REFERENCES users(user_id_hex),
    action              audit_action NOT NULL,
    share_id            UUID REFERENCES active_shares(share_id),
    detail              JSONB,  -- No PHI, no plaintext
    ip_address          INET NOT NULL,
    user_agent          TEXT,
    timestamp           TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_actor ON audit_log(actor_user_id_hex, timestamp DESC);
CREATE INDEX idx_audit_action ON audit_log(action, timestamp DESC);
CREATE INDEX idx_audit_share ON audit_log(share_id);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_actor_action ON audit_log(actor_user_id_hex, action, timestamp);

-- =====================================================
-- RATE LIMITING
-- =====================================================

CREATE TABLE rate_limit (
    id                  SERIAL PRIMARY KEY,
    key_hash            VARCHAR(64) NOT NULL,  -- SHA-256 of email or IP
    action              VARCHAR(50) NOT NULL,
    attempts            INTEGER DEFAULT 1,
    first_attempt       TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_attempt        TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    blocked_until       TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_rate_limit_key ON rate_limit(key_hash, action);
CREATE INDEX idx_rate_limit_blocked ON rate_limit(blocked_until);

-- =====================================================
-- TOKEN REVOCATIONS (JWT logout)
-- =====================================================

CREATE TABLE token_revocations (
    id                  SERIAL PRIMARY KEY,
    token_jti           VARCHAR(128) UNIQUE NOT NULL,
    user_id_hex         VARCHAR(32) NOT NULL REFERENCES users(user_id_hex),
    revoked_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_token_revocations_user ON token_revocations(user_id_hex);
CREATE INDEX idx_token_revocations_expires ON token_revocations(expires_at);

-- =====================================================
-- REFRESH TOKENS
-- =====================================================

CREATE TABLE refresh_tokens (
    id                      SERIAL PRIMARY KEY,
    token_hash              VARCHAR(128) UNIQUE NOT NULL,
    user_id_hex             VARCHAR(32) NOT NULL REFERENCES users(user_id_hex),
    family_id               VARCHAR(64) NOT NULL,
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at              TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at              TIMESTAMP WITH TIME ZONE,
    replaced_by_token_hash  VARCHAR(128)
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id_hex);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- =====================================================
-- POW CHALLENGES (Anti-spam)
-- =====================================================

CREATE TABLE pow_challenges (
    id                  SERIAL PRIMARY KEY,
    challenge_id        VARCHAR(64) UNIQUE NOT NULL,
    nonce_prefix        VARCHAR(16) NOT NULL,
    difficulty          INTEGER DEFAULT 20,
    target_hash         VARCHAR(64) NOT NULL,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '5 minutes'),
    solved_at           TIMESTAMP WITH TIME ZONE,
    solved_nonce        VARCHAR(32),
    solver_ip           INET
);

CREATE INDEX idx_pow_challenge_id ON pow_challenges(challenge_id);
CREATE INDEX idx_pow_expires ON pow_challenges(expires_at);

-- =====================================================
-- FUNCTIONS
-- =====================================================

-- Function to automatically expire shares
CREATE OR REPLACE FUNCTION expire_old_shares()
RETURNS void AS $$
BEGIN
    UPDATE active_shares
    SET status = 'expired'
    WHERE status = 'active'
      AND expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Function to generate short code for share
CREATE OR REPLACE FUNCTION generate_short_code()
RETURNS TRIGGER AS $$
DECLARE
    chars text := '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    result text := '';
    i integer := 0;
    random_bytes bytea;
BEGIN
    random_bytes := gen_random_bytes(8);
    FOR i IN 0..7 LOOP
        result := result || substr(chars, (get_byte(random_bytes, i) % 62) + 1, 1);
    END LOOP;
    NEW.short_code := result;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to generate user_id_hex from signing public key
CREATE OR REPLACE FUNCTION generate_user_id_hex()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.signing_public_key IS NOT NULL AND NEW.user_id_hex IS NULL THEN
        NEW.user_id_hex := encode(
            sha256(decode(NEW.signing_public_key, 'base64')::bytea),
            'hex'
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to log share access automatically
CREATE OR REPLACE FUNCTION log_share_access()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO share_access_log (share_id, grantee_user_id_hex, access_ip, user_agent)
    VALUES (
        NEW.share_id,
        NEW.grantee_user_id_hex,
        current_setting('medledger.client_ip', true)::INET,
        current_setting('medledger.user_agent', true)
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old data
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS void AS $$
BEGIN
    -- Expire old shares
    PERFORM expire_old_shares();

    -- Delete old audit logs (after 7 years)
    DELETE FROM audit_log
    WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '7 years';

    -- Delete old rate limit entries
    DELETE FROM rate_limit
    WHERE last_attempt < CURRENT_TIMESTAMP - INTERVAL '24 hours';

    -- Delete expired token revocations
    DELETE FROM token_revocations
    WHERE expires_at < CURRENT_TIMESTAMP;

    -- Delete expired refresh tokens
    DELETE FROM refresh_tokens
    WHERE expires_at < CURRENT_TIMESTAMP OR revoked_at IS NOT NULL;

    -- Delete expired PoW challenges
    DELETE FROM pow_challenges
    WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- TRIGGERS
-- =====================================================

-- Auto-generate short_code for new shares
CREATE TRIGGER trigger_generate_short_code
    BEFORE INSERT ON active_shares
    FOR EACH ROW
    WHEN (NEW.short_code IS NULL)
    EXECUTE FUNCTION generate_short_code();

-- Auto-generate user_id_hex
CREATE TRIGGER trigger_generate_user_id_hex
    BEFORE INSERT OR UPDATE OF signing_public_key ON users
    FOR EACH ROW
    EXECUTE FUNCTION generate_user_id_hex();

-- Auto-log share access
CREATE TRIGGER trigger_log_share_access
    AFTER UPDATE OF retrieved_at ON active_shares
    FOR EACH ROW
    WHEN (NEW.retrieved_at IS NOT NULL AND OLD.retrieved_at IS NULL)
    EXECUTE FUNCTION log_share_access();

-- =====================================================
-- VIEWS
-- =====================================================

-- Active shares view (excludes expired/revoked)
CREATE OR REPLACE VIEW v_active_shares AS
SELECT
    s.share_id,
    s.short_code,
    u1.username as owner_username,
    u2.username as grantee_username,
    s.filename,
    s.mime_type,
    s.size_bytes,
    s.created_at,
    s.expires_at,
    s.delete_on_download,
    s.status
FROM active_shares s
JOIN users u1 ON s.owner_user_id_hex = u1.user_id_hex
JOIN users u2 ON s.grantee_user_id_hex = u2.user_id_hex
WHERE s.status = 'active';

-- User share statistics
CREATE OR REPLACE VIEW v_user_share_stats AS
SELECT
    u.user_id_hex,
    u.username,
    COUNT(DISTINCT s_owned.share_id) as shares_created,
    COUNT(DISTINCT s_received.share_id) as shares_received,
    COALESCE(SUM(s_owned.size_bytes), 0) as total_bytes_shared,
    MAX(s_owned.created_at) as last_share_created
FROM users u
LEFT JOIN active_shares s_owned ON u.user_id_hex = s_owned.owner_user_id_hex AND s_owned.status = 'active'
LEFT JOIN active_shares s_received ON u.user_id_hex = s_received.grantee_user_id_hex AND s_received.status = 'active'
WHERE u.account_deleted = FALSE
GROUP BY u.user_id_hex, u.username;

-- Vault statistics
CREATE OR REPLACE VIEW v_vault_stats AS
SELECT
    u.username,
    u.user_id_hex,
    COUNT(v.record_id) as total_files,
    COALESCE(SUM(v.size_bytes), 0) as total_bytes,
    COUNT(DISTINCT g.grant_id) as total_grants_given,
    MAX(v.created_at) as last_upload
FROM users u
LEFT JOIN vault_records v ON u.user_id_hex = v.owner_user_id_hex
LEFT JOIN grants g ON v.record_id = g.record_id AND g.revoked = FALSE
WHERE u.account_deleted = FALSE
GROUP BY u.user_id_hex, u.username;

-- =====================================================
-- INITIAL DATA (Optional - for testing)
-- =====================================================

-- Insert a test user (password: test123)
-- Password hash is Argon2id, generated with:
-- password: test123
-- WARNING: Change this in production!
INSERT INTO users (
    username,
    email,
    full_name,
    role,
    password_hash,
    server_salt,
    is_verified,
    is_active,
    created_at
) VALUES (
    'testuser',
    'test@example.com',
    'Test User',
    'PATIENT',
    '$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$GqBxJzR7YqXxL8vN2wP5mK9tF4sD1hU3jL6kM8nB0vC',
    encode(gen_random_bytes(32), 'hex'),
    TRUE,
    TRUE,
    CURRENT_TIMESTAMP
) ON CONFLICT (username) DO NOTHING;

-- =====================================================
-- COMMENTS
-- =====================================================

COMMENT ON DATABASE medledger_db IS 'MedLedger Zero-Knowledge Secure File Sharing Database';
COMMENT ON TABLE users IS 'User accounts with public keys only - no private keys stored server-side';
COMMENT ON TABLE active_shares IS 'Encrypted shares - server cannot decrypt without user keys (zero-knowledge)';
COMMENT ON TABLE vault_records IS 'File metadata only - no ciphertext for fast listing';
COMMENT ON TABLE vault_ciphertext IS 'Separate table for encrypted blob storage';
COMMENT ON TABLE audit_log IS 'Append-only audit trail for compliance (7-year retention)';
COMMENT ON TABLE grants IS 'Share permissions with time-bound access control';
COMMENT ON COLUMN users.server_salt IS 'Per-user entropy for deterministic key derivation (not secret)';
COMMENT ON COLUMN active_shares.dek_bundle IS 'Sealed box containing DEK, encrypted to recipient''s public key';
COMMENT ON COLUMN active_shares.signature IS 'Ed25519 signature of grant metadata by owner';
COMMENT ON COLUMN active_shares.ciphertext IS 'XSalsa20-Poly1305 encrypted file (zero-knowledge)';

-- =====================================================
-- MAINTENANCE
-- =====================================================

-- Create a scheduled job to clean up old data (if pg_cron is available)
-- CREATE EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule('cleanup-old-data', '0 * * * *', 'SELECT cleanup_old_data();');

-- Manual cleanup command:
-- SELECT cleanup_old_data();
