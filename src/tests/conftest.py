"""
tests/conftest.py — Shared fixtures for the full test suite.

Provides:
  • SQLite in-memory engine + session (for database/ integration tests)
  • Mock DatabaseRepository (for service unit tests)
  • Mock AuditService
  • Token module fixture
"""
from __future__ import annotations

import os
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# Force test mode for password iterations
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("TESTING", "true")

# ─────────────────────────────────────────────
# SQLite DDL — mirrors the production schema
# (PostgreSQL-specific types replaced for SQLite compat)
# ─────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id_hex         TEXT    NOT NULL UNIQUE DEFAULT (lower(hex(randomblob(16)))),
    username            TEXT    NOT NULL UNIQUE,
    email               TEXT    NOT NULL UNIQUE,
    full_name           TEXT    NOT NULL DEFAULT '',
    role                TEXT    NOT NULL DEFAULT 'PATIENT',
    password_hash       TEXT,
    signing_public_key  TEXT,
    exchange_public_key TEXT,
    email_verified      INTEGER NOT NULL DEFAULT 0,
    is_verified         INTEGER NOT NULL DEFAULT 0,
    totp_enabled        INTEGER NOT NULL DEFAULT 0,
    totp_secret         TEXT,
    account_deleted     INTEGER NOT NULL DEFAULT 0,
    deleted_at          TEXT,
    is_active           INTEGER NOT NULL DEFAULT 1,
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,
    verification_token  TEXT,
    token_expires_at    TEXT,
    last_login_at       TEXT,
    pwhash_salt         TEXT,
    server_salt         TEXT,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT,
    action      TEXT NOT NULL,
    description TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pow_challenges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT    NOT NULL UNIQUE,
    nonce_prefix TEXT    NOT NULL,
    difficulty   INTEGER NOT NULL,
    target_hash  TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    solved_at    TEXT,
    solved_nonce TEXT,
    solver_ip    TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash            TEXT    NOT NULL UNIQUE,
    user_id_hex           TEXT    NOT NULL,
    family_id             TEXT    NOT NULL,
    expires_at            TEXT    NOT NULL,
    revoked               INTEGER NOT NULL DEFAULT 0,
    revoked_at            TEXT,
    replaced_by_token_hash TEXT,
    created_at            TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS token_revocations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_jti   TEXT    NOT NULL UNIQUE,
    user_id_hex TEXT,
    expires_at  TEXT    NOT NULL,
    revoked_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS rate_limit (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash       TEXT    NOT NULL,
    action         TEXT    NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    first_attempt  TEXT,
    last_attempt   TEXT,
    blocked_until  TEXT,
    UNIQUE(key_hash, action)
);

CREATE TABLE IF NOT EXISTS active_shares (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id            TEXT    NOT NULL UNIQUE DEFAULT (lower(hex(randomblob(16)))),
    short_code          TEXT    UNIQUE DEFAULT (upper(hex(randomblob(4)))),
    owner_user_id_hex   TEXT    NOT NULL,
    grantee_user_id_hex TEXT,
    ciphertext          BLOB,
    dek_bundle          TEXT,
    nonce               TEXT,
    filename            TEXT,
    mime_type           TEXT,
    size_bytes          INTEGER,
    file_hash           TEXT,
    signature           TEXT,
    payload_canon       TEXT,
    status              TEXT    NOT NULL DEFAULT 'pending',
    expires_at          TEXT    NOT NULL,
    delete_on_download  INTEGER NOT NULL DEFAULT 1,
    retrieved_at        TEXT,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS share_access_log (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id             TEXT,
    grantee_user_id_hex  TEXT,
    access_ip            TEXT,
    user_agent           TEXT,
    accessed_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vault_records (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id            TEXT    NOT NULL UNIQUE,
    owner_key_hash       TEXT    NOT NULL,
    owner_user_id_hex    TEXT    NOT NULL,
    owner_public_key_hex TEXT    NOT NULL,
    filename             TEXT    NOT NULL,
    mime_type            TEXT    NOT NULL,
    size_bytes           INTEGER NOT NULL,
    iv_hex               TEXT    NOT NULL,
    tags                 TEXT    NOT NULL DEFAULT '[]',
    created_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vault_ciphertext (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id   TEXT    NOT NULL UNIQUE,
    ciphertext  BLOB    NOT NULL,
    dek_bundle  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS grants (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id               TEXT    NOT NULL UNIQUE,
    record_id              TEXT    NOT NULL,
    grantor_key_hash       TEXT    NOT NULL,
    grantee_key_hash       TEXT    NOT NULL,
    grantee_user_id_hex    TEXT,
    grantee_public_key_hex TEXT    NOT NULL,
    permission_level       TEXT    NOT NULL DEFAULT 'view_only',
    time_start             TEXT    NOT NULL,
    time_end               TEXT    NOT NULL,
    dek_bundle_grantee     TEXT    NOT NULL,
    signature_hex          TEXT    NOT NULL,
    revoked                INTEGER NOT NULL DEFAULT 0,
    revoked_at             TEXT,
    retrieved_at           TEXT,
    created_at             TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id_hex TEXT,
    action            TEXT NOT NULL,
    share_id          TEXT,
    detail            TEXT,
    ip_address        TEXT,
    user_agent        TEXT,
    timestamp         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vault_audit (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    action            TEXT NOT NULL,
    actor_key_hash    TEXT NOT NULL DEFAULT '',
    actor_user_id_hex TEXT,
    record_id         TEXT NOT NULL DEFAULT '',
    share_id          TEXT,
    detail            TEXT NOT NULL DEFAULT '',
    ip_address        TEXT,
    user_agent        TEXT,
    timestamp         TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


# ─────────────────────────────────────────────
# Database fixtures
# ─────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default asyncio event loop policy."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture(scope="session")
async def db_engine():
    """Session-scoped in-memory SQLite engine with schema applied."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        # Create all tables
        for statement in SCHEMA_SQL.strip().split(";"):
            s = statement.strip()
            if s:
                await conn.execute(__import__("sqlalchemy").text(s))
    yield engine
    await engine.dispose()


class _SQLiteCompatSession:
    """
    Wraps AsyncSession to auto-serialize dict/list params before hitting SQLite.
    PostgreSQL uses JSONB natively; SQLite needs JSON strings.
    """
    def __init__(self, session: AsyncSession):
        self._session = session

    def _coerce_params(self, params):
        if not isinstance(params, dict):
            return params
        import json as _json
        result = {}
        for k, v in params.items():
            if isinstance(v, (dict, list)):
                result[k] = _json.dumps(v)
            else:
                result[k] = v
        return result

    async def execute(self, stmt, params=None, **kwargs):
        coerced = self._coerce_params(params) if params else params
        return await self._session.execute(stmt, coerced, **kwargs)

    async def commit(self):
        return await self._session.commit()

    async def rollback(self):
        return await self._session.rollback()

    async def close(self):
        return await self._session.close()

    def __getattr__(self, name):
        return getattr(self._session, name)


@pytest.fixture
async def db_session(db_engine):
    """
    Fresh AsyncSession per test with SQLite JSON-serialization shim.
    Each test rolls back after completion.
    """
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield _SQLiteCompatSession(session)
        await session.rollback()


# ─────────────────────────────────────────────
# Mock fixtures for service unit tests
# ─────────────────────────────────────────────

@pytest.fixture
def mock_db_repo():
    """AsyncMock of DatabaseRepository for service unit tests."""
    return AsyncMock()


@pytest.fixture
def mock_audit_service():
    """AsyncMock of AuditService — all log_* methods pre-mocked."""
    audit = AsyncMock()
    audit.log_auth_event = AsyncMock()
    audit.log_key_event = AsyncMock()
    audit.log_vault_event = AsyncMock()
    audit.log_share_event = AsyncMock()
    audit.log_grant_event = AsyncMock()
    audit.log_relay_event = AsyncMock()
    return audit


@pytest.fixture
def token_module():
    """Real TokenModule with a test secret."""
    from services.token import TokenModule
    return TokenModule(secret="test-secret-key-32-bytes-minimum!!", expiry_seconds=3600)


@pytest.fixture
def mock_email_module():
    m = MagicMock()
    m.validate_email.return_value = MagicMock(valid=True, email="user@example.com")
    m.validate_and_send_code.return_value = MagicMock(
        success=True, email="user@example.com", code="123456"
    )
    return m


@pytest.fixture
def mock_totp_module():
    m = MagicMock()
    m.generate_secret.return_value = MagicMock(
        secret="JBSWY3DPEHPK3PXP",
        uri="otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test",
        issuer="Test",
        email="user@example.com",
    )
    m.verify_code.return_value = True
    m.generate_backup_codes.return_value = ["ABCD-1234", "EFGH-5678"]
    m.current_token.return_value = "123456"
    return m


@pytest.fixture
def mock_password_module():
    m = MagicMock()
    m.validate_strength.return_value = MagicMock(valid=True, score=5, issues=[])
    m.hash_password.return_value = MagicMock(
        hash_hex="a" * 128,
        salt_hex="b" * 32,
        iterations=1000,
    )
    m.verify_password.return_value = True
    return m


@pytest.fixture
def mock_pow_module():
    m = MagicMock()
    m.new_challenge.return_value = MagicMock(
        challenge_id="abc123",
        challenge="random_nonce",
        difficulty=4,
        timestamp=1000.0,
        to_dict=lambda: {
            "challenge_id": "abc123",
            "challenge": "random_nonce",
            "difficulty": 4,
            "timestamp": 1000.0,
        }
    )
    m.verify_solution.return_value = MagicMock(success=True)
    m.is_expired.return_value = False
    m.expiry_seconds = 300
    return m


@pytest.fixture
def mock_config():
    cfg = MagicMock()
    cfg.gmail_user = "noreply@test.com"
    cfg.gmail_app_password = "test-password"
    cfg.jwt_secret = "test-secret"
    cfg.jwt_expiry_seconds = 3600
    cfg.refresh_expiry_days = 30
    cfg.max_login_attempts = 5
    cfg.login_lockout_minutes = 15
    cfg.max_verification_attempts = 3
    cfg.verification_expiry_minutes = 10
    return cfg


@pytest.fixture
def auth_service_deps(
    mock_db_repo, mock_email_module, mock_totp_module,
    mock_password_module, token_module, mock_pow_module,
    mock_audit_service, mock_config
):
    """All dependencies for AuthService in one dict."""
    return {
        "db_repo":         mock_db_repo,
        "email_module":    mock_email_module,
        "totp_module":     mock_totp_module,
        "password_module": mock_password_module,
        "token_module":    token_module,
        "pow_module":      mock_pow_module,
        "audit_service":   mock_audit_service,
        "config":          mock_config,
    }
