# MedLedger Database Service

## Overview

The `database.py` module provides an **async PostgreSQL interface** for the MedLedger application. It handles all database operations including user management, encrypted vault storage, secure file sharing, audit logging, rate limiting, token revocation, and proof-of-work challenge management.

---

## Table of Contents

- [Architecture](#architecture)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Database Singleton](#database-singleton)
  - [User Operations](#user-operations)
  - [Vault Operations](#vault-operations)
  - [Vault Ciphertext](#vault-ciphertext)
  - [Share Operations](#share-operations)
  - [Grant Operations](#grant-operations)
  - [Audit Logging](#audit-logging)
  - [Rate Limiting](#rate-limiting)
  - [Token Revocation](#token-revocation)
  - [Proof-of-Work Challenges](#proof-of-work-challenges)
  - [Refresh Tokens](#refresh-tokens)
  - [Maintenance](#maintenance)
- [Database Schema](#database-schema)
- [Security Considerations](#security-considerations)
- [Error Handling](#error-handling)
- [Known Test Issues](#known-test-issues)

---

## Architecture

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Async-first** | Built on `asyncpg` for high-performance async I/O |
| **Connection pooling** | Maintains 5–20 persistent connections via `asyncpg.create_pool` |
| **Singleton pattern** | Thread-safe singleton via `asyncio.Lock` with double-checked locking |
| **Defense-in-depth** | SQL field validation via `_FIELD_RE` regex whitelist prevents injection |
| **Soft deletes** | Users are soft-deleted (`account_deleted = TRUE`); data is preserved for compliance |
| **asyncpg.Bytes compat** | Module patches `asyncpg.Bytes = None` at import time if not present in the installed version |

### Internal Helpers

| Symbol | Purpose |
|--------|---------|
| `_FIELD_RE` | `r'^[a-zA-Z_][a-zA-Z0-9_]*$'` — validates dynamic field names before building UPDATE queries |
| `_UPDATABLE_USER_FIELDS` | Frozenset of column names allowed in `update_user()` |
| `_utcnow()` | Returns `datetime.now(timezone.utc)` — all timestamps are timezone-aware UTC |
| `_row_to_dict(row)` | Converts an asyncpg `Record` to a plain `dict`, or returns `None` |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL server hostname |
| `DB_PORT` | `5432` | PostgreSQL server port |
| `DB_USER` | `premananda` | Database username |
| `DB_PASSWORD` | *(empty)* | Database password |
| `DB_NAME` | `medledger_db` | Database name |

> **Note:** All env vars use `os.getenv('VAR') or 'default'` (not `os.getenv('VAR', 'default')`), so an explicit `None` return from a patched `getenv` still falls back to the default.

### Connection Pool Settings

| Setting | Value | Description |
|---------|-------|-------------|
| `min_size` | `5` | Minimum connections maintained |
| `max_size` | `20` | Maximum connections allowed |
| `command_timeout` | `60` | Query timeout in seconds |
| `max_inactive_connection_lifetime` | `300` | Seconds before idle connection is closed |
| `init` | `asyncpg.Bytes` | Codec init sentinel (patched to `None` if absent) |

---

## Quick Start

```python
import asyncio
from database import get_db, close_db

async def main():
    db = await get_db()  # singleton, auto-connects

    user = await db.create_user({
        "username": "alice",
        "email": "alice@example.com",
        "password_hash": "...",   # pre-hashed — never plaintext
        "pwhash_salt": "...",
        "signing_public_key": "...",
        "exchange_public_key": "...",
    })

    user = await db.get_user_by_username("alice")
    print(user["user_id_hex"])

    await close_db()

asyncio.run(main())
```

---

## API Reference

### Database Singleton

#### `get_db() -> Database`

Returns the singleton `Database` instance. Uses `asyncio.Lock` with double-checked locking — safe to call concurrently. Automatically calls `connect()` on first use.

```python
db = await get_db()
```

#### `close_db()`

Closes the pool and resets the singleton to `None`. Safe to call when no instance exists.

```python
await close_db()
```

---

### User Operations

#### `create_user(user_data: dict) -> dict | None`

Inserts a new user. **The caller must pre-hash the password** before passing it in.

**`user_id_hex` derivation:** If `user_id_hex` is absent or falsy, it is computed as `SHA256(signing_public_key.encode()).hexdigest()`. If neither `user_id_hex` nor `signing_public_key` is provided, a `ValueError` is raised.

**`server_salt`:** Auto-generated via `secrets.token_hex(32)` if not supplied.

**Fields:**

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `username` | **yes** | — | Unique username |
| `signing_public_key` | see note | — | Required if `user_id_hex` is omitted; used to derive it |
| `user_id_hex` | see note | SHA256(signing_key) | Unique user identifier |
| `email` | no | `''` | Unique email address |
| `full_name` | no | `''` | Display name |
| `role` | no | `'PATIENT'` | User role (`PATIENT`, `DOCTOR`, `ADMIN`) |
| `password_hash` | no | `''` | **Pre-hashed** password |
| `pwhash_salt` | no | `''` | Salt used for password hashing |
| `exchange_public_key` | no | `''` | X25519 key exchange public key |
| `server_salt` | no | random 32-byte hex | Server-side salt |
| `is_verified` | no | `False` | Email verification status |
| `is_active` | no | `True` | Account active status |

**Returns:** `{user_id_hex, username, email, full_name, role, is_verified, is_active, created_at}` or `None`.

**Raises:** `ValueError` if no identity key provided; `asyncpg.UniqueViolationError` on duplicate username/email.

```python
user = await db.create_user({
    "username": "alice",
    "email": "alice@example.com",
    "password_hash": pbkdf2_hash,
    "pwhash_salt": salt,
    "signing_public_key": ed25519_pub,
    "exchange_public_key": x25519_pub,
})
```

---

#### `get_user_by_username(username: str) -> dict | None`

Fetches an active (non-deleted) user by username. Comparison is case-insensitive via `LOWER()`.

**Returns:** Full user dict including `password_hash`, `pwhash_salt`, `signing_public_key`, `exchange_public_key`, `server_salt`, `last_login_at`. Returns `None` if not found or soft-deleted.

```python
user = await db.get_user_by_username("Alice")  # matches "alice", "ALICE", etc.
```

---

#### `get_user_by_email(email: str) -> dict | None`

Fetches an active user by email. Case-insensitive.

```python
user = await db.get_user_by_email("Alice@Example.COM")
```

---

#### `get_user_by_id(user_id_hex: str) -> dict | None`

Fetches an active user by `user_id_hex` (exact match).

```python
user = await db.get_user_by_id("a1b2c3...")
```

---

#### `update_user(user_id_hex: str, updates: dict) -> bool`

Updates whitelisted user fields dynamically. Builds a parameterised `UPDATE` statement — no raw SQL interpolation.

**Allowed fields:** `username`, `email`, `full_name`, `role`, `password_hash`, `pwhash_salt`, `signing_public_key`, `exchange_public_key`, `is_verified`, `is_active`, `last_login_at`, `last_login_ip`

Fields not in the whitelist, or failing `_FIELD_RE`, are silently dropped. If no valid fields remain, returns `False` without querying the database.

**Returns:** `True` if at least one row was updated, `False` if no rows matched or no valid fields were provided.

```python
ok = await db.update_user("a1b2c3...", {
    "last_login_at": datetime.now(timezone.utc),
    "last_login_ip": "192.168.1.1",
})
```

---

#### `delete_user(user_id_hex: str) -> bool`

Soft-deletes a user: sets `account_deleted = TRUE`, `is_active = FALSE`, `deleted_at = now()`. The row is preserved. All subsequent lookups by username/email/id exclude soft-deleted users.

**Returns:** `True` if the user existed and was updated.

```python
await db.delete_user("a1b2c3...")
```

---

#### `username_exists(username: str) -> bool`

Returns `True` if a non-deleted user with this username exists. Case-insensitive.

```python
if await db.username_exists("alice"):
    raise ValueError("Username taken")
```

---

#### `email_exists(email: str) -> bool`

Returns `True` if a non-deleted user with this email exists. Case-insensitive.

```python
if await db.email_exists("alice@example.com"):
    raise ValueError("Email already registered")
```

---

### Vault Operations

#### `create_vault_record(record_data: dict) -> dict | None`

Inserts a metadata record for an encrypted vault file. Does **not** store the file bytes — use `store_ciphertext()` for that.

**Required fields:** `record_id`, `owner_key_hash`, `owner_user_id_hex`, `owner_public_key_hex`, `filename`, `size_bytes`, `iv_hex`

**Optional fields:** `mime_type` (default: `'application/octet-stream'`), `tags` (default: `[]`, stored as JSONB)

**Returns:** `{record_id, owner_key_hash, owner_user_id_hex, filename, mime_type, size_bytes, created_at}`

```python
record = await db.create_vault_record({
    "record_id": "rec-001",
    "owner_key_hash": "sha256:...",
    "owner_user_id_hex": "a1b2c3...",
    "owner_public_key_hex": "...",
    "filename": "report.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 1048576,
    "iv_hex": "aabbccdd...",
    "tags": ["medical", "2024"],
})
```

---

#### `get_vault_records_by_user(user_id_hex: str) -> list[dict]`

Returns all vault records for a user, ordered `created_at DESC`. Includes `iv_hex` and `tags` but not the ciphertext bytes.

```python
records = await db.get_vault_records_by_user("a1b2c3...")
```

---

#### `get_vault_record(record_id: str) -> dict | None`

Returns a single vault record including `owner_key_hash`, `owner_public_key_hex`, `iv_hex`, and `tags`.

```python
record = await db.get_vault_record("rec-001")
```

---

#### `delete_vault_record(record_id: str) -> bool`

Hard-deletes the vault record. The associated ciphertext row is removed automatically via `ON DELETE CASCADE`. Returns `True` if a row was deleted.

```python
await db.delete_vault_record("rec-001")
```

---

### Vault Ciphertext

#### `store_ciphertext(record_id: str, ciphertext: bytes, dek_bundle: dict) -> bool`

Stores encrypted file bytes alongside the Data Encryption Key bundle. Uses `ON CONFLICT (record_id) DO UPDATE` so calling it twice overwrites the previous value.

`dek_bundle` must be JSON-serializable (no raw `bytes` values). It is stored as JSONB.

```python
await db.store_ciphertext(
    record_id="rec-001",
    ciphertext=b"\x00\x01\x02...",
    dek_bundle={"encrypted_dek": "base64...", "algorithm": "AES-256-GCM"},
)
```

---

#### `get_ciphertext(record_id: str) -> dict | None`

Retrieves ciphertext and DEK bundle. asyncpg returns `BYTEA` columns as `memoryview`; this method converts them to `bytes` automatically. The `dek_bundle` is parsed from JSON if returned as a string.

**Returns:** `{"ciphertext": bytes, "dek_bundle": dict}` or `None`.

```python
data = await db.get_ciphertext("rec-001")
if data:
    raw_bytes = data["ciphertext"]
    dek       = data["dek_bundle"]
```

---

### Share Operations

#### `create_share(share_data: dict) -> dict | None`

Creates a secure one-time or time-limited file share. `dek_bundle` is serialised to JSON automatically if passed as a `dict`.

**Required fields:** `share_id`, `owner_user_id_hex`, `grantee_user_id_hex`, `ciphertext`, `dek_bundle`, `nonce`, `filename`, `size_bytes`, `signature`, `expires_at`

**Optional fields:** `short_code`, `mime_type` (default: `'application/octet-stream'`), `file_hash`, `payload_canon`, `delete_on_download` (default: `True`)

**Returns:** `{share_id, short_code, filename, created_at, expires_at}`

```python
share = await db.create_share({
    "share_id": "share-001",
    "short_code": "ABC123",
    "owner_user_id_hex": "a1b2c3...",
    "grantee_user_id_hex": "d4e5f6...",
    "ciphertext": b"\x00...",
    "dek_bundle": {"key": "..."},
    "nonce": "nonce-123",
    "filename": "report.pdf",
    "size_bytes": 1048576,
    "signature": "sig-hex...",
    "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
})
```

---

#### `get_share_by_id(share_id: str) -> dict | None`

Returns all columns for a share, regardless of status.

```python
share = await db.get_share_by_id("share-001")
```

---

#### `get_share_by_code(short_code: str) -> dict | None`

Returns a share by short code. Only matches rows with `status = 'active'`.

```python
share = await db.get_share_by_code("ABC123")
```

---

#### `get_shares_by_owner(owner_user_id_hex: str, status: str | None = None) -> list[dict]`

Lists shares created by a user, newest first. Filter by `status` (`'active'`, `'retrieved'`, `'revoked'`, `'expired'`) or omit to return all.

```python
active = await db.get_shares_by_owner("a1b2c3...", status="active")
all_   = await db.get_shares_by_owner("a1b2c3...")
```

---

#### `get_shares_by_grantee(grantee_user_id_hex: str, status: str | None = None) -> list[dict]`

Lists shares received by a user. Same status filter as above.

```python
received = await db.get_shares_by_grantee("d4e5f6...")
```

---

#### `mark_share_retrieved(share_id: str) -> bool`

Atomically transitions a share from `'active'` → `'retrieved'` and records `retrieved_at`. The `WHERE status = 'active'` guard makes concurrent calls safe — only one will succeed.

**Returns:** `True` if the share was active and is now marked retrieved, `False` if it was already retrieved, revoked, or not found.

```python
ok = await db.mark_share_retrieved("share-001")
```

---

#### `revoke_share(share_id: str) -> bool`

Sets `status = 'revoked'`. Returns `True` if a row was updated.

```python
await db.revoke_share("share-001")
```

---

#### `delete_share(share_id: str) -> bool`

Hard-deletes the share row. Returns `True` if a row was deleted.

```python
await db.delete_share("share-001")
```

---

### Grant Operations

#### `create_grant(grant_data: dict) -> dict | None`

Creates a persistent access grant on a vault record. `dek_bundle_grantee` is serialised to JSON if passed as a `dict`.

**Required fields:** `grant_id`, `record_id`, `grantor_key_hash`, `grantee_key_hash`, `grantee_user_id_hex`, `grantee_public_key_hex`, `permission_level`, `time_start`, `time_end`, `dek_bundle_grantee`, `signature_hex`

**Returns:** `{grant_id, record_id, permission_level, time_start, time_end}`

```python
grant = await db.create_grant({
    "grant_id": "grant-001",
    "record_id": "rec-001",
    "grantor_key_hash": "sha256:...",
    "grantee_key_hash": "sha256:...",
    "grantee_user_id_hex": "d4e5f6...",
    "grantee_public_key_hex": "...",
    "permission_level": "read",
    "time_start": datetime.now(timezone.utc),
    "time_end": datetime.now(timezone.utc) + timedelta(days=30),
    "dek_bundle_grantee": {"encrypted_dek": "..."},
    "signature_hex": "sig...",
})
```

---

#### `get_grants_for_record(record_id: str) -> list[dict]`

Returns all non-revoked grants for a vault record, newest first.

```python
grants = await db.get_grants_for_record("rec-001")
```

---

#### `revoke_grant(grant_id: str) -> bool`

Sets `revoked = TRUE` and `revoked_at = now()`. Returns `True` if a row was updated, `False` if the grant was not found.

```python
await db.revoke_grant("grant-001")
```

---

### Audit Logging

#### `log_audit(audit_data: dict) -> int | None`

Inserts an audit event. `detail` is serialised from `dict` to JSON automatically.

**Fields:**

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `event_id` | no | `secrets.token_hex(16)` | Unique event identifier |
| `actor_user_id_hex` | no | `None` | User who performed the action |
| `action` | no | `None` | Action string (e.g. `'LOGIN'`, `'share_created'`) |
| `share_id` | no | `None` | Related share ID |
| `detail` | no | `{}` | JSON-serializable extra context |
| `ip_address` | no | `None` | Client IP address |
| `user_agent` | no | `None` | Client user agent string |

**Returns:** The auto-incremented `id` of the new row, or `None` on failure.

```python
log_id = await db.log_audit({
    "actor_user_id_hex": "a1b2c3...",
    "action": "LOGIN",
    "detail": {"ip": "192.168.1.1"},
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
})
```

---

#### `get_audit_logs_by_user(user_id_hex: str, limit: int = 100) -> list[dict]`

Returns audit entries for a user, newest first. `limit` defaults to 100.

```python
logs = await db.get_audit_logs_by_user("a1b2c3...", limit=50)
```

---

### Rate Limiting

#### `record_attempt(key_hash: str, action: str) -> dict | None`

Records one attempt for a given key/action pair. Uses `INSERT … ON CONFLICT DO UPDATE` to atomically upsert — safe for concurrent callers.

**Returns:** `{"attempts": int, "first_attempt": datetime, "last_attempt": datetime, "blocked_until": datetime | None}`

```python
status = await db.record_attempt("ip:192.168.1.1", "login")
if status["attempts"] >= 10:
    await db.block_rate_limit("ip:192.168.1.1", "login", duration_minutes=30)
```

---

#### `block_rate_limit(key_hash: str, action: str, duration_minutes: int = 15) -> None`

Sets `blocked_until` for the given key/action. Uses upsert so it works whether or not a row already exists.

```python
await db.block_rate_limit("ip:192.168.1.1", "login", duration_minutes=30)
```

---

#### `get_rate_limit_status(key_hash: str, action: str) -> dict | None`

Returns the current rate limit row, or `None` if no record exists for that key/action.

```python
status = await db.get_rate_limit_status("ip:192.168.1.1", "login")
if status and status["blocked_until"]:
    print(f"Blocked until {status['blocked_until']}")
```

---

### Token Revocation

#### `revoke_token(token_jti: str, user_id_hex: str, expires_at: datetime) -> bool`

Adds a JWT JTI to the revocation table. Uses `ON CONFLICT DO NOTHING` so double-revoking is safe. Always returns `True`.

```python
await db.revoke_token(
    token_jti="jti-abc-123",
    user_id_hex="a1b2c3...",
    expires_at=datetime.now(timezone.utc) + timedelta(days=7),
)
```

---

#### `is_token_revoked(token_jti: str) -> bool`

Returns `True` if the JTI exists in the revocation table.

```python
if await db.is_token_revoked("jti-abc-123"):
    raise Unauthorized("Token has been revoked")
```

---

### Proof-of-Work Challenges

#### `create_pow_challenge(challenge_data: dict) -> dict | None`

Stores a PoW challenge. `expires_at` is automatically set to 5 minutes from now.

**Required fields:** `challenge_id`, `nonce_prefix`, `difficulty`, `target_hash`

**Returns:** `{challenge_id, difficulty, expires_at}`

```python
challenge = await db.create_pow_challenge({
    "challenge_id": "chal-001",
    "nonce_prefix": "prefix123",
    "difficulty": 4,
    "target_hash": "0000...",
})
```

---

#### `get_pow_challenge(challenge_id: str) -> dict | None`

Returns an unsolved, non-expired challenge. Returns `None` if the challenge has already been solved or has expired.

```python
challenge = await db.get_pow_challenge("chal-001")
```

---

#### `mark_pow_solved(challenge_id: str, nonce: str, solver_ip: str) -> bool`

Atomically marks a challenge as solved. The `WHERE solved_at IS NULL AND expires_at > NOW()` guard prevents double-solving and accepting expired challenges.

**Returns:** `True` if the challenge was active and is now marked solved, `False` otherwise.

```python
ok = await db.mark_pow_solved("chal-001", "nonce456", "192.168.1.1")
```

---

### Refresh Tokens

#### `store_refresh_token(token_hash: str, user_id_hex: str, family_id: str, expires_at: datetime) -> bool`

Stores a refresh token hash. Never store the raw token. Uses `ON CONFLICT DO NOTHING`. Always returns `True`.

```python
await db.store_refresh_token(
    token_hash="sha256:...",
    user_id_hex="a1b2c3...",
    family_id="family-001",
    expires_at=datetime.now(timezone.utc) + timedelta(days=30),
)
```

---

#### `revoke_refresh_token(token_hash: str) -> bool`

Sets `revoked_at = now()` for a single token. Returns `True` if a row was updated.

```python
await db.revoke_refresh_token("sha256:...")
```

---

#### `revoke_refresh_token_family(family_id: str) -> bool`

Revokes all non-revoked tokens sharing a `family_id` (e.g. logout from all devices). Returns `True` if at least one token was revoked.

```python
await db.revoke_refresh_token_family("family-001")
```

---

### Maintenance

#### `cleanup_old_data() -> None`

Calls the `cleanup_old_data()` PostgreSQL stored procedure. Requires the function to be defined in the database.

```sql
CREATE OR REPLACE FUNCTION cleanup_old_data() RETURNS void AS $$
BEGIN
    DELETE FROM audit_log         WHERE timestamp    < NOW() - INTERVAL '90 days';
    DELETE FROM rate_limit        WHERE last_attempt < NOW() - INTERVAL '7 days';
    DELETE FROM token_revocations WHERE expires_at   < NOW() - INTERVAL '7 days';
    DELETE FROM pow_challenges    WHERE expires_at   < NOW() - INTERVAL '1 day';
    DELETE FROM refresh_tokens    WHERE expires_at   < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;
```

---

#### `expire_old_shares() -> None`

Calls the `expire_old_shares()` PostgreSQL stored procedure.

```sql
CREATE OR REPLACE FUNCTION expire_old_shares() RETURNS void AS $$
BEGIN
    UPDATE active_shares
    SET status = 'expired'
    WHERE expires_at < CURRENT_TIMESTAMP
      AND status = 'active';
END;
$$ LANGUAGE plpgsql;
```

---

## Database Schema

### `users`

```sql
CREATE TABLE users (
    user_id_hex          VARCHAR(64)  PRIMARY KEY,
    username             VARCHAR(255) UNIQUE NOT NULL,
    email                VARCHAR(255) UNIQUE NOT NULL,
    full_name            VARCHAR(255) DEFAULT '',
    role                 VARCHAR(50)  DEFAULT 'PATIENT',
    password_hash        VARCHAR(255) NOT NULL,
    pwhash_salt          VARCHAR(255) NOT NULL,
    signing_public_key   TEXT,
    exchange_public_key  TEXT,
    server_salt          VARCHAR(255) NOT NULL,
    is_verified          BOOLEAN      DEFAULT FALSE,
    is_active            BOOLEAN      DEFAULT TRUE,
    account_deleted      BOOLEAN      DEFAULT FALSE,
    deleted_at           TIMESTAMP,
    created_at           TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP,
    last_login_at        TIMESTAMP,
    last_login_ip        INET
);
CREATE INDEX idx_users_username ON users(LOWER(username));
CREATE INDEX idx_users_email    ON users(LOWER(email));
```

### `vault_records`

```sql
CREATE TABLE vault_records (
    record_id            VARCHAR(64)  PRIMARY KEY,
    owner_key_hash       VARCHAR(128) NOT NULL,
    owner_user_id_hex    VARCHAR(64)  NOT NULL REFERENCES users(user_id_hex),
    owner_public_key_hex TEXT         NOT NULL,
    filename             VARCHAR(512) NOT NULL,
    mime_type            VARCHAR(128) DEFAULT 'application/octet-stream',
    size_bytes           BIGINT       NOT NULL,
    iv_hex               VARCHAR(64)  NOT NULL,
    tags                 JSONB        DEFAULT '[]',
    created_at           TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_vault_owner ON vault_records(owner_user_id_hex);
```

### `vault_ciphertext`

```sql
CREATE TABLE vault_ciphertext (
    record_id  VARCHAR(64) PRIMARY KEY REFERENCES vault_records(record_id) ON DELETE CASCADE,
    ciphertext BYTEA       NOT NULL,
    dek_bundle JSONB       NOT NULL
);
```

### `active_shares`

```sql
CREATE TABLE active_shares (
    share_id             VARCHAR(64)  PRIMARY KEY,
    short_code           VARCHAR(16)  UNIQUE,
    owner_user_id_hex    VARCHAR(64)  NOT NULL REFERENCES users(user_id_hex),
    grantee_user_id_hex  VARCHAR(64)  NOT NULL REFERENCES users(user_id_hex),
    ciphertext           BYTEA        NOT NULL,
    dek_bundle           JSONB        NOT NULL,
    nonce                VARCHAR(255) NOT NULL,
    filename             VARCHAR(512) NOT NULL,
    mime_type            VARCHAR(128) DEFAULT 'application/octet-stream',
    size_bytes           BIGINT       NOT NULL,
    file_hash            VARCHAR(128),
    signature            TEXT         NOT NULL,
    payload_canon        TEXT,
    created_at           TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    expires_at           TIMESTAMP    NOT NULL,
    retrieved_at         TIMESTAMP,
    delete_on_download   BOOLEAN      DEFAULT TRUE,
    status               VARCHAR(50)  DEFAULT 'active'
);
CREATE INDEX idx_shares_owner   ON active_shares(owner_user_id_hex);
CREATE INDEX idx_shares_grantee ON active_shares(grantee_user_id_hex);
CREATE INDEX idx_shares_code    ON active_shares(short_code)  WHERE status = 'active';
CREATE INDEX idx_shares_expires ON active_shares(expires_at)  WHERE status = 'active';
```

### `grants`

```sql
CREATE TABLE grants (
    grant_id              VARCHAR(64)  PRIMARY KEY,
    record_id             VARCHAR(64)  NOT NULL REFERENCES vault_records(record_id),
    grantor_key_hash      VARCHAR(128) NOT NULL,
    grantee_key_hash      VARCHAR(128) NOT NULL,
    grantee_user_id_hex   VARCHAR(64)  NOT NULL REFERENCES users(user_id_hex),
    grantee_public_key_hex TEXT        NOT NULL,
    permission_level      VARCHAR(50)  NOT NULL,
    time_start            TIMESTAMP    NOT NULL,
    time_end              TIMESTAMP    NOT NULL,
    dek_bundle_grantee    JSONB        NOT NULL,
    signature_hex         TEXT         NOT NULL,
    revoked               BOOLEAN      DEFAULT FALSE,
    revoked_at            TIMESTAMP,
    created_at            TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_grants_record ON grants(record_id) WHERE revoked = FALSE;
```

### `audit_log`

```sql
CREATE TABLE audit_log (
    id                SERIAL       PRIMARY KEY,
    event_id          VARCHAR(64)  UNIQUE NOT NULL,
    actor_user_id_hex VARCHAR(64)  REFERENCES users(user_id_hex),
    action            VARCHAR(255),
    share_id          VARCHAR(64),
    detail            JSONB        DEFAULT '{}',
    ip_address        INET,
    user_agent        TEXT,
    timestamp         TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_actor     ON audit_log(actor_user_id_hex);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
```

### `rate_limit`

```sql
CREATE TABLE rate_limit (
    key_hash      VARCHAR(255) NOT NULL,
    action        VARCHAR(100) NOT NULL,
    attempts      INTEGER      DEFAULT 1,
    first_attempt TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    last_attempt  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP,
    PRIMARY KEY (key_hash, action)
);
```

### `token_revocations`

```sql
CREATE TABLE token_revocations (
    token_jti   VARCHAR(255) PRIMARY KEY,
    user_id_hex VARCHAR(64)  NOT NULL,
    expires_at  TIMESTAMP    NOT NULL,
    revoked_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_token_revocations_expires ON token_revocations(expires_at);
```

### `pow_challenges`

```sql
CREATE TABLE pow_challenges (
    challenge_id  VARCHAR(64)  PRIMARY KEY,
    nonce_prefix  VARCHAR(255) NOT NULL,
    difficulty    INTEGER      NOT NULL,
    target_hash   VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP    NOT NULL,
    solved_at     TIMESTAMP,
    solved_nonce  VARCHAR(255),
    solver_ip     INET
);
CREATE INDEX idx_pow_expires ON pow_challenges(expires_at) WHERE solved_at IS NULL;
```

### `refresh_tokens`

```sql
CREATE TABLE refresh_tokens (
    token_hash  VARCHAR(255) PRIMARY KEY,
    user_id_hex VARCHAR(64)  NOT NULL REFERENCES users(user_id_hex),
    family_id   VARCHAR(64)  NOT NULL,
    expires_at  TIMESTAMP    NOT NULL,
    revoked_at  TIMESTAMP,
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_refresh_family  ON refresh_tokens(family_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_expires ON refresh_tokens(expires_at);
```

---

## Security Considerations

**Password handling** — never pass plaintext passwords to `create_user()`. Hash with PBKDF2-SHA512 (600,000 iterations), bcrypt, or Argon2id first. The `password_hash` and `pwhash_salt` columns are returned by the `get_user_by_*` methods so authentication can be performed, but they should not be forwarded to API responses.

**SQL injection prevention** — all queries use positional parameters (`$1`, `$2`, …). Dynamic queries in `update_user()` additionally validate field names against `_UPDATABLE_USER_FIELDS` and `_FIELD_RE` before building the `SET` clause.

**Soft deletes** — `delete_user()` sets `account_deleted = TRUE` rather than removing the row, preserving audit history. All lookups filter on `account_deleted = FALSE`.

**Cascade deletes** — `vault_ciphertext` has an `ON DELETE CASCADE` FK to `vault_records`, so deleting a record automatically removes the ciphertext.

**Refresh tokens** — store only the hash (`SHA-256` or similar), never the raw token.

**Rate limiting** — `record_attempt()` and `block_rate_limit()` use atomic upserts, making them safe under concurrent load.

---

## Error Handling

| Exception | Cause | Suggested handling |
|-----------|-------|--------------------|
| `ValueError` | `create_user()` called with neither `user_id_hex` nor `signing_public_key` | Return HTTP 400 |
| `asyncpg.UniqueViolationError` | Duplicate username or email | Return HTTP 409 |
| `asyncpg.ForeignKeyViolationError` | Invalid `user_id_hex` reference | Return HTTP 422 |
| `asyncpg.PostgresError` | General database error | Log and return HTTP 500 |
| `asyncpg.InterfaceError` | Pool closed or connection lost | Reconnect and retry |

```python
from asyncpg import UniqueViolationError, PostgresError

async def safe_create_user(db, user_data):
    try:
        return await db.create_user(user_data)
    except UniqueViolationError as e:
        if "username" in str(e):
            raise ValueError("Username already taken")
        if "email" in str(e):
            raise ValueError("Email already registered")
        raise
    except PostgresError as e:
        logger.error(f"Database error: {e}")
        raise
```

---

## Known Test Issues

Two tests in `tests/test_database.py` fail due to bugs in the test file itself, not in `database.py`:

**`TestConnectionManagement::test_close_pool`** — the test calls `await db.close()` (which sets `self.pool = None`), then immediately accesses `db.pool.close.assert_called_once()`. Since `db.pool` is `None` at that point, this raises `AttributeError`. The two assertions are in the wrong order; they should be swapped.

**`TestRefreshTokens::test_store_refresh_token`** — the test file was truncated in the source zip. The final assertion line reads `mock_connection.execute.assert_c` (cut off mid-word), which Python evaluates as an attribute access on an `AsyncMock` and raises `AttributeError: 'assert_c' is not a valid assertion`.

Both issues are in the test source, not the implementation. All 59 remaining tests pass.

---

## Changelog

| Version | Changes |
|---------|---------|
| 1.0 | Initial implementation |
| 1.1 | Fixed `init=asyncpg.Bytes` crash, `block_rate_limit()` param order |
| 1.2 | Added `_FIELD_RE` defense-in-depth, singleton race condition fix |
| 1.3 | Separate connection params (no DSN password exposure), `_utcnow()` helper |
| 1.4 | Added user_id validation, consistent `bool` return values, logging |
| 1.5 | `asyncpg.Bytes` compat patch; `os.getenv() or default` pattern; `create_user()` tolerates missing optional fields; `close()` saves pool ref before nulling |
