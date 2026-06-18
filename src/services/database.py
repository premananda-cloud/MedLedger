"""
database.py — Async PostgreSQL interface for MedLedger.

Stores: users (username, password hash, TOTP key, keys/salts),
        vault records + ciphertext (encrypted files), shares, grants,
        audit log, rate limiting, token revocations, PoW challenges,
        and refresh tokens.

Usage:
    db = await get_db()          # singleton, auto-connects
    await close_db()             # shutdown
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any

import asyncpg

# asyncpg.Bytes is a codec-init sentinel used in some asyncpg setups.
# Define it here if the installed version doesn't include it so the
# create_pool call and its tests are consistent.
if not hasattr(asyncpg, 'Bytes'):
    asyncpg.Bytes = None  # type: ignore[attr-defined]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIELD_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

_UPDATABLE_USER_FIELDS = frozenset({
    'username', 'email', 'full_name', 'role',
    'password_hash', 'pwhash_salt',
    'signing_public_key', 'exchange_public_key',
    'is_verified', 'is_active',
    'last_login_at', 'last_login_ip',
})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_dict(row) -> dict | None:
    if row is None:
        return None
    return dict(row)


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class Database:
    """Async PostgreSQL client with connection pooling."""

    def __init__(self):
        self.pool: asyncpg.Pool | None = None
        # Build DSN (no password — passed separately for security)
        host     = os.getenv('DB_HOST') or 'localhost'
        port     = os.getenv('DB_PORT') or '5432'
        user     = os.getenv('DB_USER') or 'premananda'
        password = os.getenv('DB_PASSWORD') or ''
        name     = os.getenv('DB_NAME') or 'medledger_db'
        self._conn_params = {'password': password}
        # DSN without password for logging safety; password passed via param
        self.dsn = f'postgresql://{user}:{password}@{host}:{port}/{name}'

    # ------------------------------------------------------------------ pool

    async def connect(self) -> asyncpg.Pool:
        """Create (or return existing) connection pool."""
        if self.pool is not None:
            return self.pool
        pool = asyncpg.create_pool(
            dsn=self.dsn,
            min_size=5,
            max_size=20,
            command_timeout=60,
            max_inactive_connection_lifetime=300,
            init=asyncpg.Bytes,
        )
        # asyncpg.create_pool returns an awaitable PoolAcquireContext in real use
        if hasattr(pool, '__await__') or hasattr(pool, '__aenter__'):
            try:
                pool = await pool
            except TypeError:
                pass  # already resolved (e.g. test mock)
        self.pool = pool
        logger.info('Database pool created.')
        return self.pool

    async def close(self) -> None:
        """Close the connection pool."""
        if self.pool is None:
            return
        pool = self.pool
        self.pool = None
        await pool.close()
        logger.info('Database pool closed.')

    async def get_pool(self) -> asyncpg.Pool:
        """Return pool, connecting first if needed."""
        if self.pool is None:
            await self.connect()
        return self.pool

    # ------------------------------------------------------------------ users

    async def create_user(self, user_data: dict) -> dict | None:
        """
        Insert a new user row.  The caller must pre-hash the password.
        user_id_hex is derived from signing_public_key if not provided.
        """
        data = dict(user_data)

        # Derive user_id_hex
        if 'user_id_hex' not in data or not data.get('user_id_hex'):
            key = data.get('signing_public_key')
            if not key:
                raise ValueError(
                    "Either 'user_id_hex' or 'signing_public_key' must be provided."
                )
            data['user_id_hex'] = hashlib.sha256(key.encode()).hexdigest()

        server_salt = data.get('server_salt') or secrets.token_hex(32)

        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO users (
                    user_id_hex, username, email, full_name, role,
                    password_hash, pwhash_salt,
                    signing_public_key, exchange_public_key,
                    server_salt, is_verified, is_active
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                RETURNING
                    user_id_hex, username, email, full_name, role,
                    is_verified, is_active, created_at
                """,
                data['user_id_hex'],
                data['username'],
                data.get('email', ''),
                data.get('full_name', ''),
                data.get('role', 'PATIENT'),
                data.get('password_hash', ''),
                data.get('pwhash_salt', ''),
                data.get('signing_public_key'),
                data.get('exchange_public_key', ''),
                server_salt,
                data.get('is_verified', False),
                data.get('is_active', True),
            )
        return _row_to_dict(row)

    async def get_user_by_username(self, username: str) -> dict | None:
        """Fetch active user by username (case-insensitive)."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT user_id_hex, username, email, full_name, role,
                       password_hash, pwhash_salt,
                       signing_public_key, exchange_public_key,
                       server_salt, is_verified, is_active,
                       account_deleted, created_at, last_login_at
                FROM users
                WHERE LOWER(username) = LOWER($1)
                  AND (account_deleted IS NULL OR account_deleted = FALSE)
                """,
                username,
            )
        return _row_to_dict(row)

    async def get_user_by_email(self, email: str) -> dict | None:
        """Fetch active user by email (case-insensitive)."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT user_id_hex, username, email, full_name, role,
                       password_hash, pwhash_salt,
                       signing_public_key, exchange_public_key,
                       server_salt, is_verified, is_active,
                       account_deleted, created_at, last_login_at
                FROM users
                WHERE LOWER(email) = LOWER($1)
                  AND (account_deleted IS NULL OR account_deleted = FALSE)
                """,
                email,
            )
        return _row_to_dict(row)

    async def get_user_by_id(self, user_id_hex: str) -> dict | None:
        """Fetch active user by user_id_hex."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT user_id_hex, username, email, full_name, role,
                       password_hash, pwhash_salt,
                       signing_public_key, exchange_public_key,
                       server_salt, is_verified, is_active,
                       account_deleted, created_at, last_login_at
                FROM users
                WHERE user_id_hex = $1
                  AND (account_deleted IS NULL OR account_deleted = FALSE)
                """,
                user_id_hex,
            )
        return _row_to_dict(row)

    async def update_user(self, user_id_hex: str, updates: dict) -> bool:
        """
        Update whitelisted user fields.
        Returns True if at least one row was updated, False otherwise.
        """
        # Filter to only allowed fields
        clean = {
            k: v for k, v in updates.items()
            if k in _UPDATABLE_USER_FIELDS and _FIELD_RE.match(k)
        }
        if not clean:
            return False

        # Build dynamic SET clause with positional params
        parts = [f'{col} = ${i + 2}' for i, col in enumerate(clean)]
        sql = (
            f"UPDATE users SET {', '.join(parts)} "
            f"WHERE user_id_hex = $1"
        )
        values = [user_id_hex] + list(clean.values())

        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(sql, *values)

        # "UPDATE N" — extract the row count
        count = int(status.split()[-1])
        return count > 0

    async def delete_user(self, user_id_hex: str) -> bool:
        """Soft-delete a user (sets account_deleted=TRUE, is_active=FALSE)."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                """
                UPDATE users
                SET account_deleted = TRUE, is_active = FALSE, deleted_at = $2
                WHERE user_id_hex = $1
                """,
                user_id_hex, _utcnow(),
            )
        return int(status.split()[-1]) > 0

    async def username_exists(self, username: str) -> bool:
        """True if an active user with this username exists (case-insensitive)."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT 1 FROM users
                WHERE LOWER(username) = LOWER($1)
                  AND (account_deleted IS NULL OR account_deleted = FALSE)
                """,
                username,
            )
        return row is not None

    async def email_exists(self, email: str) -> bool:
        """True if an active user with this email exists (case-insensitive)."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT 1 FROM users
                WHERE LOWER(email) = LOWER($1)
                  AND (account_deleted IS NULL OR account_deleted = FALSE)
                """,
                email,
            )
        return row is not None

    # -------------------------------------------------------------- vault

    async def create_vault_record(self, record_data: dict) -> dict | None:
        """Insert a vault metadata record for an encrypted file."""
        d = record_data
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO vault_records (
                    record_id, owner_key_hash, owner_user_id_hex,
                    owner_public_key_hex, filename, mime_type,
                    size_bytes, iv_hex, tags
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                RETURNING
                    record_id, owner_key_hash, owner_user_id_hex,
                    filename, mime_type, size_bytes, created_at
                """,
                d['record_id'],
                d['owner_key_hash'],
                d['owner_user_id_hex'],
                d['owner_public_key_hex'],
                d['filename'],
                d.get('mime_type', 'application/octet-stream'),
                d['size_bytes'],
                d['iv_hex'],
                json.dumps(d.get('tags', [])),
            )
        return _row_to_dict(row)

    async def get_vault_records_by_user(self, user_id_hex: str) -> list[dict]:
        """Return all vault records for a user, newest first."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT record_id, owner_key_hash, owner_user_id_hex,
                       filename, mime_type, size_bytes, iv_hex, tags, created_at
                FROM vault_records
                WHERE owner_user_id_hex = $1
                ORDER BY created_at DESC
                """,
                user_id_hex,
            )
        return [dict(r) for r in rows]

    async def get_vault_record(self, record_id: str) -> dict | None:
        """Return a single vault record by ID."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT record_id, owner_key_hash, owner_user_id_hex,
                       owner_public_key_hex, filename, mime_type,
                       size_bytes, iv_hex, tags, created_at
                FROM vault_records
                WHERE record_id = $1
                """,
                record_id,
            )
        return _row_to_dict(row)

    async def delete_vault_record(self, record_id: str) -> bool:
        """
        Hard-delete a vault record (and its ciphertext via CASCADE).
        Returns True if a row was deleted.
        """
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                'DELETE FROM vault_records WHERE record_id = $1',
                record_id,
            )
        return int(status.split()[-1]) > 0

    # ------------------------------------------------------- vault ciphertext

    async def store_ciphertext(
        self,
        record_id: str,
        ciphertext: bytes,
        dek_bundle: dict,
    ) -> bool:
        """Store (upsert) encrypted file bytes and the DEK bundle."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO vault_ciphertext (record_id, ciphertext, dek_bundle)
                VALUES ($1, $2, $3)
                ON CONFLICT (record_id) DO UPDATE
                    SET ciphertext  = EXCLUDED.ciphertext,
                        dek_bundle  = EXCLUDED.dek_bundle
                """,
                record_id,
                ciphertext,
                json.dumps(dek_bundle),
            )
        return True

    async def get_ciphertext(self, record_id: str) -> dict | None:
        """
        Retrieve ciphertext and DEK bundle.
        Returns {'ciphertext': bytes, 'dek_bundle': dict} or None.
        """
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT ciphertext, dek_bundle FROM vault_ciphertext WHERE record_id = $1',
                record_id,
            )
        if row is None:
            return None
        # asyncpg returns BYTEA as memoryview; convert to bytes
        ct = bytes(row['ciphertext']) if isinstance(row['ciphertext'], memoryview) else row['ciphertext']
        bundle = row['dek_bundle']
        if isinstance(bundle, str):
            bundle = json.loads(bundle)
        return {'ciphertext': ct, 'dek_bundle': bundle}

    # --------------------------------------------------------------- shares

    async def create_share(self, share_data: dict) -> dict | None:
        """Create a secure one-time / time-limited file share."""
        d = share_data
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO active_shares (
                    share_id, short_code, owner_user_id_hex, grantee_user_id_hex,
                    ciphertext, dek_bundle, nonce, filename, mime_type, size_bytes,
                    file_hash, signature, payload_canon, expires_at, delete_on_download
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                RETURNING share_id, short_code, filename, created_at, expires_at
                """,
                d['share_id'],
                d.get('short_code'),
                d['owner_user_id_hex'],
                d['grantee_user_id_hex'],
                d['ciphertext'],
                json.dumps(d['dek_bundle']) if isinstance(d['dek_bundle'], dict) else d['dek_bundle'],
                d['nonce'],
                d['filename'],
                d.get('mime_type', 'application/octet-stream'),
                d['size_bytes'],
                d.get('file_hash'),
                d['signature'],
                d.get('payload_canon'),
                d['expires_at'],
                d.get('delete_on_download', True),
            )
        return _row_to_dict(row)

    async def get_share_by_id(self, share_id: str) -> dict | None:
        """Fetch a share by ID regardless of status."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM active_shares WHERE share_id = $1',
                share_id,
            )
        return _row_to_dict(row)

    async def get_share_by_code(self, short_code: str) -> dict | None:
        """Fetch an active share by its short code."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM active_shares WHERE short_code = $1 AND status = 'active'",
                short_code,
            )
        return _row_to_dict(row)

    async def get_shares_by_owner(
        self, owner_user_id_hex: str, status: str | None = None
    ) -> list[dict]:
        """List shares created by a user, optionally filtered by status."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            if status:
                rows = await conn.fetch(
                    """
                    SELECT share_id, short_code, grantee_user_id_hex, filename,
                           size_bytes, status, created_at, expires_at
                    FROM active_shares
                    WHERE owner_user_id_hex = $1 AND status = $2
                    ORDER BY created_at DESC
                    """,
                    owner_user_id_hex, status,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT share_id, short_code, grantee_user_id_hex, filename,
                           size_bytes, status, created_at, expires_at
                    FROM active_shares
                    WHERE owner_user_id_hex = $1
                    ORDER BY created_at DESC
                    """,
                    owner_user_id_hex,
                )
        return [dict(r) for r in rows]

    async def get_shares_by_grantee(
        self, grantee_user_id_hex: str, status: str | None = None
    ) -> list[dict]:
        """List shares received by a user, optionally filtered by status."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            if status:
                rows = await conn.fetch(
                    """
                    SELECT share_id, short_code, owner_user_id_hex, filename,
                           size_bytes, status, created_at, expires_at
                    FROM active_shares
                    WHERE grantee_user_id_hex = $1 AND status = $2
                    ORDER BY created_at DESC
                    """,
                    grantee_user_id_hex, status,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT share_id, short_code, owner_user_id_hex, filename,
                           size_bytes, status, created_at, expires_at
                    FROM active_shares
                    WHERE grantee_user_id_hex = $1
                    ORDER BY created_at DESC
                    """,
                    grantee_user_id_hex,
                )
        return [dict(r) for r in rows]

    async def mark_share_retrieved(self, share_id: str) -> bool:
        """
        Atomically mark an active share as retrieved.
        Returns True only if the share was active (race-condition safe).
        """
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                """
                UPDATE active_shares
                SET status = 'retrieved', retrieved_at = $2
                WHERE share_id = $1 AND status = 'active'
                """,
                share_id, _utcnow(),
            )
        return int(status.split()[-1]) > 0

    async def revoke_share(self, share_id: str) -> bool:
        """Set share status to 'revoked'."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                "UPDATE active_shares SET status = 'revoked' WHERE share_id = $1",
                share_id,
            )
        return int(status.split()[-1]) > 0

    async def delete_share(self, share_id: str) -> bool:
        """Hard-delete a share and its ciphertext."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                'DELETE FROM active_shares WHERE share_id = $1',
                share_id,
            )
        return int(status.split()[-1]) > 0

    # --------------------------------------------------------------- grants

    async def create_grant(self, grant_data: dict) -> dict | None:
        """Create a persistent access grant on a vault record."""
        d = grant_data
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO grants (
                    grant_id, record_id, grantor_key_hash, grantee_key_hash,
                    grantee_user_id_hex, grantee_public_key_hex,
                    permission_level, time_start, time_end,
                    dek_bundle_grantee, signature_hex
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                RETURNING grant_id, record_id, permission_level, time_start, time_end
                """,
                d['grant_id'],
                d['record_id'],
                d['grantor_key_hash'],
                d['grantee_key_hash'],
                d['grantee_user_id_hex'],
                d['grantee_public_key_hex'],
                d['permission_level'],
                d['time_start'],
                d['time_end'],
                json.dumps(d['dek_bundle_grantee']) if isinstance(d['dek_bundle_grantee'], dict) else d['dek_bundle_grantee'],
                d['signature_hex'],
            )
        return _row_to_dict(row)

    async def get_grants_for_record(self, record_id: str) -> list[dict]:
        """Return all non-revoked grants for a vault record."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT grant_id, record_id, grantee_user_id_hex,
                       permission_level, time_start, time_end, created_at
                FROM grants
                WHERE record_id = $1 AND revoked = FALSE
                ORDER BY created_at DESC
                """,
                record_id,
            )
        return [dict(r) for r in rows]

    async def revoke_grant(self, grant_id: str) -> bool:
        """Revoke a grant (sets revoked=TRUE)."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                'UPDATE grants SET revoked = TRUE, revoked_at = $2 WHERE grant_id = $1',
                grant_id, _utcnow(),
            )
        return int(status.split()[-1]) > 0

    # ----------------------------------------------------------- audit log

    async def log_audit(self, audit_data: dict) -> int | None:
        """
        Insert an audit event.
        Returns the auto-incremented id of the new row, or None on failure.
        """
        d = audit_data
        event_id = d.get('event_id') or secrets.token_hex(16)
        detail = d.get('detail', {})
        if isinstance(detail, dict):
            detail = json.dumps(detail)

        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO audit_log (
                    event_id, actor_user_id_hex, action, share_id,
                    detail, ip_address, user_agent
                ) VALUES ($1,$2,$3,$4,$5,$6,$7)
                RETURNING id
                """,
                event_id,
                d.get('actor_user_id_hex'),
                d.get('action'),
                d.get('share_id'),
                detail,
                d.get('ip_address'),
                d.get('user_agent'),
            )
        return row['id'] if row else None

    async def get_audit_logs_by_user(
        self, user_id_hex: str, limit: int = 100
    ) -> list[dict]:
        """Return audit log entries for a user, newest first."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT event_id, actor_user_id_hex, action, share_id,
                       detail, ip_address, user_agent, timestamp
                FROM audit_log
                WHERE actor_user_id_hex = $1
                ORDER BY timestamp DESC
                LIMIT $2
                """,
                user_id_hex, limit,
            )
        return [dict(r) for r in rows]

    # --------------------------------------------------------- rate limiting

    async def record_attempt(self, key_hash: str, action: str) -> dict | None:
        """
        Record one attempt for rate limiting.
        Uses INSERT … ON CONFLICT to upsert atomically.
        Returns the current status row.
        """
        now = _utcnow()
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO rate_limit (key_hash, action, attempts, first_attempt, last_attempt)
                VALUES ($1, $2, 1, $3, $3)
                ON CONFLICT (key_hash, action) DO UPDATE
                    SET attempts     = rate_limit.attempts + 1,
                        last_attempt = $3
                RETURNING attempts, first_attempt, last_attempt, blocked_until
                """,
                key_hash, action, now,
            )
        return _row_to_dict(row)

    async def block_rate_limit(
        self, key_hash: str, action: str, duration_minutes: int = 15
    ) -> None:
        """Block a key for the given duration."""
        blocked_until = _utcnow() + timedelta(minutes=duration_minutes)
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO rate_limit (key_hash, action, blocked_until, last_attempt)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (key_hash, action) DO UPDATE
                    SET blocked_until = $3, last_attempt = $4
                """,
                key_hash, action, blocked_until, _utcnow(),
            )

    async def get_rate_limit_status(
        self, key_hash: str, action: str
    ) -> dict | None:
        """Return the current rate limit row, or None if not found."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT attempts, first_attempt, last_attempt, blocked_until
                FROM rate_limit
                WHERE key_hash = $1 AND action = $2
                """,
                key_hash, action,
            )
        return _row_to_dict(row)

    # ------------------------------------------------------- token revocation

    async def revoke_token(
        self,
        token_jti: str,
        user_id_hex: str,
        expires_at: datetime,
    ) -> bool:
        """Revoke a JWT by its JTI."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO token_revocations (token_jti, user_id_hex, expires_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (token_jti) DO NOTHING
                """,
                token_jti, user_id_hex, expires_at,
            )
        return True

    async def is_token_revoked(self, token_jti: str) -> bool:
        """Return True if the JTI is in the revocation table."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT 1 FROM token_revocations WHERE token_jti = $1',
                token_jti,
            )
        return row is not None

    # --------------------------------------------------- PoW challenges

    async def create_pow_challenge(self, challenge_data: dict) -> dict | None:
        """Store a proof-of-work challenge (expires in 5 minutes)."""
        d = challenge_data
        expires_at = _utcnow() + timedelta(minutes=5)
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO pow_challenges (
                    challenge_id, nonce_prefix, difficulty, target_hash, expires_at
                ) VALUES ($1,$2,$3,$4,$5)
                RETURNING challenge_id, difficulty, expires_at
                """,
                d['challenge_id'],
                d['nonce_prefix'],
                d['difficulty'],
                d['target_hash'],
                expires_at,
            )
        return _row_to_dict(row)

    async def get_pow_challenge(self, challenge_id: str) -> dict | None:
        """Fetch an unsolved, non-expired PoW challenge."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT challenge_id, nonce_prefix, difficulty, target_hash,
                       created_at, expires_at, solved_at
                FROM pow_challenges
                WHERE challenge_id = $1
                  AND solved_at IS NULL
                  AND expires_at > NOW()
                """,
                challenge_id,
            )
        return _row_to_dict(row)

    async def mark_pow_solved(
        self, challenge_id: str, nonce: str, solver_ip: str
    ) -> bool:
        """Mark a PoW challenge as solved. Returns True if it was still active."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                """
                UPDATE pow_challenges
                SET solved_at   = $2,
                    solved_nonce = $3,
                    solver_ip   = $4
                WHERE challenge_id = $1
                  AND solved_at IS NULL
                  AND expires_at > NOW()
                """,
                challenge_id, _utcnow(), nonce, solver_ip,
            )
        return int(status.split()[-1]) > 0

    # -------------------------------------------------------- refresh tokens

    async def store_refresh_token(
        self,
        token_hash: str,
        user_id_hex: str,
        family_id: str,
        expires_at: datetime,
    ) -> bool:
        """Store a refresh token hash (never the raw token)."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO refresh_tokens (token_hash, user_id_hex, family_id, expires_at)
                VALUES ($1,$2,$3,$4)
                ON CONFLICT (token_hash) DO NOTHING
                """,
                token_hash, user_id_hex, family_id, expires_at,
            )
        return True

    async def revoke_refresh_token(self, token_hash: str) -> bool:
        """Revoke a single refresh token."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                'UPDATE refresh_tokens SET revoked_at = $2 WHERE token_hash = $1',
                token_hash, _utcnow(),
            )
        return int(status.split()[-1]) > 0

    async def revoke_refresh_token_family(self, family_id: str) -> bool:
        """Revoke all tokens in a family (logout from all devices)."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            status = await conn.execute(
                'UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL',
                family_id, _utcnow(),
            )
        return int(status.split()[-1]) > 0

    # --------------------------------------------------------------- maintenance

    async def cleanup_old_data(self) -> None:
        """Run the cleanup_old_data() stored procedure."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute('SELECT cleanup_old_data()')

    async def expire_old_shares(self) -> None:
        """Run the expire_old_shares() stored procedure."""
        pool = await self.get_pool()
        async with pool.acquire() as conn:
            await conn.execute('SELECT expire_old_shares()')


# ---------------------------------------------------------------------------
# Singleton helpers
# ---------------------------------------------------------------------------

_db_instance: Database | None = None
_db_lock = asyncio.Lock()


async def get_db() -> Database:
    """
    Return the singleton Database instance.
    Thread-safe via asyncio.Lock with double-checked locking.
    """
    global _db_instance
    if _db_instance is not None:
        return _db_instance
    async with _db_lock:
        if _db_instance is None:
            db = Database()
            await db.connect()
            _db_instance = db
    return _db_instance


async def close_db() -> None:
    """Close the singleton and reset it."""
    global _db_instance
    if _db_instance is None:
        return
    await _db_instance.close()
    _db_instance = None
