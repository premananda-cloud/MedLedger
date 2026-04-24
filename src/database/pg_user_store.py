"""
database/pg_user_store.py

PostgreSQL-backed user store.
Drop-in replacement for UserStore (JSON) — identical public interface.

A ThreadedConnectionPool is created once per instance and shared safely
across FastAPI / uvicorn threads.  All writes run in explicit transactions;
failures auto-rollback via the context manager.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras
from psycopg2 import pool as pg_pool

from src.schemas import UserRecord, AuditEntry


# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL = """
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
    public_key_hash       TEXT        UNIQUE,
    verification_token    TEXT,
    token_expires_at      TEXT,
    reset_token_hash      TEXT,
    reset_token_expires_at TEXT,
    created_at            TEXT        NOT NULL,
    last_login            TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower
    ON users (lower(username));

CREATE TABLE IF NOT EXISTS user_audit (
    id          SERIAL  PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    action      TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    timestamp   TEXT    NOT NULL
);

-- Safe migration for existing deployments that predate the reset-token columns
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='users' AND column_name='reset_token_hash'
    ) THEN
        ALTER TABLE users
            ADD COLUMN reset_token_hash       TEXT,
            ADD COLUMN reset_token_expires_at TEXT;
    END IF;
END$$;
"""


# ── helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── store ─────────────────────────────────────────────────────────────────────

class PgUserStore:

    def __init__(self, dsn: str):
        self._pool = pg_pool.ThreadedConnectionPool(1, 10, dsn=dsn)
        self._init_schema()

    # ── schema ────────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        with self._tx() as cur:
            cur.execute(_DDL)

    # ── connection context manager ────────────────────────────────────────────

    @contextmanager
    def _tx(self):
        """Yield a RealDictCursor inside a single transaction."""
        conn = self._pool.getconn()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            self._pool.putconn(conn)

    # ── row → schema conversion ───────────────────────────────────────────────

    @staticmethod
    def _to_user(row) -> UserRecord:
        return UserRecord.from_dict(dict(row))

    @staticmethod
    def _to_audit(row) -> AuditEntry:
        return AuditEntry.from_dict(dict(row))

    # ── queries ───────────────────────────────────────────────────────────────

    def get_by_email(self, email: str) -> Optional[UserRecord]:
        with self._tx() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email.lower(),))
            row = cur.fetchone()
        return self._to_user(row) if row else None

    def get_by_id(self, user_id: int) -> Optional[UserRecord]:
        with self._tx() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
        return self._to_user(row) if row else None

    def get_by_verification_token(self, token: str) -> Optional[UserRecord]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM users WHERE verification_token = %s", (token,)
            )
            row = cur.fetchone()
        return self._to_user(row) if row else None

    def get_by_public_key_hash(self, pkh: str) -> Optional[UserRecord]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM users WHERE public_key_hash = %s", (pkh,)
            )
            row = cur.fetchone()
        return self._to_user(row) if row else None

    # ── mutations ─────────────────────────────────────────────────────────────

    def create_user(
        self,
        *,
        email: str,
        username: str,
        full_name: str = "",
        role: str = "PATIENT",
        password_hash: str,
        verification_token: str,
        token_expires_at: str,
    ) -> UserRecord:
        """
        Insert a new unverified user.
        Raises ValueError on duplicate email or username.
        """
        with self._tx() as cur:
            # duplicate check (case-insensitive username)
            cur.execute(
                "SELECT email, username FROM users "
                "WHERE email = %s OR lower(username) = lower(%s)",
                (email.lower(), username),
            )
            conflict = cur.fetchone()
            if conflict:
                if conflict["email"] == email.lower():
                    raise ValueError(f"Email already registered: {email}")
                raise ValueError(f"Username already taken: {username}")

            cur.execute(
                """
                INSERT INTO users
                    (email, username, full_name, role, password_hash,
                     verification_token, token_expires_at,
                     is_verified, is_active, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE, FALSE, %s)
                RETURNING *
                """,
                (
                    email.lower(), username, full_name, role, password_hash,
                    verification_token, token_expires_at, _now(),
                ),
            )
            row = cur.fetchone()
        return self._to_user(row)

    def activate_user(
        self,
        *,
        user_id: int,
        public_key_hex: str,
        public_key_compressed: str,
        public_key_hash: str,
    ) -> None:
        """Set public-key fields, mark verified + active, clear the token."""
        with self._tx() as cur:
            cur.execute(
                """
                UPDATE users SET
                    is_verified           = TRUE,
                    is_active             = TRUE,
                    public_key_hex        = %s,
                    public_key_compressed = %s,
                    public_key_hash       = %s,
                    verification_token    = NULL,
                    token_expires_at      = NULL
                WHERE id = %s
                """,
                (public_key_hex, public_key_compressed, public_key_hash, user_id),
            )

    def set_last_login(self, *, user_id: int) -> None:
        with self._tx() as cur:
            cur.execute(
                "UPDATE users SET last_login = %s WHERE id = %s",
                (_now(), user_id),
            )

    def set_reset_token(self, *, user_id: int, token_hash: str, expires_at: str) -> None:
        """Store a hashed password-reset token and its expiry for user_id."""
        with self._tx() as cur:
            cur.execute(
                """
                UPDATE users SET
                    reset_token_hash       = %s,
                    reset_token_expires_at = %s
                WHERE id = %s
                """,
                (token_hash, expires_at, user_id),
            )

    def get_by_reset_token_hash(self, token_hash: str) -> Optional[UserRecord]:
        """Look up a user by their hashed reset token."""
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM users WHERE reset_token_hash = %s", (token_hash,)
            )
            row = cur.fetchone()
        return self._to_user(row) if row else None

    def set_password(self, *, user_id: int, password_hash: str) -> None:
        """Update password and clear the reset token atomically."""
        with self._tx() as cur:
            cur.execute(
                """
                UPDATE users SET
                    password_hash          = %s,
                    reset_token_hash       = NULL,
                    reset_token_expires_at = NULL
                WHERE id = %s
                """,
                (password_hash, user_id),
            )

    # ── audit ─────────────────────────────────────────────────────────────────

    def append_audit(
        self,
        *,
        user_id: int,
        action: str,
        description: str,
    ) -> AuditEntry:
        with self._tx() as cur:
            cur.execute(
                """
                INSERT INTO user_audit (user_id, action, description, timestamp)
                VALUES (%s, %s, %s, %s)
                RETURNING *
                """,
                (user_id, action, description, _now()),
            )
            row = cur.fetchone()
        return self._to_audit(row)

    def get_audit_for_user(self, user_id: int) -> list[AuditEntry]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM user_audit WHERE user_id = %s ORDER BY id",
                (user_id,),
            )
            rows = cur.fetchall()
        return [self._to_audit(r) for r in rows]
