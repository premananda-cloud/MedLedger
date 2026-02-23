"""
core/keystore.py - Local key and session storage using SQLite.

Design:
  - One SQLite database: keys/medledger.db
  - Table `users`   — stores account info + private key hex (plain text — demo only)
  - Table `session` — stores the currently logged-in user id

Private key is stored as a 64-char hex string directly in the DB.
No passphrase, no encryption of the key file — kept simple for demo purposes.

If you need production-grade security, replace the `private_key_hex` column
with an AES-GCM encrypted blob and add a passphrase prompt at login time.
"""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from config import KEYS_DIR

DB_PATH = KEYS_DIR / "medledger.db"


# ── DB bootstrap ──────────────────────────────────────────────────────────────

def _init_db():
    with _conn() as cx:
        cx.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,   -- server int OR offline_xxx string
                username      TEXT NOT NULL,
                email         TEXT NOT NULL,
                full_name     TEXT,
                role          TEXT NOT NULL,
                private_key_hex TEXT NOT NULL,    -- 64 hex chars (raw P-256 scalar)
                public_key_hex  TEXT NOT NULL,    -- 130 hex chars (uncompressed)
                public_key_hash TEXT NOT NULL,    -- 64 hex chars (SHA-256 of pub)
                token         TEXT,               -- JWT (null if offline)
                created_at    TEXT
            )
        """)
        cx.execute("""
            CREATE TABLE IF NOT EXISTS session (
                id      INTEGER PRIMARY KEY CHECK (id = 1),  -- only one row
                user_id TEXT
            )
        """)
        cx.execute("INSERT OR IGNORE INTO session (id, user_id) VALUES (1, NULL)")


@contextmanager
def _conn():
    KEYS_DIR.mkdir(exist_ok=True)
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


_init_db()


# ── User storage ──────────────────────────────────────────────────────────────

def save_user(
    user_id: str,
    username: str,
    email: str,
    full_name: str,
    role: str,
    private_key_hex: str,
    public_key_hex: str,
    public_key_hash: str,
    token: Optional[str] = None,
    created_at: Optional[str] = None,
):
    """Insert or update a user record in the local DB."""
    with _conn() as cx:
        cx.execute("""
            INSERT INTO users
              (user_id, username, email, full_name, role,
               private_key_hex, public_key_hex, public_key_hash, token, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              token      = excluded.token,
              full_name  = excluded.full_name
        """, (str(user_id), username, email, full_name, role,
              private_key_hex, public_key_hex, public_key_hash,
              token, created_at))


def load_user(user_id: str) -> Optional[dict]:
    """Return the user row as a dict, or None."""
    with _conn() as cx:
        row = cx.execute(
            "SELECT * FROM users WHERE user_id = ?", (str(user_id),)
        ).fetchone()
    return dict(row) if row else None


def find_user_by_email(email: str) -> Optional[dict]:
    """Look up a local user by email (for offline login)."""
    with _conn() as cx:
        row = cx.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
    return dict(row) if row else None


def update_token(user_id: str, token: Optional[str]):
    with _conn() as cx:
        cx.execute("UPDATE users SET token = ? WHERE user_id = ?",
                   (token, str(user_id)))


def key_exists(user_id) -> bool:
    return load_user(str(user_id)) is not None


def load_private_key_hex(user_id) -> str:
    """Return the private key hex for user_id. Raises if not found."""
    row = load_user(str(user_id))
    if not row:
        raise FileNotFoundError(
            f"No local key found for user {user_id}. "
            "Did you register on this device?"
        )
    return row["private_key_hex"]


# ── Session (who is currently logged in) ─────────────────────────────────────

def set_active_session(user_id: Optional[str]):
    with _conn() as cx:
        cx.execute("UPDATE session SET user_id = ? WHERE id = 1",
                   (str(user_id) if user_id else None,))


def get_active_session() -> Optional[str]:
    with _conn() as cx:
        row = cx.execute("SELECT user_id FROM session WHERE id = 1").fetchone()
    return row["user_id"] if row else None


def clear_session():
    set_active_session(None)


# ── Legacy shims (so old imports don't break) ─────────────────────────────────

def save_session(user_id, token, role, username, full_name,
                 email, public_key_hex, public_key_hash):
    """Compat shim — actual data lives in the users table."""
    update_token(str(user_id), token)
    set_active_session(str(user_id))


def load_session() -> Optional[dict]:
    """Return a session-like dict for the currently active user, or None."""
    uid = get_active_session()
    if not uid:
        return None
    return load_user(uid)


def has_session() -> bool:
    return get_active_session() is not None
