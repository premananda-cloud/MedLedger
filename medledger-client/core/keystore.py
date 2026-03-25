"""
core/keystore.py - Local key and session storage using SQLite.

Security model:
  - Private keys are encrypted at rest with AES-256-GCM before writing to SQLite.
  - The encryption key is derived from the user's login password via PBKDF2-HMAC-SHA256
    (310,000 iterations, random 32-byte salt stored alongside the ciphertext).
  - The plaintext private key is only held in memory while the user is logged in
    and is cleared on logout.
  - The DB file itself is stored in keys/medledger.db which is git-ignored.

Key storage format (stored as JSON in the private_key_enc column):
  { "salt": "<hex>", "iv": "<hex>", "ct": "<hex>", "tag": "<hex>" }
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from config import KEYS_DIR

# ── Private-key encryption helpers ───────────────────────────────────────────
# The raw private key scalar is never written to disk unencrypted.
# Each key is wrapped with AES-256-GCM using a PBKDF2-derived key.

def _derive_wrapping_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a user password via PBKDF2-HMAC-SHA256."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=310_000,        # OWASP 2023 recommendation for PBKDF2-SHA256
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(priv_hex: str, password: str) -> str:
    """Encrypt a 64-char hex private key with the user's password. Returns JSON string."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(32)
    iv   = os.urandom(12)
    key  = _derive_wrapping_key(password, salt)
    ct   = AESGCM(key).encrypt(iv, priv_hex.encode("utf-8"), None)
    return json.dumps({
        "salt": salt.hex(),
        "iv":   iv.hex(),
        "ct":   ct[:-16].hex(),
        "tag":  ct[-16:].hex(),
    })


def decrypt_private_key(enc_json: str, password: str) -> str:
    """Decrypt an encrypted private key blob. Returns 64-char hex string.
    Raises ValueError on wrong password or tampered data.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        bundle = json.loads(enc_json)
        salt   = bytes.fromhex(bundle["salt"])
        iv     = bytes.fromhex(bundle["iv"])
        ct     = bytes.fromhex(bundle["ct"])
        tag    = bytes.fromhex(bundle["tag"])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Malformed key bundle: {exc}") from exc

    key = _derive_wrapping_key(password, salt)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        plaintext = AESGCM(key).decrypt(iv, ct + tag, None)
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise ValueError("Wrong password or corrupted key data") from exc

DB_PATH = KEYS_DIR / "medledger.db"


# ── DB bootstrap ──────────────────────────────────────────────────────────────

def _init_db():
    with _conn() as cx:
        cx.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id          TEXT PRIMARY KEY,  -- server int OR offline_xxx string
                username         TEXT NOT NULL,
                email            TEXT NOT NULL,
                full_name        TEXT,
                role             TEXT NOT NULL,
                private_key_enc  TEXT NOT NULL,     -- AES-256-GCM encrypted key bundle (JSON)
                public_key_hex   TEXT NOT NULL,     -- 130 hex chars (uncompressed)
                public_key_hash  TEXT NOT NULL,     -- 64 hex chars (SHA-256 of pub)
                token            TEXT,              -- JWT (null if offline)
                created_at       TEXT
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
    password: str,              # required — used to encrypt the private key at rest
    token: Optional[str] = None,
    created_at: Optional[str] = None,
):
    """Insert or update a user record. Private key is encrypted before writing."""
    enc_blob = encrypt_private_key(private_key_hex, password)
    with _conn() as cx:
        cx.execute("""
            INSERT INTO users
              (user_id, username, email, full_name, role,
               private_key_enc, public_key_hex, public_key_hash, token, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              token           = excluded.token,
              full_name       = excluded.full_name,
              private_key_enc = excluded.private_key_enc
        """, (str(user_id), username, email, full_name, role,
              enc_blob, public_key_hex, public_key_hash,
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


def load_private_key_hex(user_id, password: str) -> str:
    """Decrypt and return the private key hex for user_id.
    Raises FileNotFoundError if user not found.
    Raises ValueError if password is wrong or key data is corrupted.
    """
    row = load_user(str(user_id))
    if not row:
        raise FileNotFoundError(
            f"No local key found for user {user_id}. "
            "Did you register on this device?"
        )
    return decrypt_private_key(row["private_key_enc"], password)


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
