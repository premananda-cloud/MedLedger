"""
src/services/auth_service.py
JWT creation/validation, Argon2id password hashing, refresh-token management.
"""
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from jose import JWTError, jwt

from src.services.config import get_settings
from src.services.database import DB

logger = logging.getLogger("medledger.auth")

_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plaintext: str) -> str:
    return _ph.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id_hex: str, username: str) -> str:
    settings = get_settings()
    jti = secrets.token_hex(16)
    payload = {
        "sub": user_id_hex,
        "username": username,
        "jti": jti,
        "exp": _now() + timedelta(minutes=settings.access_token_expire_minutes),
        "iat": _now(),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


async def is_token_revoked(jti: str) -> bool:
    async with DB() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM token_revocations WHERE token_jti = $1", jti
        )
    return row is not None


async def revoke_token(jti: str, user_id_hex: str, expires_at: datetime) -> None:
    async with DB() as conn:
        await conn.execute(
            """
            INSERT INTO token_revocations (token_jti, user_id_hex, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (token_jti) DO NOTHING
            """,
            jti, user_id_hex, expires_at,
        )


# ── Refresh tokens ────────────────────────────────────────────────────────────

def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def create_refresh_token(user_id_hex: str) -> str:
    settings = get_settings()
    raw = secrets.token_hex(32)
    token_hash = _hash_token(raw)
    family_id = secrets.token_hex(16)
    expires_at = _now() + timedelta(days=settings.refresh_token_expire_days)
    async with DB() as conn:
        await conn.execute(
            """
            INSERT INTO refresh_tokens (token_hash, user_id_hex, family_id, expires_at)
            VALUES ($1, $2, $3, $4)
            """,
            token_hash, user_id_hex, family_id, expires_at,
        )
    return raw


async def rotate_refresh_token(raw: str) -> tuple[str, str] | None:
    """Validates and rotates a refresh token. Returns (new_raw, user_id_hex) or None."""
    settings = get_settings()
    token_hash = _hash_token(raw)
    async with DB() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, user_id_hex, expires_at, revoked_at
            FROM refresh_tokens
            WHERE token_hash = $1
            """,
            token_hash,
        )
        if not row:
            return None
        if row["revoked_at"] or row["expires_at"] < _now():
            # Possible token theft — revoke entire family
            await conn.execute(
                "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id_hex = $1",
                row["user_id_hex"],
            )
            return None

        new_raw = secrets.token_hex(32)
        new_hash = _hash_token(new_raw)
        new_expires = _now() + timedelta(days=settings.refresh_token_expire_days)

        await conn.execute(
            "UPDATE refresh_tokens SET revoked_at = NOW(), replaced_by_token_hash = $1 WHERE id = $2",
            new_hash, row["id"],
        )
        await conn.execute(
            """
            INSERT INTO refresh_tokens (token_hash, user_id_hex, family_id, expires_at)
            VALUES ($1, $2, $3, $4)
            """,
            new_hash, row["user_id_hex"],
            (await conn.fetchval("SELECT family_id FROM refresh_tokens WHERE id = $1", row["id"])) or secrets.token_hex(16),
            new_expires,
        )
        return new_raw, row["user_id_hex"]


async def revoke_all_refresh_tokens(user_id_hex: str) -> None:
    async with DB() as conn:
        await conn.execute(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id_hex = $1 AND revoked_at IS NULL",
            user_id_hex,
        )
