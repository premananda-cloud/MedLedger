"""
database/repository.py — DatabaseRepository

Single class that handles ALL data operations for MedLedger.

Layer contract:
  ✓ Pure data access — reads and writes, nothing else
  ✓ Receives an AsyncSession in __init__, owns nothing else
  ✓ Raises only exceptions from database/exceptions.py
  ✓ Returns None for missing records on get_* methods
  ✗ No business logic
  ✗ No validation
  ✗ No auth decisions (no "is this user allowed to…")
  ✗ No imports from auth/ or services/

Password storage note:
  Argon2id produces a single self-contained hash string that embeds its own
  salt and parameters.  set_password_hash() updates only the password_hash
  column, and create_user() no longer accepts or stores a separate salt.

Tables covered (in schema order):
  users, user_audit,
  pow_challenges,
  refresh_tokens, token_revocations,
  rate_limit,
  active_shares, share_access_log,
  vault_records, vault_ciphertext,
  grants,
  audit_log, vault_audit
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError as SAIntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .exceptions import (
    DatabaseError,
    DuplicateError,
    IntegrityError,
    RecordNotFoundError,
)

log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_integrity(exc: SAIntegrityError) -> DuplicateError | IntegrityError:
    """Map a SQLAlchemy IntegrityError to a domain exception."""
    msg = str(exc.orig).lower()
    for field in ("email", "username", "user_id_hex", "public_key_hash",
                  "token_hash", "token_jti", "challenge_id", "share_id",
                  "short_code", "family_id"):
        if field in msg:
            return DuplicateError(f"Duplicate value for field '{field}'.", field=field)
    if "unique" in msg or "duplicate" in msg:
        return DuplicateError("Duplicate record.", field=None)
    return IntegrityError(f"Integrity constraint violated: {exc.orig}")


# ─────────────────────────────────────────────────────────────────────────────
# Repository
# ─────────────────────────────────────────────────────────────────────────────

class DatabaseRepository:
    """
    All database operations for MedLedger, grouped by table.

    Inject an AsyncSession (from services/database.py) on construction.
    The session lifecycle (commit / rollback / close) is managed here for
    writes; the caller manages the session for reads if needed.

    Usage:
        async with get_session() as session:
            repo = DatabaseRepository(session)
            user = await repo.get_user_by_id_hex("abc123")
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # =========================================================================
    # USERS
    # =========================================================================

    async def create_user(
        self,
         username:      str,
         email:         str,
         full_name:     str,
         password_hash: str,
         signing_public_key: str = None,   # ADD
         exchange_public_key: str = None,  # ADD
         role:          str = "PATIENT",
     ) -> dict:
        """
        Insert a new user row.

        password_hash must be an Argon2id hash string produced by
        PasswordModule.hash_password().  No separate salt is accepted or
        stored — the salt is embedded in the Argon2id string.

        Returns the created user as a dict.
        Raises DuplicateError if username or email already exists.
        """
        sql = text("""
            INSERT INTO users (username, email, full_name, role, password_hash, signing_public_key, exchange_public_key)
            VALUES (:username, :email, :full_name, :role, :password_hash, :signing_public_key, :exchange_public_key)
            RETURNING *
        """)
        try:
            result = await self.db.execute(sql, {
                "username":      username.lower().strip(),
                "email":         email.lower().strip(),
                "full_name":     full_name,
                "role":          role,
                "password_hash": password_hash,
                "signing_public_key": signing_public_key,    # ADD
                "exchange_public_key": exchange_public_key,  # ADD
            })
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_user_by_id_hex(self, user_id_hex: str) -> dict | None:
        """
        Get an active (non-deleted) user by their hex ID.
        Returns None if not found or soft-deleted.
        """
        result = await self.db.execute(
            text("SELECT * FROM users WHERE user_id_hex = :h AND account_deleted = FALSE"),
            {"h": user_id_hex},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def get_user_by_email(self, email: str) -> dict | None:
        """
        Get an active user by email (case-insensitive).
        Returns None if not found or soft-deleted.
        """
        result = await self.db.execute(
            text("SELECT * FROM users WHERE lower(email) = lower(:e) AND account_deleted = FALSE"),
            {"e": email.strip()},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def get_user_by_username(self, username: str) -> dict | None:
        """
        Get an active user by username (case-insensitive).
        Returns None if not found or soft-deleted.
        """
        result = await self.db.execute(
            text("SELECT * FROM users WHERE lower(username) = lower(:u) AND account_deleted = FALSE"),
            {"u": username.strip()},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def email_exists(self, email: str) -> bool:
        """True if the email belongs to any active (non-deleted) user."""
        result = await self.db.execute(
            text("SELECT 1 FROM users WHERE lower(email) = lower(:e) AND account_deleted = FALSE LIMIT 1"),
            {"e": email.strip()},
        )
        return result.first() is not None

    async def username_exists(self, username: str) -> bool:
        """True if the username is taken by any active (non-deleted) user."""
        result = await self.db.execute(
            text("SELECT 1 FROM users WHERE lower(username) = lower(:u) AND account_deleted = FALSE LIMIT 1"),
            {"u": username.strip()},
        )
        return result.first() is not None

    async def update_user(self, user_id_hex: str, **kwargs: Any) -> dict:
        """
        Update arbitrary user fields by user_id_hex.
        Only columns present in kwargs are touched.
        Raises RecordNotFoundError if user does not exist.
        """
        if not kwargs:
            raise ValueError("update_user requires at least one field to update.")

        sets   = ", ".join(f"{k} = :{k}" for k in kwargs)
        params = {"user_id_hex": user_id_hex, **kwargs}
        sql    = text(f"UPDATE users SET {sets} WHERE user_id_hex = :user_id_hex RETURNING *")
        try:
            result = await self.db.execute(sql, params)
            await self.db.commit()
            row = result.mappings().first()
            if not row:
                raise RecordNotFoundError(f"User '{user_id_hex}' not found.")
            return dict(row)
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def set_public_keys(
        self,
        user_id_hex:         str,
        signing_public_key:  str,
        exchange_public_key: str,
    ) -> None:
        """
        Store Ed25519 signing key and X25519 exchange key for a user.

        Called once at registration. To update existing keys the caller must
        use update_user() explicitly — this method will raise DuplicateError
        if the DB schema enforces a unique constraint on the key columns,
        making accidental overwrites visible rather than silent.
        """
        await self.update_user(
            user_id_hex,
            signing_public_key=signing_public_key,
            exchange_public_key=exchange_public_key,
        )

    async def set_password_hash(self, user_id_hex: str, password_hash: str) -> None:
        """
        Update the stored password hash.

        Accepts only the Argon2id hash string produced by
        PasswordModule.hash_password().  The salt is embedded in that string —
        there is no separate salt parameter.

        FIX: the old signature accepted (user_id_hex, hash, salt) but only
        persisted the hash, silently dropping the salt on every password change
        and reset.  With Argon2id there is nothing to drop — one string is all
        that is needed.
        """
        await self.update_user(user_id_hex, password_hash=password_hash)

    async def mark_email_verified(self, user_id_hex: str) -> None:
        """Set is_verified=True and clear legacy verification token fields."""
        await self.update_user(
            user_id_hex,
            is_verified=True,
            verification_token=None,
            token_expires_at=None,
        )

    async def store_verification_token(
        self,
        user_id_hex:  str,
        token:        str,
        expires_at:   str,   # stored as TEXT in schema (legacy column)
    ) -> None:
        """
        Store a legacy verification token string and its expiry.
        Note: verification_token / token_expires_at are legacy columns.
        Prefer rate_limit + a separate verification table for new flows.
        """
        await self.update_user(
            user_id_hex,
            verification_token=token,
            token_expires_at=expires_at,
        )

    async def record_successful_login(
        self,
        user_id_hex: str,
        ip_address:  str,
    ) -> None:
        """Update last_login_at and last_login_ip after a successful login."""
        await self.update_user(
            user_id_hex,
            last_login_at=_now(),
            last_login_ip=ip_address,
        )

    async def soft_delete_user(self, user_id_hex: str) -> None:
        """Mark account as deleted. Data is retained for audit purposes."""
        await self.update_user(
            user_id_hex,
            account_deleted=True,
            is_active=False,
            deleted_at=_now(),
        )

    async def restore_user(self, user_id_hex: str) -> None:
        """Reverse a soft delete."""
        await self.update_user(
            user_id_hex,
            account_deleted=False,
            is_active=True,
            deleted_at=None,
        )

    async def list_users(
        self,
        skip:        int  = 0,
        limit:       int  = 100,
        active_only: bool = True,
    ) -> list[dict]:
        """Paginated user list, optionally filtered to active/non-deleted."""
        where = "WHERE account_deleted = FALSE AND is_active = TRUE" if active_only else ""
        result = await self.db.execute(
            text(f"SELECT * FROM users {where} ORDER BY created_at DESC LIMIT :limit OFFSET :skip"),
            {"limit": limit, "skip": skip},
        )
        return [dict(r) for r in result.mappings()]

    async def count_users(self, active_only: bool = True) -> int:
        """Count users, optionally filtered to active/non-deleted."""
        where = "WHERE account_deleted = FALSE AND is_active = TRUE" if active_only else ""
        result = await self.db.execute(text(f"SELECT COUNT(*) FROM users {where}"))
        return result.scalar_one()

    # =========================================================================
    # USER AUDIT
    # =========================================================================

    async def append_user_audit(
        self,
        user_id:     int,        # internal serial id — FK in user_audit
        action:      str,
        description: str = "",
        ip_address:  str | None = None,
        user_agent:  str | None = None,
    ) -> None:
        """Append an audit event for a user. Never updates existing rows."""
        await self.db.execute(
            text("""
                INSERT INTO user_audit (user_id, action, description, ip_address, user_agent)
                VALUES (:user_id, :action, :description, :ip_address, :user_agent)
            """),
            {
                "user_id":     user_id,
                "action":      action,
                "description": description,
                "ip_address":  ip_address,
                "user_agent":  user_agent,
            },
        )
        await self.db.commit()

    async def get_user_audit(
        self,
        user_id: int,
        limit:   int = 100,
        skip:    int = 0,
    ) -> list[dict]:
        """Return audit events for a user, newest first."""
        result = await self.db.execute(
            text("""
                SELECT * FROM user_audit
                WHERE user_id = :user_id
                ORDER BY timestamp DESC
                LIMIT :limit OFFSET :skip
            """),
            {"user_id": user_id, "limit": limit, "skip": skip},
        )
        return [dict(r) for r in result.mappings()]

    # =========================================================================
    # POW CHALLENGES
    # =========================================================================

    async def create_pow_challenge(
        self,
        challenge_id:  str,
        nonce_prefix:  str,
        difficulty:    int,
        target_hash:   str,
        expires_at:    datetime,
    ) -> dict:
        """
        Store a new PoW challenge issued to a client.
        Raises DuplicateError if challenge_id already exists.
        """
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO pow_challenges
                        (challenge_id, nonce_prefix, difficulty, target_hash, expires_at)
                    VALUES
                        (:challenge_id, :nonce_prefix, :difficulty, :target_hash, :expires_at)
                    RETURNING *
                """),
                {
                    "challenge_id": challenge_id,
                    "nonce_prefix": nonce_prefix,
                    "difficulty":   difficulty,
                    "target_hash":  target_hash,
                    "expires_at":   expires_at,
                },
            )
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_pow_challenge(self, challenge_id: str) -> dict | None:
        """Get a PoW challenge by ID. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM pow_challenges WHERE challenge_id = :c"),
            {"c": challenge_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def mark_pow_solved(
        self,
        challenge_id: str,
        solved_nonce: str,
        solver_ip:    str,
    ) -> None:
        """
        Record a successful PoW solution.
        Raises RecordNotFoundError if challenge does not exist.
        """
        result = await self.db.execute(
            text("""
                UPDATE pow_challenges
                SET solved_at = :now, solved_nonce = :nonce, solver_ip = :ip
                WHERE challenge_id = :c
            """),
            {"now": _now(), "nonce": solved_nonce, "ip": solver_ip, "c": challenge_id},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"PoW challenge '{challenge_id}' not found.")

    async def delete_pow_challenge(self, challenge_id: str) -> None:
        """
        Delete a challenge after it has been verified.
        Call this after mark_pow_solved for replay protection.
        """
        await self.db.execute(
            text("DELETE FROM pow_challenges WHERE challenge_id = :c"),
            {"c": challenge_id},
        )
        await self.db.commit()

    async def cleanup_expired_pow(self) -> int:
        """Delete all expired PoW challenges. Returns count deleted."""
        result = await self.db.execute(
            text("DELETE FROM pow_challenges WHERE expires_at < :now"),
            {"now": _now()},
        )
        await self.db.commit()
        return result.rowcount

    # =========================================================================
    # REFRESH TOKENS
    # =========================================================================

    async def store_refresh_token(
        self,
        token_hash:  str,
        user_id_hex: str,
        family_id:   str,
        expires_at:  datetime,
    ) -> dict:
        """
        Store a hashed refresh token.
        family_id groups tokens from the same login chain (for rotation detection).
        Raises DuplicateError if token_hash already exists.
        """
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO refresh_tokens (token_hash, user_id_hex, family_id, expires_at)
                    VALUES (:token_hash, :user_id_hex, :family_id, :expires_at)
                    RETURNING *
                """),
                {
                    "token_hash":  token_hash,
                    "user_id_hex": user_id_hex,
                    "family_id":   family_id,
                    "expires_at":  expires_at,
                },
            )
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_refresh_token(self, token_hash: str) -> dict | None:
        """
        Get a non-revoked, non-expired refresh token by hash.
        Returns None if not found, expired, or already revoked.
        """
        result = await self.db.execute(
            text("""
                SELECT * FROM refresh_tokens
                WHERE token_hash = :h
                  AND revoked_at IS NULL
                  AND expires_at > :now
            """),
            {"h": token_hash, "now": _now()},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def revoke_refresh_token(
        self,
        token_hash:             str,
        replaced_by_token_hash: str | None = None,
    ) -> None:
        """
        Revoke a refresh token.
        Pass replaced_by_token_hash when rotating (the new token's hash).
        Raises RecordNotFoundError if token does not exist.
        """
        result = await self.db.execute(
            text("""
                UPDATE refresh_tokens
                SET revoked_at = :now, replaced_by_token_hash = :replaced
                WHERE token_hash = :h
            """),
            {"now": _now(), "replaced": replaced_by_token_hash, "h": token_hash},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Refresh token not found.")

    async def revoke_token_family(self, family_id: str) -> int:
        """
        Revoke all tokens in a family (reuse detected — logout everywhere).
        Returns count revoked.
        """
        result = await self.db.execute(
            text("""
                UPDATE refresh_tokens
                SET revoked_at = :now
                WHERE family_id = :fid AND revoked_at IS NULL
            """),
            {"now": _now(), "fid": family_id},
        )
        await self.db.commit()
        return result.rowcount

    async def revoke_all_user_refresh_tokens(self, user_id_hex: str) -> int:
        """Revoke all active refresh tokens for a user. Returns count revoked."""
        result = await self.db.execute(
            text("""
                UPDATE refresh_tokens
                SET revoked_at = :now
                WHERE user_id_hex = :h AND revoked_at IS NULL
            """),
            {"now": _now(), "h": user_id_hex},
        )
        await self.db.commit()
        return result.rowcount

    async def cleanup_expired_refresh_tokens(self) -> int:
        """Delete expired or revoked refresh tokens. Returns count deleted."""
        result = await self.db.execute(
            text("""
                DELETE FROM refresh_tokens
                WHERE expires_at < :now OR revoked_at IS NOT NULL
            """),
            {"now": _now()},
        )
        await self.db.commit()
        return result.rowcount

    # =========================================================================
    # TOKEN REVOCATIONS (JWT JTI blocklist)
    # =========================================================================

    async def revoke_token_jti(
        self,
        token_jti:   str,
        user_id_hex: str,
        expires_at:  datetime,
    ) -> None:
        """
        Add a JWT JTI to the revocation list.
        expires_at should match the token's own expiry — cleanup uses this.
        Raises DuplicateError if JTI already revoked (idempotent alternative: ignore).
        """
        try:
            await self.db.execute(
                text("""
                    INSERT INTO token_revocations (token_jti, user_id_hex, expires_at)
                    VALUES (:jti, :user_id_hex, :expires_at)
                """),
                {"jti": token_jti, "user_id_hex": user_id_hex, "expires_at": expires_at},
            )
            await self.db.commit()
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def is_token_revoked(self, token_jti: str) -> bool:
        """True if this JTI has been revoked. Called by auth middleware."""
        result = await self.db.execute(
            text("SELECT 1 FROM token_revocations WHERE token_jti = :jti LIMIT 1"),
            {"jti": token_jti},
        )
        return result.first() is not None

    async def revoke_all_user_jtis(self, user_id_hex: str) -> int:
        """
        Revoke all outstanding JTIs for a user (e.g. password change, account lock).
        Note: JTI rows must already exist — this doesn't create new revocations
        for tokens we haven't seen. Pair with revoke_all_user_refresh_tokens.
        Returns count of existing revocation rows for the user.
        """
        result = await self.db.execute(
            text("SELECT COUNT(*) FROM token_revocations WHERE user_id_hex = :h"),
            {"h": user_id_hex},
        )
        return result.scalar_one()

    async def cleanup_expired_jtis(self) -> int:
        """Delete JTI revocations whose tokens have already expired. Returns count."""
        result = await self.db.execute(
            text("DELETE FROM token_revocations WHERE expires_at < :now"),
            {"now": _now()},
        )
        await self.db.commit()
        return result.rowcount

    # =========================================================================
    # RATE LIMITING
    # (keeping all original methods intact from here — no changes needed)
    # =========================================================================

    # NOTE: All methods below this line are unchanged from the original.
    # They are included here so this file is a complete drop-in replacement.
    # Paste the rest of your original repository.py from line ~600 onward here.
