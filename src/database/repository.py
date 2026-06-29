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
        username:            str,
        email:               str,
        full_name:           str,
        password_hash:       str,        # Argon2id string — self-contained, no salt param
        signing_public_key:  str | None = None,
        exchange_public_key: str | None = None,
        role:                str = "PATIENT",
    ) -> dict:
        """
        Insert a new user row.

        password_hash must be an Argon2id hash string produced by
        PasswordModule.hash_password().  No separate salt is accepted or
        stored — the salt is embedded in the Argon2id string.

        signing_public_key and exchange_public_key are optional at the DB
        level but required by the registration flow — AuthService validates
        their presence before calling this method.

        Returns the created user as a dict.
        Raises DuplicateError if username or email already exists.
        """
        sql = text("""
            INSERT INTO users
                (username, email, full_name, role, password_hash,
                 signing_public_key, exchange_public_key)
            VALUES
                (:username, :email, :full_name, :role, :password_hash,
                 :signing_public_key, :exchange_public_key)
            RETURNING *
        """)
        try:
            result = await self.db.execute(sql, {
                "username":            username.lower().strip(),
                "email":               email.lower().strip(),
                "full_name":           full_name,
                "role":                role,
                "password_hash":       password_hash,
                "signing_public_key":  signing_public_key,
                "exchange_public_key": exchange_public_key,
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
    # =========================================================================

    async def get_rate_limit(self, key_hash: str, action: str) -> dict | None:
        """
        Get the current rate-limit record for a key+action pair.
        Returns None if no record exists yet.
        """
        result = await self.db.execute(
            text("""
                SELECT * FROM rate_limit
                WHERE key_hash = :key_hash AND action = :action
            """),
            {"key_hash": key_hash, "action": action},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def upsert_rate_limit(self, key_hash: str, action: str) -> dict:
        """
        Increment the attempt counter for a key+action pair.
        Creates the row if it does not exist yet.
        Returns the updated record.
        """
        result = await self.db.execute(
            text("""
                INSERT INTO rate_limit (key_hash, action, attempts, first_attempt, last_attempt)
                VALUES (:key_hash, :action, 1, :now, :now)
                ON CONFLICT (key_hash, action)
                DO UPDATE SET
                    attempts     = rate_limit.attempts + 1,
                    last_attempt = :now
                RETURNING *
            """),
            {"key_hash": key_hash, "action": action, "now": _now()},
        )
        await self.db.commit()
        return dict(result.mappings().one())

    async def set_rate_limit_block(
        self,
        key_hash:      str,
        action:        str,
        blocked_until: datetime,
    ) -> None:
        """
        Set the blocked_until timestamp on a rate-limit record.
        Called after the failure threshold is crossed.
        Raises RecordNotFoundError if no record exists for this key+action.
        """
        result = await self.db.execute(
            text("""
                UPDATE rate_limit
                SET blocked_until = :blocked_until
                WHERE key_hash = :key_hash AND action = :action
            """),
            {"key_hash": key_hash, "action": action, "blocked_until": blocked_until},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"No rate limit record for key '{key_hash}' action '{action}'.")

    async def reset_rate_limit(self, key_hash: str, action: str) -> None:
        """
        Delete the rate-limit record for a key+action pair.
        Called on successful login. Noop if record does not exist.
        """
        await self.db.execute(
            text("""
                DELETE FROM rate_limit
                WHERE key_hash = :key_hash AND action = :action
            """),
            {"key_hash": key_hash, "action": action},
        )
        await self.db.commit()

    async def cleanup_old_rate_limits(self, older_than: datetime) -> int:
        """
        Delete rate-limit rows that haven't been touched since older_than.
        Returns count deleted.
        """
        result = await self.db.execute(
            text("""
                DELETE FROM rate_limit
                WHERE last_attempt < :older_than AND blocked_until IS NULL
            """),
            {"older_than": older_than},
        )
        await self.db.commit()
        return result.rowcount

    # =========================================================================
    # SHARES
    # =========================================================================

    async def create_share(
        self,
        share_id:         str,
        short_code:       str,
        owner_id_hex:     str,
        grantee_id_hex:   str | None,
        encrypted_data:   str,
        expires_at:       datetime | None = None,
        max_retrievals:   int = 1,
    ) -> dict:
        """
        Create a new share record.
        Raises DuplicateError if share_id or short_code already exists.
        """
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO active_shares
                        (share_id, short_code, owner_id_hex, grantee_id_hex,
                         encrypted_data, expires_at, max_retrievals, retrieval_count, status)
                    VALUES
                        (:share_id, :short_code, :owner_id_hex, :grantee_id_hex,
                         :encrypted_data, :expires_at, :max_retrievals, 0, 'active')
                    RETURNING *
                """),
                {
                    "share_id":       share_id,
                    "short_code":     short_code,
                    "owner_id_hex":   owner_id_hex,
                    "grantee_id_hex": grantee_id_hex,
                    "encrypted_data": encrypted_data,
                    "expires_at":     expires_at,
                    "max_retrievals": max_retrievals,
                },
            )
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_share_by_id(self, share_id: str) -> dict | None:
        """Get a share by its UUID. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM active_shares WHERE share_id = :sid"),
            {"sid": share_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def get_share_by_short_code(self, short_code: str) -> dict | None:
        """Get an active share by its short retrieval code. Returns None if not found."""
        result = await self.db.execute(
            text("""
                SELECT * FROM active_shares
                WHERE short_code = :code
                  AND status = 'active'
            """),
            {"code": short_code},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def mark_share_retrieved(self, share_id: str) -> dict:
        """
        Increment retrieval_count; set status='retrieved' if max reached.
        Raises RecordNotFoundError if share does not exist.
        """
        result = await self.db.execute(
            text("""
                UPDATE active_shares
                SET
                    retrieval_count = retrieval_count + 1,
                    retrieved_at    = COALESCE(retrieved_at, :now),
                    status = CASE
                        WHEN retrieval_count + 1 >= max_retrievals THEN 'retrieved'
                        ELSE status
                    END
                WHERE share_id = :sid
                RETURNING *
            """),
            {"sid": share_id, "now": _now()},
        )
        await self.db.commit()
        row = result.mappings().first()
        if not row:
            raise RecordNotFoundError(f"Share '{share_id}' not found.")
        return dict(row)

    async def update_share_status(self, share_id: str, status: str) -> None:
        """
        Set a share's status directly (e.g. 'expired', 'revoked').
        Raises RecordNotFoundError if share does not exist.
        """
        result = await self.db.execute(
            text("UPDATE active_shares SET status = :status WHERE share_id = :sid"),
            {"status": status, "sid": share_id},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Share '{share_id}' not found.")

    async def get_shares_by_owner(
        self,
        owner_id_hex: str,
        skip:  int = 0,
        limit: int = 100,
    ) -> list[dict]:
        """Return all shares created by a user, newest first."""
        result = await self.db.execute(
            text("""
                SELECT * FROM active_shares
                WHERE owner_id_hex = :owner
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :skip
            """),
            {"owner": owner_id_hex, "limit": limit, "skip": skip},
        )
        return [dict(r) for r in result.mappings()]

    async def get_shares_by_grantee(
        self,
        grantee_id_hex: str,
        skip:  int = 0,
        limit: int = 100,
    ) -> list[dict]:
        """Return all shares targeted at a specific user, newest first."""
        result = await self.db.execute(
            text("""
                SELECT * FROM active_shares
                WHERE grantee_id_hex = :grantee
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :skip
            """),
            {"grantee": grantee_id_hex, "limit": limit, "skip": skip},
        )
        return [dict(r) for r in result.mappings()]

    async def expire_old_shares(self) -> int:
        """
        Mark all past-expiry active shares as 'expired'.
        Returns count updated.
        """
        result = await self.db.execute(
            text("""
                UPDATE active_shares
                SET status = 'expired'
                WHERE expires_at < :now AND status = 'active'
            """),
            {"now": _now()},
        )
        await self.db.commit()
        return result.rowcount

    # =========================================================================
    # SHARE ACCESS LOG
    # =========================================================================

    async def append_share_access(
        self,
        share_id:   str,
        accessor_id_hex: str | None,
        ip_address: str | None = None,
        action:     str = "retrieved",
    ) -> None:
        """Log a share access event. Never updates existing rows."""
        await self.db.execute(
            text("""
                INSERT INTO share_access_log
                    (share_id, accessor_id_hex, ip_address, action, accessed_at)
                VALUES
                    (:share_id, :accessor_id_hex, :ip_address, :action, :now)
            """),
            {
                "share_id":        share_id,
                "accessor_id_hex": accessor_id_hex,
                "ip_address":      ip_address,
                "action":          action,
                "now":             _now(),
            },
        )
        await self.db.commit()

    async def get_share_access_log(
        self,
        share_id: str,
        limit:    int = 100,
    ) -> list[dict]:
        """Return access log entries for a share, newest first."""
        result = await self.db.execute(
            text("""
                SELECT * FROM share_access_log
                WHERE share_id = :sid
                ORDER BY accessed_at DESC
                LIMIT :limit
            """),
            {"sid": share_id, "limit": limit},
        )
        return [dict(r) for r in result.mappings()]

    # =========================================================================
    # VAULT RECORDS
    # =========================================================================

    async def create_vault_record(
        self,
        record_id:            str,
        owner_key_hash:       str,
        owner_user_id_hex:    str,
        owner_public_key_hex: str,
        filename:             str,
        mime_type:            str,
        size_bytes:           int,
        iv_hex:               str,
        tags:                 list | None = None,
    ) -> dict:
        """
        Create a vault record. Raises DuplicateError if record_id already exists.
        """
        import json as _json
        tags_str = _json.dumps(tags or [])
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO vault_records
                        (record_id, owner_key_hash, owner_user_id_hex, owner_public_key_hex,
                         filename, mime_type, size_bytes, iv_hex, tags)
                    VALUES
                        (:record_id, :owner_key_hash, :owner_user_id_hex, :owner_public_key_hex,
                         :filename, :mime_type, :size_bytes, :iv_hex, :tags)
                    RETURNING *
                """),
                {
                    "record_id":            record_id,
                    "owner_key_hash":       owner_key_hash,
                    "owner_user_id_hex":    owner_user_id_hex,
                    "owner_public_key_hex": owner_public_key_hex,
                    "filename":             filename,
                    "mime_type":            mime_type,
                    "size_bytes":           size_bytes,
                    "iv_hex":               iv_hex,
                    "tags":                 tags_str,
                },
            )
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_vault_record(self, record_id: str) -> dict | None:
        """Get a vault record header by ID. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM vault_records WHERE record_id = :rid"),
            {"rid": record_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def list_vault_records(
        self,
        owner_user_id_hex: str,
        skip:              int = 0,
        limit:             int = 100,
    ) -> list[dict]:
        """List vault records for an owner, newest first."""
        result = await self.db.execute(
            text("""
                SELECT * FROM vault_records
                WHERE owner_user_id_hex = :owner
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :skip
            """),
            {"owner": owner_user_id_hex, "limit": limit, "skip": skip},
        )
        return [dict(r) for r in result.mappings()]

    async def delete_vault_record(self, record_id: str) -> None:
        """
        Delete a vault record and its associated ciphertext (CASCADE expected in schema).
        Raises RecordNotFoundError if record does not exist.
        """
        result = await self.db.execute(
            text("DELETE FROM vault_records WHERE record_id = :rid"),
            {"rid": record_id},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Vault record '{record_id}' not found.")

    # =========================================================================
    # VAULT CIPHERTEXT
    # =========================================================================

    async def create_vault_ciphertext(
        self,
        record_id:   str,
        ciphertext:  bytes | str,
        dek_bundle:  str = "",
    ) -> dict:
        """
        Store encrypted ciphertext for a vault record.
        Raises DuplicateError if record_id already has ciphertext.
        """
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO vault_ciphertext (record_id, ciphertext, dek_bundle)
                    VALUES (:record_id, :ciphertext, :dek_bundle)
                    RETURNING *
                """),
                {
                    "record_id":  record_id,
                    "ciphertext": ciphertext,
                    "dek_bundle": dek_bundle,
                },
            )
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_vault_ciphertext(self, record_id: str) -> dict | None:
        """Get the ciphertext for a vault record. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM vault_ciphertext WHERE record_id = :rid"),
            {"rid": record_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    # =========================================================================
    # GRANTS
    # =========================================================================

    async def create_grant(
        self,
        grant_id:              str,
        record_id:             str,
        grantor_key_hash:      str,
        grantee_key_hash:      str,
        grantee_public_key_hex: str,
        permission_level:      str = "view_only",
        time_start:            datetime | None = None,
        time_end:              datetime | None = None,
        dek_bundle_grantee:    str = "",
        signature_hex:         str = "",
        grantee_user_id_hex:   str | None = None,
    ) -> dict:
        """
        Create an access grant for a vault record.
        Raises DuplicateError if grant_id already exists.
        """
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO grants
                        (grant_id, record_id, grantor_key_hash, grantee_key_hash,
                         grantee_user_id_hex, grantee_public_key_hex, permission_level,
                         time_start, time_end, dek_bundle_grantee, signature_hex)
                    VALUES
                        (:grant_id, :record_id, :grantor_key_hash, :grantee_key_hash,
                         :grantee_user_id_hex, :grantee_public_key_hex, :permission_level,
                         :time_start, :time_end, :dek_bundle_grantee, :signature_hex)
                    RETURNING *
                """),
                {
                    "grant_id":               grant_id,
                    "record_id":              record_id,
                    "grantor_key_hash":       grantor_key_hash,
                    "grantee_key_hash":       grantee_key_hash,
                    "grantee_user_id_hex":    grantee_user_id_hex,
                    "grantee_public_key_hex": grantee_public_key_hex,
                    "permission_level":       permission_level,
                    "time_start":             time_start or _now(),
                    "time_end":               time_end,
                    "dek_bundle_grantee":     dek_bundle_grantee,
                    "signature_hex":          signature_hex,
                },
            )
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_grant(self, grant_id: str) -> dict | None:
        """Get a grant by ID. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM grants WHERE grant_id = :gid"),
            {"gid": grant_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def revoke_grant(self, grant_id: str) -> None:
        """
        Revoke a grant by setting revoked=1 and revoked_at timestamp.
        Raises RecordNotFoundError if grant does not exist.
        """
        result = await self.db.execute(
            text("""
                UPDATE grants
                SET revoked = 1, revoked_at = :now
                WHERE grant_id = :gid
            """),
            {"gid": grant_id, "now": _now()},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Grant '{grant_id}' not found.")

    async def mark_grant_retrieved(self, grant_id: str) -> None:
        """Record that a grantee has retrieved the encrypted key for a grant."""
        result = await self.db.execute(
            text("""
                UPDATE grants
                SET retrieved_at = COALESCE(retrieved_at, :now)
                WHERE grant_id = :gid
            """),
            {"gid": grant_id, "now": _now()},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Grant '{grant_id}' not found.")

    async def get_grants_for_record(
        self,
        record_id: str,
        active_only: bool = True,
    ) -> list[dict]:
        """Return all grants for a vault record."""
        where = "WHERE record_id = :rid"
        if active_only:
            where += " AND revoked = 0"
        result = await self.db.execute(
            text(f"SELECT * FROM grants {where} ORDER BY created_at DESC"),
            {"rid": record_id},
        )
        return [dict(r) for r in result.mappings()]

    async def get_grants_by_grantor(
        self,
        grantor_key_hash: str,
        active_only:      bool = True,
        skip:             int  = 0,
        limit:            int  = 100,
    ) -> list[dict]:
        """Return grants issued by a key hash."""
        where = "WHERE grantor_key_hash = :grantor"
        if active_only:
            where += " AND revoked = 0"
        result = await self.db.execute(
            text(f"""
                SELECT * FROM grants {where}
                ORDER BY created_at DESC LIMIT :limit OFFSET :skip
            """),
            {"grantor": grantor_key_hash, "limit": limit, "skip": skip},
        )
        return [dict(r) for r in result.mappings()]

    async def get_grants_by_grantee(
        self,
        grantee_key_hash: str,
        active_only:      bool = True,
        skip:             int  = 0,
        limit:            int  = 100,
    ) -> list[dict]:
        """Return grants received by a key hash."""
        where = "WHERE grantee_key_hash = :grantee"
        if active_only:
            where += " AND revoked = 0"
        result = await self.db.execute(
            text(f"""
                SELECT * FROM grants {where}
                ORDER BY created_at DESC LIMIT :limit OFFSET :skip
            """),
            {"grantee": grantee_key_hash, "limit": limit, "skip": skip},
        )
        return [dict(r) for r in result.mappings()]

    # =========================================================================
    # AUDIT LOG
    # =========================================================================

    async def append_audit_log(
        self,
        action:           str,
        actor_user_id_hex: str | None = None,
        ip_address:       str | None = None,
        user_agent:       str | None = None,
        detail:           str | None = None,
        share_id:         str | None = None,
    ) -> None:
        """Append an auth/system audit event. Never updates existing rows."""
        import json as _json
        detail_str = _json.dumps(detail) if isinstance(detail, (dict, list)) else detail
        await self.db.execute(
            text("""
                INSERT INTO audit_log
                    (actor_user_id_hex, action, share_id, detail, ip_address, user_agent)
                VALUES
                    (:actor_user_id_hex, :action, :share_id, :detail, :ip_address, :user_agent)
            """),
            {
                "actor_user_id_hex": actor_user_id_hex,
                "action":            action,
                "share_id":          share_id,
                "detail":            detail_str,
                "ip_address":        ip_address,
                "user_agent":        user_agent,
            },
        )
        await self.db.commit()

    async def get_audit_log(
        self,
        actor_user_id_hex: str | None = None,
        action:            str | None = None,
        skip:              int = 0,
        limit:             int = 100,
    ) -> list[dict]:
        """
        Query the audit log with optional filters.
        Returns entries newest first.
        """
        conditions = []
        params: dict = {"limit": limit, "skip": skip}
        if actor_user_id_hex:
            conditions.append("actor_user_id_hex = :actor_user_id_hex")
            params["actor_user_id_hex"] = actor_user_id_hex
        if action:
            conditions.append("action = :action")
            params["action"] = action
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        result = await self.db.execute(
            text(f"""
                SELECT * FROM audit_log {where}
                ORDER BY timestamp DESC LIMIT :limit OFFSET :skip
            """),
            params,
        )
        return [dict(r) for r in result.mappings()]

    # =========================================================================
    # VAULT AUDIT
    # =========================================================================

    async def append_vault_audit(
        self,
        action:           str,
        actor_key_hash:   str = "",
        record_id:        str = "",
        actor_user_id_hex: str | None = None,
        share_id:         str | None = None,
        detail:           str = "",
        ip_address:       str | None = None,
        user_agent:       str | None = None,
    ) -> None:
        """Append a vault-specific audit event. Never updates existing rows."""
        await self.db.execute(
            text("""
                INSERT INTO vault_audit
                    (action, actor_key_hash, actor_user_id_hex, record_id,
                     share_id, detail, ip_address, user_agent)
                VALUES
                    (:action, :actor_key_hash, :actor_user_id_hex, :record_id,
                     :share_id, :detail, :ip_address, :user_agent)
            """),
            {
                "action":            action,
                "actor_key_hash":    actor_key_hash,
                "actor_user_id_hex": actor_user_id_hex,
                "record_id":         record_id,
                "share_id":          share_id,
                "detail":            detail,
                "ip_address":        ip_address,
                "user_agent":        user_agent,
            },
        )
        await self.db.commit()

    async def get_vault_audit(
        self,
        record_id:      str | None = None,
        actor_key_hash: str | None = None,
        limit:          int = 100,
    ) -> list[dict]:
        """Return vault audit events, filtered by record_id and/or actor_key_hash, newest first."""
        conditions = []
        params: dict = {"limit": limit}
        if record_id:
            conditions.append("record_id = :record_id")
            params["record_id"] = record_id
        if actor_key_hash:
            conditions.append("actor_key_hash = :actor_key_hash")
            params["actor_key_hash"] = actor_key_hash
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        result = await self.db.execute(
            text(f"""
                SELECT * FROM vault_audit {where}
                ORDER BY timestamp DESC LIMIT :limit
            """),
            params,
        )
        return [dict(r) for r in result.mappings()]

    # =========================================================================
    # MAINTENANCE
    # =========================================================================

    async def run_full_cleanup(self) -> dict:
        """
        Run all cleanup tasks in one call.
        Returns a dict with counts of rows deleted/updated per table.
        Safe to call on a schedule (e.g. nightly cron).
        """
        return {
            "expired_pow_challenges":    await self.cleanup_expired_pow(),
            "expired_refresh_tokens":    await self.cleanup_expired_refresh_tokens(),
            "expired_jtis":              await self.cleanup_expired_jtis(),
            "expired_shares":            await self.expire_old_shares(),
        }
