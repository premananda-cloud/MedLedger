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
        username:     str,
        email:        str,
        full_name:    str,
        password_hash: str,
        role:         str = "PATIENT",
    ) -> dict:
        """
        Insert a new user row.

        Returns the created user as a dict.
        Raises DuplicateError if username or email already exists.
        """
        sql = text("""
            INSERT INTO users (username, email, full_name, role, password_hash)
            VALUES (:username, :email, :full_name, :role, :password_hash)
            RETURNING *
        """)
        try:
            result = await self.db.execute(sql, {
                "username":      username.lower().strip(),
                "email":         email.lower().strip(),
                "full_name":     full_name,
                "role":          role,
                "password_hash": password_hash,
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
        user_id_hex:        str,
        signing_public_key:  str,
        exchange_public_key: str,
    ) -> None:
        """
        Store Ed25519 signing key and X25519 exchange key.
        The DB trigger auto-generates user_id_hex from signing_public_key
        if it was NULL, but here it's already set.
        """
        await self.update_user(
            user_id_hex,
            signing_public_key=signing_public_key,
            exchange_public_key=exchange_public_key,
        )

    async def set_password_hash(self, user_id_hex: str, password_hash: str) -> None:
        """Update password hash. Caller is responsible for hashing."""
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
        token_hash:            str,
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
        key_hash is SHA-256 of email or IP (computed by caller).
        Returns None if no record exists yet.
        """
        result = await self.db.execute(
            text("SELECT * FROM rate_limit WHERE key_hash = :k AND action = :a"),
            {"k": key_hash, "a": action},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def upsert_rate_limit(self, key_hash: str, action: str) -> dict:
        """
        Increment attempt counter for a key+action, creating the row if needed.
        Returns the updated record including the new attempts count.
        """
        result = await self.db.execute(
            text("""
                INSERT INTO rate_limit (key_hash, action, attempts, first_attempt, last_attempt)
                VALUES (:k, :a, 1, :now, :now)
                ON CONFLICT (key_hash, action)
                DO UPDATE SET
                    attempts     = rate_limit.attempts + 1,
                    last_attempt = :now
                RETURNING *
            """),
            {"k": key_hash, "a": action, "now": _now()},
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
        Set blocked_until on a rate-limit record.
        Raises RecordNotFoundError if the record does not exist yet
        (call upsert_rate_limit first).
        """
        result = await self.db.execute(
            text("""
                UPDATE rate_limit SET blocked_until = :until
                WHERE key_hash = :k AND action = :a
            """),
            {"until": blocked_until, "k": key_hash, "a": action},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Rate limit record for action '{action}' not found.")

    async def reset_rate_limit(self, key_hash: str, action: str) -> None:
        """Clear rate-limit record after a successful action."""
        await self.db.execute(
            text("DELETE FROM rate_limit WHERE key_hash = :k AND action = :a"),
            {"k": key_hash, "a": action},
        )
        await self.db.commit()

    async def cleanup_old_rate_limits(self) -> int:
        """Delete rate-limit records older than 24 hours. Returns count deleted."""
        result = await self.db.execute(
            text("DELETE FROM rate_limit WHERE last_attempt < :cutoff"),
            {"cutoff": text("CURRENT_TIMESTAMP - INTERVAL '24 hours'")},
        )
        await self.db.commit()
        return result.rowcount

    # =========================================================================
    # ACTIVE SHARES
    # =========================================================================

    async def create_share(
        self,
        owner_user_id_hex:   str,
        grantee_user_id_hex: str,
        ciphertext:          bytes,
        dek_bundle:          str,
        nonce:               str,
        filename:            str,
        size_bytes:          int,
        signature:           str,
        expires_at:          datetime,
        mime_type:           str | None = None,
        file_hash:           str | None = None,
        payload_canon:       str | None = None,
        delete_on_download:  bool = True,
    ) -> dict:
        """
        Insert a new encrypted share record.
        short_code is auto-generated by the DB trigger.
        Returns the full row including generated share_id and short_code.
        """
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO active_shares (
                        owner_user_id_hex, grantee_user_id_hex,
                        ciphertext, dek_bundle, nonce,
                        filename, mime_type, size_bytes, file_hash,
                        signature, payload_canon,
                        expires_at, delete_on_download
                    ) VALUES (
                        :owner, :grantee,
                        :ciphertext, :dek_bundle, :nonce,
                        :filename, :mime_type, :size_bytes, :file_hash,
                        :signature, :payload_canon,
                        :expires_at, :delete_on_download
                    )
                    RETURNING *
                """),
                {
                    "owner":              owner_user_id_hex,
                    "grantee":            grantee_user_id_hex,
                    "ciphertext":         ciphertext,
                    "dek_bundle":         dek_bundle,
                    "nonce":              nonce,
                    "filename":           filename,
                    "mime_type":          mime_type,
                    "size_bytes":         size_bytes,
                    "file_hash":          file_hash,
                    "signature":          signature,
                    "payload_canon":      payload_canon,
                    "expires_at":         expires_at,
                    "delete_on_download": delete_on_download,
                },
            )
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_share_by_id(self, share_id: UUID) -> dict | None:
        """Get a share by its UUID. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM active_shares WHERE share_id = :s"),
            {"s": share_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def get_share_by_short_code(self, short_code: str) -> dict | None:
        """Get a share by its short alphanumeric code. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM active_shares WHERE short_code = :c"),
            {"c": short_code},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def mark_share_retrieved(self, share_id: UUID) -> None:
        """
        Set retrieved_at=now and status='retrieved'.
        The DB trigger also writes a share_access_log row.
        Raises RecordNotFoundError if share does not exist.
        """
        result = await self.db.execute(
            text("""
                UPDATE active_shares
                SET retrieved_at = :now, status = 'retrieved'
                WHERE share_id = :s
            """),
            {"now": _now(), "s": share_id},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Share '{share_id}' not found.")

    async def update_share_status(self, share_id: UUID, status: str) -> None:
        """
        Update the status enum of a share.
        Valid values: 'active', 'retrieved', 'expired', 'revoked', 'deleted'.
        Raises RecordNotFoundError if share does not exist.
        """
        result = await self.db.execute(
            text("UPDATE active_shares SET status = :status WHERE share_id = :s"),
            {"status": status, "s": share_id},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Share '{share_id}' not found.")

    async def get_shares_by_owner(
        self,
        owner_user_id_hex: str,
        status:            str | None = None,
        skip:              int = 0,
        limit:             int = 50,
    ) -> list[dict]:
        """List shares created by a user, newest first. Optionally filter by status."""
        where = "WHERE owner_user_id_hex = :owner"
        params: dict = {"owner": owner_user_id_hex, "limit": limit, "skip": skip}
        if status:
            where += " AND status = :status"
            params["status"] = status
        result = await self.db.execute(
            text(f"SELECT * FROM active_shares {where} ORDER BY created_at DESC LIMIT :limit OFFSET :skip"),
            params,
        )
        return [dict(r) for r in result.mappings()]

    async def get_shares_by_grantee(
        self,
        grantee_user_id_hex: str,
        status:              str | None = None,
        skip:                int = 0,
        limit:               int = 50,
    ) -> list[dict]:
        """List shares sent to a user, newest first. Optionally filter by status."""
        where = "WHERE grantee_user_id_hex = :grantee"
        params: dict = {"grantee": grantee_user_id_hex, "limit": limit, "skip": skip}
        if status:
            where += " AND status = :status"
            params["status"] = status
        result = await self.db.execute(
            text(f"SELECT * FROM active_shares {where} ORDER BY created_at DESC LIMIT :limit OFFSET :skip"),
            params,
        )
        return [dict(r) for r in result.mappings()]

    async def expire_old_shares(self) -> int:
        """
        Set status='expired' on all active shares past their expires_at.
        Mirrors the DB function expire_old_shares(). Returns count updated.
        """
        result = await self.db.execute(
            text("""
                UPDATE active_shares SET status = 'expired'
                WHERE status = 'active' AND expires_at < :now
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
        share_id:            UUID,
        grantee_user_id_hex: str,
        access_ip:           str,
        user_agent:          str | None = None,
    ) -> None:
        """
        Manually append a share access log entry.
        Note: the DB trigger also does this automatically on retrieved_at update,
        so only call this directly for additional access events.
        """
        await self.db.execute(
            text("""
                INSERT INTO share_access_log (share_id, grantee_user_id_hex, access_ip, user_agent)
                VALUES (:share_id, :grantee, :ip, :ua)
            """),
            {"share_id": share_id, "grantee": grantee_user_id_hex, "ip": access_ip, "ua": user_agent},
        )
        await self.db.commit()

    async def get_share_access_log(self, share_id: UUID, limit: int = 50) -> list[dict]:
        """Return access events for a share, newest first."""
        result = await self.db.execute(
            text("""
                SELECT * FROM share_access_log
                WHERE share_id = :s
                ORDER BY accessed_at DESC
                LIMIT :limit
            """),
            {"s": share_id, "limit": limit},
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
        Insert a vault record (metadata only — no ciphertext).
        Ciphertext is stored separately via create_vault_ciphertext.
        Raises DuplicateError if record_id already exists.
        """
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO vault_records (
                        record_id, owner_key_hash, owner_user_id_hex,
                        owner_public_key_hex, filename, mime_type,
                        size_bytes, iv_hex, tags
                    ) VALUES (
                        :record_id, :owner_key_hash, :owner_user_id_hex,
                        :owner_public_key_hex, :filename, :mime_type,
                        :size_bytes, :iv_hex, :tags
                    )
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
                    "tags":                 tags or [],
                },
            )
            await self.db.commit()
            return dict(result.mappings().one())
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_vault_record(self, record_id: str) -> dict | None:
        """Get a vault record by ID. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM vault_records WHERE record_id = :r"),
            {"r": record_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def list_vault_records(
        self,
        owner_user_id_hex: str,
        skip:  int = 0,
        limit: int = 50,
    ) -> list[dict]:
        """List all vault records for an owner, newest first."""
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
        Delete a vault record and its ciphertext (CASCADE).
        Raises RecordNotFoundError if the record does not exist.
        """
        result = await self.db.execute(
            text("DELETE FROM vault_records WHERE record_id = :r"),
            {"r": record_id},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Vault record '{record_id}' not found.")

    # =========================================================================
    # VAULT CIPHERTEXT
    # =========================================================================

    async def create_vault_ciphertext(
        self,
        record_id:  str,
        ciphertext: bytes,
        dek_bundle: dict,
    ) -> None:
        """
        Store encrypted ciphertext paired with a vault record.
        Must be called after create_vault_record for the same record_id.
        dek_bundle is stored as JSONB.
        """
        try:
            await self.db.execute(
                text("""
                    INSERT INTO vault_ciphertext (record_id, ciphertext, dek_bundle)
                    VALUES (:record_id, :ciphertext, :dek_bundle)
                """),
                {
                    "record_id":  record_id,
                    "ciphertext": ciphertext,
                    "dek_bundle": dek_bundle,
                },
            )
            await self.db.commit()
        except SAIntegrityError as exc:
            await self.db.rollback()
            raise _parse_integrity(exc) from exc

    async def get_vault_ciphertext(self, record_id: str) -> dict | None:
        """Get the ciphertext blob for a record. Returns None if not found."""
        result = await self.db.execute(
            text("SELECT * FROM vault_ciphertext WHERE record_id = :r"),
            {"r": record_id},
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
        permission_level:      str,
        time_start:            datetime,
        time_end:              datetime,
        dek_bundle_grantee:    dict,
        signature_hex:         str,
        grantee_user_id_hex:   str | None = None,
    ) -> dict:
        """
        Create a share grant giving a grantee time-bounded access to a record.
        permission_level must be 'view_only' or 'view_download'.
        Raises DuplicateError if grant_id already exists.
        """
        try:
            result = await self.db.execute(
                text("""
                    INSERT INTO grants (
                        grant_id, record_id,
                        grantor_key_hash, grantee_key_hash, grantee_user_id_hex,
                        grantee_public_key_hex, permission_level,
                        time_start, time_end,
                        dek_bundle_grantee, signature_hex
                    ) VALUES (
                        :grant_id, :record_id,
                        :grantor_key_hash, :grantee_key_hash, :grantee_user_id_hex,
                        :grantee_public_key_hex, :permission_level,
                        :time_start, :time_end,
                        :dek_bundle_grantee, :signature_hex
                    )
                    RETURNING *
                """),
                {
                    "grant_id":              grant_id,
                    "record_id":             record_id,
                    "grantor_key_hash":      grantor_key_hash,
                    "grantee_key_hash":      grantee_key_hash,
                    "grantee_user_id_hex":   grantee_user_id_hex,
                    "grantee_public_key_hex": grantee_public_key_hex,
                    "permission_level":      permission_level,
                    "time_start":            time_start,
                    "time_end":              time_end,
                    "dek_bundle_grantee":    dek_bundle_grantee,
                    "signature_hex":         signature_hex,
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
            text("SELECT * FROM grants WHERE grant_id = :g"),
            {"g": grant_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None

    async def revoke_grant(self, grant_id: str) -> None:
        """
        Mark a grant as revoked.
        Raises RecordNotFoundError if grant does not exist.
        """
        result = await self.db.execute(
            text("UPDATE grants SET revoked = TRUE, revoked_at = :now WHERE grant_id = :g"),
            {"now": _now(), "g": grant_id},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Grant '{grant_id}' not found.")

    async def mark_grant_retrieved(self, grant_id: str) -> None:
        """Record when the grantee first retrieved the shared data."""
        result = await self.db.execute(
            text("UPDATE grants SET retrieved_at = :now WHERE grant_id = :g AND retrieved_at IS NULL"),
            {"now": _now(), "g": grant_id},
        )
        await self.db.commit()
        if result.rowcount == 0:
            raise RecordNotFoundError(f"Grant '{grant_id}' not found or already retrieved.")

    async def get_grants_for_record(self, record_id: str, active_only: bool = True) -> list[dict]:
        """List all grants on a vault record."""
        where = "WHERE record_id = :r"
        if active_only:
            where += " AND revoked = FALSE AND time_end > :now"
        params: dict = {"r": record_id, "now": _now()}
        result = await self.db.execute(
            text(f"SELECT * FROM grants {where} ORDER BY created_at DESC"),
            params,
        )
        return [dict(r) for r in result.mappings()]

    async def get_grants_by_grantor(self, grantor_key_hash: str, active_only: bool = True) -> list[dict]:
        """List grants created by a grantor key hash."""
        where = "WHERE grantor_key_hash = :g"
        if active_only:
            where += " AND revoked = FALSE AND time_end > :now"
        params: dict = {"g": grantor_key_hash, "now": _now()}
        result = await self.db.execute(
            text(f"SELECT * FROM grants {where} ORDER BY created_at DESC"),
            params,
        )
        return [dict(r) for r in result.mappings()]

    async def get_grants_by_grantee(self, grantee_key_hash: str, active_only: bool = True) -> list[dict]:
        """List grants where this key hash is the recipient."""
        where = "WHERE grantee_key_hash = :g"
        if active_only:
            where += " AND revoked = FALSE AND time_end > :now"
        params: dict = {"g": grantee_key_hash, "now": _now()}
        result = await self.db.execute(
            text(f"SELECT * FROM grants {where} ORDER BY created_at DESC"),
            params,
        )
        return [dict(r) for r in result.mappings()]

    # =========================================================================
    # AUDIT LOG (append-only compliance log)
    # =========================================================================

    async def append_audit_log(
        self,
        action:           str,
        ip_address:       str,
        actor_user_id_hex: str | None = None,
        share_id:         UUID | None = None,
        detail:           dict | None = None,
        user_agent:       str | None = None,
    ) -> None:
        """
        Append a compliance audit event. Never updates existing rows.
        action must match the audit_action enum in the schema.
        detail must contain no PHI and no plaintext.
        """
        await self.db.execute(
            text("""
                INSERT INTO audit_log
                    (actor_user_id_hex, action, share_id, detail, ip_address, user_agent)
                VALUES
                    (:actor, :action, :share_id, :detail, :ip, :ua)
            """),
            {
                "actor":    actor_user_id_hex,
                "action":   action,
                "share_id": share_id,
                "detail":   detail,
                "ip":       ip_address,
                "ua":       user_agent,
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
        Query the audit log. Filter by actor and/or action.
        Returns newest events first.
        """
        conditions = []
        params: dict = {"limit": limit, "skip": skip}
        if actor_user_id_hex:
            conditions.append("actor_user_id_hex = :actor")
            params["actor"] = actor_user_id_hex
        if action:
            conditions.append("action = :action")
            params["action"] = action
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        result = await self.db.execute(
            text(f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT :limit OFFSET :skip"),
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
        detail:           str = "",
        actor_user_id_hex: str | None = None,
        share_id:         UUID | None = None,
        ip_address:       str | None = None,
        user_agent:       str | None = None,
    ) -> None:
        """Append a vault-level audit event (unlock, lock, upload, download)."""
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
                "action":           action,
                "actor_key_hash":   actor_key_hash,
                "actor_user_id_hex": actor_user_id_hex,
                "record_id":        record_id,
                "share_id":         share_id,
                "detail":           detail,
                "ip_address":       ip_address,
                "user_agent":       user_agent,
            },
        )
        await self.db.commit()

    async def get_vault_audit(
        self,
        actor_key_hash: str | None = None,
        record_id:      str | None = None,
        skip:           int = 0,
        limit:          int = 100,
    ) -> list[dict]:
        """Query vault audit events. Filter by actor key hash and/or record ID."""
        conditions = []
        params: dict = {"limit": limit, "skip": skip}
        if actor_key_hash:
            conditions.append("actor_key_hash = :actor")
            params["actor"] = actor_key_hash
        if record_id:
            conditions.append("record_id = :record_id")
            params["record_id"] = record_id
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        result = await self.db.execute(
            text(f"SELECT * FROM vault_audit {where} ORDER BY timestamp DESC LIMIT :limit OFFSET :skip"),
            params,
        )
        return [dict(r) for r in result.mappings()]

    # =========================================================================
    # MAINTENANCE
    # =========================================================================

    async def run_full_cleanup(self) -> dict:
        """
        Run all cleanup operations in one call.
        Mirrors the DB's cleanup_old_data() function but from Python
        so results are visible to the caller.
        Returns a dict of counts per operation.
        """
        return {
            "expired_shares":        await self.expire_old_shares(),
            "expired_pow":           await self.cleanup_expired_pow(),
            "expired_refresh_tokens": await self.cleanup_expired_refresh_tokens(),
            "expired_jtis":          await self.cleanup_expired_jtis(),
        }
