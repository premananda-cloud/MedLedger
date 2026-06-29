"""
services/auth_service.py — AuthService

Orchestrates the full user authentication lifecycle.
Calls auth modules and DatabaseRepository. Contains all business logic
for registration, login, verification, TOTP, tokens, and passwords.

Layer contract:
  ✓ Imports from auth/ and database/
  ✓ All business decisions live here
  ✗ No crypto operations (frontend handles all crypto; Argon2 lives in PasswordModule)
  ✗ No raw SQL (DatabaseRepository handles all queries)

Password storage:
  Argon2id via PasswordModule.hash_password() returns a single self-contained
  string.  Store it in users.password_hash.  No separate salt or iterations
  column is needed or used.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from auth.email    import EmailAuthModule
from auth.totp     import TOTPModule
from auth.password import PasswordModule
from auth.pow      import POWModule, POWChallenge
from database      import DatabaseRepository
from database.exceptions import DuplicateError, RecordNotFoundError

from .audit_service import AuditService
from .token import TokenModule

log = logging.getLogger(__name__)

# How long verification codes and reset codes are valid
_CODE_TTL_SECONDS    = 600   # 10 min
_RESET_TTL_SECONDS   = 900   # 15 min
_REFRESH_TTL_DAYS    = 30
_MAX_LOGIN_FAILURES  = 5
_LOCKOUT_MINUTES     = 15


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_code(code: str) -> str:
    """SHA-256 hex of a plain verification code. Store this, not the code."""
    return hashlib.sha256(code.encode()).hexdigest()


def _safe_user(user: dict) -> dict:
    """Strip all secrets before returning user data to caller."""
    drop = {
        "password_hash",
        "verification_token", "token_expires_at",
    }
    return {k: v for k, v in user.items() if k not in drop}


class AuthService:
    """
    User lifecycle: registration → email verify → login → TOTP → tokens → logout.

    All auth module calls are pure (no I/O). All DB calls go through db_repo.
    Config supplies credentials and secrets — service doesn't know where they live.

    Usage:
        auth_svc = AuthService(
            db_repo=repo,
            email_module=EmailAuthModule(company_name="MedLedger"),
            totp_module=TOTPModule(issuer="MedLedger"),
            password_module=PasswordModule(),
            token_module=TokenModule(secret=config.jwt_secret),
            pow_module=POWModule(difficulty=4),
            audit_service=audit_svc,
            config=config,
        )
    """

    def __init__(
        self,
        db_repo:         DatabaseRepository,
        email_module:    EmailAuthModule,
        totp_module:     TOTPModule,
        password_module: PasswordModule,
        token_module:    TokenModule,
        pow_module:      POWModule,
        audit_service:   AuditService,
        config:          Any,
    ):
        self.db      = db_repo
        self.email   = email_module
        self.totp    = totp_module
        self.pw      = password_module
        self.token   = token_module
        self.pow     = pow_module
        self.audit   = audit_service
        self.config  = config

    # =========================================================================
    # PROOF OF WORK
    # =========================================================================

    async def issue_pow_challenge(self, ip_address: str) -> dict:
        """
        Issue a PoW challenge to a client before registration or login.

        Returns the challenge dict to send to the client.
        Stores the challenge in the DB for later verification.
        """
        challenge = self.pow.new_challenge()
        expires_at = _now() + timedelta(seconds=self.pow.expiry_seconds)

        await self.db.create_pow_challenge(
            challenge_id=challenge.challenge_id,
            nonce_prefix=challenge.challenge,
            difficulty=challenge.difficulty,
            target_hash="0" * challenge.difficulty,
            expires_at=expires_at,
        )
        return challenge.to_dict()

    async def verify_pow_challenge(
        self,
        challenge_id: str,
        solution:     str,
        ip_address:   str,
    ) -> bool:
        """
        Verify a PoW solution from the client.

        Deletes the challenge on success (replay protection).
        Returns True on valid solution, False otherwise.
        """
        row = await self.db.get_pow_challenge(challenge_id)
        if not row:
            return False

        challenge = POWChallenge(
            challenge_id=row["challenge_id"],
            challenge=row["nonce_prefix"],
            difficulty=row["difficulty"],
            timestamp=row["expires_at"].timestamp() - self.pow.expiry_seconds,
        )

        if self.pow.is_expired(challenge):
            await self.db.delete_pow_challenge(challenge_id)
            return False

        result = self.pow.verify_solution(challenge, solution)
        if result.success:
            await self.db.mark_pow_solved(challenge_id, solution, ip_address)
            await self.db.delete_pow_challenge(challenge_id)
        return result.success

    # =========================================================================
    # REGISTRATION
    # =========================================================================

    async def register_user(
        self,
        email:               str,
        username:            str,
        password:            str,
        full_name:           str,
        signing_public_key:  str,
        exchange_public_key: str,
        ip_address:          str,
    ) -> dict:
        """
        Stage 1 of 2 for registration.

        No user row is created here. Instead:
        1. Validate password strength
        2. Check email/username availability (users table AND pending table)
        3. Hash password
        4. Write to pending_registrations
        5. Send verification code (hash stored in pending row)
        6. Return { pending: True, message } — no user object

        The user row is only created in verify_email() (stage 2).
        This eliminates the limbo state where an unverified user exists
        but cannot re-register or get a new code.

        Raises:
            ValueError: weak password
            DuplicateError: email or username already taken
        """
        # 1. Password strength
        strength = self.pw.validate_strength(password)
        if not strength.valid:
            raise ValueError(f"Password too weak: {'; '.join(strength.issues)}")

        # 2. Availability — check both verified users and pending registrations
        if await self.db.email_exists(email):
            raise DuplicateError("Email address is already registered.", field="email")
        if await self.db.username_exists(username):
            raise DuplicateError("Username is already taken.", field="username")

        # 3. Hash password — Argon2id returns a single self-contained string
        password_hash = self.pw.hash_password(password)

        # 4 + 5. Generate code, store pending row, send email
        result = self.email.validate_and_send_code(
            email=email,
            gmail_user=self.config.gmail_user,
            gmail_app_password=self.config.gmail_app_password,
        )
        code_hash  = _hash_code(result.code) if result.success else ""
        expires_at = _now() + timedelta(seconds=_CODE_TTL_SECONDS)

        await self.db.create_pending_registration(
            email=email,
            username=username,
            password_hash=password_hash,
            signing_public_key=signing_public_key,
            exchange_public_key=exchange_public_key,
            code_hash=code_hash,
            expires_at=expires_at,
        )

        if not result.success:
            log.warning("Failed to send verification email to %s: %s", email, result.error)

        return {"pending": True, "message": "Verification code sent to your email address."}

    # =========================================================================
    # EMAIL VERIFICATION
    # =========================================================================

    async def verify_email(
        self,
        email:      str,
        code:       str,
        ip_address: str,
    ) -> dict:
        """
        Stage 2 of 2 for registration — verify code and create user.

        1. Fetch pending registration by email
        2. Check expiry and attempt limit (max 5 wrong attempts → delete pending)
        3. Constant-time code comparison
        4. Atomically: create user in users table, delete pending row
        5. Issue tokens (auto-login on verify)
        6. Audit log

        Raises:
            ValueError: code wrong/expired, or max attempts exceeded
            RecordNotFoundError: no pending registration for this email
        """
        _MAX_VERIFY_ATTEMPTS = 5

        pending = await self.db.get_pending_by_email(email)
        if not pending:
            raise RecordNotFoundError(
                "No pending registration found for this email. "
                "The code may have expired — please register again."
            )

        # Constant-time comparison (hash both sides)
        submitted_hash = _hash_code(code)
        if not secrets.compare_digest(submitted_hash, pending["verification_code"]):
            attempts = await self.db.increment_pending_attempts(email)
            if attempts >= _MAX_VERIFY_ATTEMPTS:
                await self.db.delete_pending_registration(email)
                raise ValueError(
                    "Too many incorrect attempts. Please register again."
                )
            remaining = _MAX_VERIFY_ATTEMPTS - attempts
            raise ValueError(
                f"Invalid verification code. {remaining} attempt(s) remaining."
            )

        # Code is correct — create the real user and delete the pending row
        user = await self.db.create_user(
            username=pending["username"],
            email=pending["email"],
            full_name=pending.get("full_name", ""),
            password_hash=pending["password_hash"],
            signing_public_key=pending["signing_public_key"],
            exchange_public_key=pending["exchange_public_key"],
        )
        await self.db.delete_pending_registration(email)

        await self.audit.log_auth_event(
            "register", user["user_id_hex"], ip_address,
            detail={"username": user["username"]},
        )

        # Auto-login: issue tokens immediately
        return await self._complete_login(user, ip_address, user_agent=None)

    async def resend_verification_code(
        self,
        email:      str,
        ip_address: str,
    ) -> dict:
        """
        Resend verification email for a pending registration.

        Looks up by email — no user_id_hex exists yet (no user row created
        until verification succeeds).

        Raises:
            RecordNotFoundError: no pending registration for this email
        """
        pending = await self.db.get_pending_by_email(email)
        if not pending:
            raise RecordNotFoundError(
                "No pending registration found. The code may have expired — "
                "please register again."
            )

        result = self.email.validate_and_send_code(
            email=email,
            gmail_user=self.config.gmail_user,
            gmail_app_password=self.config.gmail_app_password,
        )
        if not result.success:
            log.warning("Failed to resend verification email to %s: %s", email, result.error)
            raise ValueError("Failed to send verification email. Please try again.")

        code_hash  = _hash_code(result.code)
        expires_at = _now() + timedelta(seconds=_CODE_TTL_SECONDS)

        await self.db.create_pending_registration(
            email=pending["email"],
            username=pending["username"],
            password_hash=pending["password_hash"],
            signing_public_key=pending["signing_public_key"],
            exchange_public_key=pending["exchange_public_key"],
            code_hash=code_hash,
            expires_at=expires_at,
        )
        return {"message": "Verification code resent."}

    # =========================================================================
    # LOGIN
    # =========================================================================

    async def login(
        self,
        email:      str,
        password:   str,
        ip_address: str,
        user_agent: str | None = None,
    ) -> dict:
        """
        Authenticate a user.

        1. Check rate limit / lockout FIRST (before any DB user fetch that
           could leak timing info about account existence)
        2. Fetch user — always run Argon2 verify to prevent timing attacks
        3. Verify password
        4. Check account status (active, not deleted)
        5. If TOTP enabled → return requires_totp signal
        6. Issue tokens, store refresh token
        7. Record login, reset rate limit, audit
        8. Rehash password if Argon2 params have been upgraded

        Raises:
            ValueError: invalid credentials, account locked/inactive
        """
        # 1. Lockout check BEFORE password verification.
        #    This prevents a locked-out attacker from learning whether their
        #    password guess is correct via a timing side-channel.
        await self._check_login_lockout(email, ip_address)

        user = await self.db.get_user_by_email(email)

        # Always run Argon2 verify — prevents user-enumeration via timing.
        # Use a pre-hashed dummy when the user doesn't exist so the verify
        # path takes the same amount of time regardless.
        _DUMMY_HASH = (
            "$argon2id$v=19$m=65536,t=3,p=4"
            "$AAAAAAAAAAAAAAAAAAAAAA"
            "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        stored_hash = user["password_hash"] if user else _DUMMY_HASH

        pw_ok = self.pw.verify_password(password, stored_hash)

        if not user or not pw_ok:
            if user:
                await self._handle_failed_login(user, ip_address)
            await self.audit.log_auth_event(
                "login_failure",
                user["user_id_hex"] if user else "unknown",
                ip_address,
                detail={"reason": "invalid_credentials"},
            )
            raise ValueError("Invalid email or password.")

        # 2. Account status checks (after password verify — don't short-circuit
        #    before verify or you leak account existence via timing)
        if user.get("account_deleted"):
            raise ValueError("Account has been deleted.")

        if not user.get("is_active"):
            raise ValueError("Account is inactive. Please contact support.")

        # 3. Opportunistic rehash — update Argon2 params if they've changed
        if self.pw.needs_rehash(stored_hash):
            new_hash = self.pw.hash_password(password)
            await self.db.set_password_hash(user["user_id_hex"], new_hash)

        # 4. TOTP required?
        if user.get("totp_enabled"):
            return {
                "requires_totp": True,
                "user_id_hex":   user["user_id_hex"],
            }

        return await self._complete_login(user, ip_address, user_agent)

    async def _check_login_lockout(self, email: str, ip_address: str) -> None:
        """Check if this email is rate-limited. Raise ValueError if locked."""
        key_hash = hashlib.sha256(email.lower().encode()).hexdigest()
        record   = await self.db.get_rate_limit(key_hash, "login")
        if not record:
            return
        blocked_until = record.get("blocked_until")
        if blocked_until and _now() < blocked_until:
            raise ValueError(
                f"Too many failed login attempts. Try again after "
                f"{blocked_until.strftime('%H:%M UTC')}."
            )

    async def _handle_failed_login(self, user: dict, ip_address: str) -> None:
        """Increment failure counter; lock account if threshold reached."""
        key_hash = hashlib.sha256(user["email"].lower().encode()).hexdigest()
        record   = await self.db.upsert_rate_limit(key_hash, "login")
        if record["attempts"] >= _MAX_LOGIN_FAILURES:
            blocked_until = _now() + timedelta(minutes=_LOCKOUT_MINUTES)
            await self.db.set_rate_limit_block(key_hash, "login", blocked_until)

    async def _complete_login(
        self,
        user:       dict,
        ip_address: str,
        user_agent: str | None,
    ) -> dict:
        """Issue tokens, record login, return token response."""
        user_id_hex = user["user_id_hex"]

        # Generate access + refresh tokens
        access_token   = self.token.create_access_token(
            sub=user_id_hex,
            username=user["username"],
            email=user["email"],
        )
        plain_refresh  = self.token.generate_refresh_token()
        refresh_hash   = self.token.hash_refresh_token(plain_refresh)
        family_id      = secrets.token_hex(16)
        refresh_expiry = _now() + timedelta(days=_REFRESH_TTL_DAYS)

        await self.db.store_refresh_token(
            token_hash=refresh_hash,
            user_id_hex=user_id_hex,
            family_id=family_id,
            expires_at=refresh_expiry,
        )
        await self.db.record_successful_login(user_id_hex, ip_address)

        # Clear login rate limit on success
        key_hash = hashlib.sha256(user["email"].lower().encode()).hexdigest()
        await self.db.reset_rate_limit(key_hash, "login")

        await self.audit.log_auth_event(
            "login_success", user_id_hex, ip_address,
            user_agent=user_agent,
        )

        return {
            "access_token":  access_token,
            "refresh_token": plain_refresh,
            "token_type":    "bearer",
            "expires_in":    self.token._expiry,
            "user":          _safe_user(user),
        }

    # =========================================================================
    # TOTP LOGIN (second factor)
    # =========================================================================

    async def verify_totp_login(
        self,
        user_id_hex: str,
        totp_code:   str,
        ip_address:  str,
        user_agent:  str | None = None,
    ) -> dict:
        """
        Complete login with TOTP second factor.

        Raises:
            RecordNotFoundError: user not found
            ValueError: invalid TOTP code
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError("User not found.")

        secret = user.get("totp_secret")
        if not secret:
            raise ValueError("TOTP is not configured for this account.")

        if not self.totp.verify_code(secret=secret, code=totp_code):
            await self.audit.log_auth_event(
                "totp_verify", user_id_hex, ip_address,
                detail={"result": "failed"},
            )
            raise ValueError("Invalid TOTP code.")

        await self.audit.log_auth_event(
            "totp_verify", user_id_hex, ip_address,
            detail={"result": "success"},
        )
        return await self._complete_login(user, ip_address, user_agent)

    # =========================================================================
    # TOTP SETUP
    # =========================================================================

    async def setup_totp(self, user_id_hex: str, ip_address: str) -> dict:
        """
        Begin TOTP setup — generate secret and backup codes.

        Temporarily stores the secret (not yet enabled).
        Caller returns provisioning URI + plain backup codes to frontend.
        TOTP is NOT active until confirm_totp() is called.

        Raises:
            RecordNotFoundError: user not found
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError("User not found.")

        totp_data    = self.totp.generate_secret(user["email"])
        backup_codes = self.totp.generate_backup_codes(count=8)

        # Hash backup codes for storage — plain codes go to the client only
        hashed_backups = [_hash_code(c) for c in backup_codes]

        # Store secret temporarily (totp_enabled stays False until confirmed)
        await self.db.update_user(
            user_id_hex,
            totp_secret=totp_data.secret,
            totp_backup_codes=hashed_backups,
        )

        await self.audit.log_auth_event("totp_setup", user_id_hex, ip_address)

        return {
            "uri":          totp_data.uri,
            "backup_codes": backup_codes,   # plain — show once, then discard
        }

    async def confirm_totp(
        self,
        user_id_hex: str,
        totp_code:   str,
        ip_address:  str,
    ) -> dict:
        """
        Confirm TOTP setup by verifying a live code from the authenticator app.

        Enables TOTP on the account once code is valid.

        Raises:
            RecordNotFoundError: user not found
            ValueError: TOTP not set up yet, or invalid code
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError("User not found.")

        secret = user.get("totp_secret")
        if not secret:
            raise ValueError("TOTP setup not started. Call setup_totp first.")

        if not self.totp.verify_code(secret=secret, code=totp_code):
            raise ValueError("Invalid TOTP code. Please try again.")

        await self.db.update_user(user_id_hex, totp_enabled=True)
        await self.audit.log_auth_event("totp_setup", user_id_hex, ip_address,
                                        detail={"confirmed": True})
        return {"totp_enabled": True}

    async def disable_totp(
        self,
        user_id_hex: str,
        password:    str,
        totp_code:   str,
        ip_address:  str,
    ) -> dict:
        """
        Disable TOTP — requires password + current TOTP code.

        Also revokes all refresh tokens (forces re-login on all devices).

        Raises:
            RecordNotFoundError: user not found
            ValueError: wrong password or TOTP code
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError("User not found.")

        if not self.pw.verify_password(password, user["password_hash"]):
            raise ValueError("Incorrect password.")

        secret = user.get("totp_secret")
        if not secret or not self.totp.verify_code(secret=secret, code=totp_code):
            raise ValueError("Invalid TOTP code.")

        await self.db.update_user(
            user_id_hex,
            totp_enabled=False,
            totp_secret=None,
            totp_backup_codes=None,
        )
        await self.db.revoke_all_user_refresh_tokens(user_id_hex)
        await self.audit.log_auth_event("totp_disabled", user_id_hex, ip_address)

        return {"totp_enabled": False}

    # =========================================================================
    # TOKEN MANAGEMENT
    # =========================================================================

    async def refresh_access_token(
        self,
        refresh_token: str,
        ip_address:    str,
    ) -> dict:
        """
        Rotate a refresh token — issue new access + refresh token pair.

        Detects reuse: if the token is already revoked, revoke the entire
        family (all sessions from this login chain are invalidated).

        Raises:
            ValueError: token invalid, expired, or reuse detected
        """
        token_hash = self.token.hash_refresh_token(refresh_token)
        stored     = await self.db.get_refresh_token(token_hash)

        if not stored:
            # Token not found or already revoked — could be reuse attack
            log.warning("Refresh token reuse or unknown token from IP %s", ip_address)
            raise ValueError("Invalid or expired refresh token.")

        # Rotate: revoke old, issue new
        new_plain   = self.token.generate_refresh_token()
        new_hash    = self.token.hash_refresh_token(new_plain)
        new_expiry  = _now() + timedelta(days=_REFRESH_TTL_DAYS)

        await self.db.store_refresh_token(
            token_hash=new_hash,
            user_id_hex=stored["user_id_hex"],
            family_id=stored["family_id"],
            expires_at=new_expiry,
        )
        await self.db.revoke_refresh_token(token_hash, replaced_by_token_hash=new_hash)

        user = await self.db.get_user_by_id_hex(stored["user_id_hex"])
        if not user:
            raise ValueError("User no longer exists.")

        access_token = self.token.create_access_token(
            sub=user["user_id_hex"],
            username=user["username"],
            email=user["email"],
        )
        return {
            "access_token":  access_token,
            "refresh_token": new_plain,
            "token_type":    "bearer",
            "expires_in":    self.token._expiry,
        }

    async def logout(
        self,
        user_id_hex:   str,
        refresh_token: str | None = None,
        ip_address:    str = "",
    ) -> dict:
        """
        Logout from the current device.

        If refresh_token provided, revokes only that token.
        Always audit-logs the event.
        """
        if refresh_token:
            token_hash = self.token.hash_refresh_token(refresh_token)
            try:
                await self.db.revoke_refresh_token(token_hash)
            except RecordNotFoundError:
                pass  # already revoked — idempotent

        await self.audit.log_auth_event("logout", user_id_hex, ip_address)
        return {"logged_out": True}

    async def logout_all_devices(self, user_id_hex: str, ip_address: str) -> dict:
        """
        Revoke all tokens for this user — logout from every device.
        """
        await self.db.revoke_all_user_refresh_tokens(user_id_hex)
        await self.audit.log_auth_event("logout_all", user_id_hex, ip_address)
        return {"logged_out": True, "devices": "all"}

    # =========================================================================
    # PASSWORD MANAGEMENT
    # =========================================================================

    async def change_password(
        self,
        user_id_hex:  str,
        old_password: str,
        new_password: str,
        ip_address:   str,
    ) -> dict:
        """
        Change password — requires current password.

        Revokes all refresh tokens after change (forces re-login).

        FIX: previously called db.set_password_hash() with only the hash,
        silently dropping the new salt. Argon2id embeds its own salt inside
        the hash string, so a single column update is now correct by design.

        Raises:
            RecordNotFoundError: user not found
            ValueError: wrong old password, or new password too weak
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError("User not found.")

        if not self.pw.verify_password(old_password, user["password_hash"]):
            raise ValueError("Current password is incorrect.")

        strength = self.pw.validate_strength(new_password)
        if not strength.valid:
            raise ValueError(f"New password too weak: {'; '.join(strength.issues)}")

        # hash_password() returns a single Argon2id string — salt is embedded
        new_hash = self.pw.hash_password(new_password)
        await self.db.set_password_hash(user_id_hex, new_hash)
        await self.db.revoke_all_user_refresh_tokens(user_id_hex)
        await self.audit.log_auth_event("password_change", user_id_hex, ip_address)

        return {"password_changed": True}

    async def request_password_reset(self, email: str, ip_address: str) -> dict:
        """
        Initiate password reset — sends reset code to email.

        Always returns success regardless of whether the email exists
        to prevent user enumeration.
        """
        user = await self.db.get_user_by_email(email)
        if user:
            result = self.email.validate_and_send_code(
                email=email,
                gmail_user=self.config.gmail_user,
                gmail_app_password=self.config.gmail_app_password,
            )
            if result.success and result.code:
                code_hash  = _hash_code(result.code)
                expires_at = _now() + timedelta(seconds=_RESET_TTL_SECONDS)
                await self.db.store_verification_token(
                    user_id_hex=user["user_id_hex"],
                    token=code_hash,
                    expires_at=expires_at.isoformat(),
                )
                await self.audit.log_auth_event(
                    "password_reset_request", user["user_id_hex"], ip_address
                )

        # Always return same response — never reveal if email exists
        return {"message": "If that email is registered, a reset code has been sent."}

    async def confirm_password_reset(
        self,
        email:        str,
        code:         str,
        new_password: str,
        ip_address:   str,
    ) -> dict:
        """
        Complete password reset with code + new password.

        FIX: previously called db.set_password_hash() with only the hash,
        silently dropping the new salt. Argon2id embeds the salt in the
        hash string, so this is now correct.

        Raises:
            ValueError: invalid/expired code, or weak new password
        """
        user = await self.db.get_user_by_email(email)
        if not user:
            raise ValueError("Invalid or expired reset code.")

        stored_hash = user.get("verification_token")
        expires_str = user.get("token_expires_at")

        if not stored_hash or not expires_str:
            raise ValueError("No reset code on file. Please request a new one.")

        try:
            expires_at = datetime.fromisoformat(expires_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            raise ValueError("Reset code has expired.")

        if _now() > expires_at:
            raise ValueError("Reset code has expired.")

        if not secrets.compare_digest(_hash_code(code), stored_hash):
            raise ValueError("Invalid reset code.")

        strength = self.pw.validate_strength(new_password)
        if not strength.valid:
            raise ValueError(f"New password too weak: {'; '.join(strength.issues)}")

        # hash_password() returns a single Argon2id string — salt is embedded
        new_hash = self.pw.hash_password(new_password)
        await self.db.set_password_hash(user["user_id_hex"], new_hash)
        # Clear the used reset token
        await self.db.store_verification_token(user["user_id_hex"], "", "")
        await self.db.revoke_all_user_refresh_tokens(user["user_id_hex"])
        await self.audit.log_auth_event(
            "password_reset_confirm", user["user_id_hex"], ip_address
        )
        return {"password_reset": True}
