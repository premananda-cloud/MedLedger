"""
auth/token.py — Pure JWT token logic.

Zero I/O. Depends only on: PyJWT, stdlib.

Responsibilities:
  • Create signed JWT tokens
  • Verify and decode JWT tokens
  • Decode without verification (for inspection only)

The caller (auth_service / middleware) is responsible for:
  • Supplying and rotating the secret key (from config / secrets manager)
  • Revocation checks (look up jti in DB/cache before trusting the payload)
"""
from __future__ import annotations

import secrets
import time
from typing import Any, Dict, Optional

import jwt

from .models import TokenPayload, TokenVerifyResult


class TokenService:
    """
    Stateless JWT token helper.

    Usage:
        svc = TokenService(secret="...", expiry_seconds=3600)

        # Issue:
        token = svc.create(sub=user.id, username=user.username,
                           email=user.email)

        # Verify (in middleware):
        result = svc.verify(token)
        if not result.valid:
            raise Unauthorized(result.error)
        payload = result.payload
    """

    ALGORITHM = "HS256"

    def __init__(
        self,
        secret:         str,
        expiry_seconds: int  = 3_600,   # 1 hour
    ):
        if not secret:
            raise ValueError("TokenService requires a non-empty secret.")
        self._secret  = secret
        self._expiry  = expiry_seconds

    # ──────────────────────────────────────────
    # Creation
    # ──────────────────────────────────────────

    def create(
        self,
        sub:      str,
        username: str,
        email:    str,
        extra:    Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a signed JWT.

        Args:
            sub:      Subject — typically user_id.
            username: Username (stored in payload for convenience).
            email:    Email (stored in payload for convenience).
            extra:    Any additional claims to include.

        Returns:
            Encoded JWT string.
        """
        now = int(time.time())
        payload: Dict[str, Any] = {
            "sub":      sub,
            "username": username,
            "email":    email,
            "iat":      now,
            "exp":      now + self._expiry,
            "jti":      secrets.token_hex(16),   # unique ID — use for revocation
            **(extra or {}),
        }
        return jwt.encode(payload, self._secret, algorithm=self.ALGORITHM)

    # ──────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────

    def verify(self, token: str) -> TokenVerifyResult:
        """
        Verify signature, expiry, and decode a JWT.

        Returns:
            TokenVerifyResult with valid=True and a TokenPayload on success,
            or valid=False and an error message on failure.

        Note: The caller should still check `payload.jti` against a revocation
        list (DB or cache) if token invalidation on logout is required.
        """
        try:
            raw = jwt.decode(token, self._secret, algorithms=[self.ALGORITHM])
        except jwt.ExpiredSignatureError:
            return TokenVerifyResult(valid=False, payload=None, error="Token has expired.")
        except jwt.InvalidTokenError as exc:
            return TokenVerifyResult(valid=False, payload=None, error=str(exc))

        try:
            payload = TokenPayload(
                sub=raw["sub"],
                username=raw["username"],
                email=raw["email"],
                iat=raw["iat"],
                exp=raw["exp"],
                jti=raw["jti"],
                extra={k: v for k, v in raw.items()
                       if k not in ("sub", "username", "email", "iat", "exp", "jti")},
            )
        except KeyError as exc:
            return TokenVerifyResult(
                valid=False, payload=None,
                error=f"Token is missing required claim: {exc}",
            )

        return TokenVerifyResult(valid=True, payload=payload)

    def decode_unverified(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode a JWT without verifying signature or expiry.

        Use only for inspection / debugging — never trust the output for auth.
        """
        try:
            return jwt.decode(
                token, options={"verify_signature": False}, algorithms=[self.ALGORITHM]
            )
        except Exception:
            return None
