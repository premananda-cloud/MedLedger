"""
auth/token.py — TokenModule

Responsibility: create and verify JWT access tokens.

What it does:
  ✓ Creates signed JWT access tokens
  ✓ Verifies and decodes tokens
  ✓ Hashes refresh tokens for storage

What it does NOT do:
  ✗ Store tokens
  ✗ Check revocation lists (that's middleware / auth_service's job)
  ✗ Manage refresh token rotation
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import jwt


@dataclass(frozen=True)
class TokenPayload:
    sub:         str            # user_id_hex
    username:    str
    email:       str
    iat:         int
    exp:         int
    jti:         str
    extra:       Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TokenVerifyResult:
    valid:   bool
    payload: Optional[TokenPayload]
    error:   Optional[str] = None


class TokenModule:
    """
    Stateless JWT helper.

    Caller (auth_service) provides the secret from config.
    Caller is responsible for refresh token storage and rotation.

    Usage:
        module = TokenModule(secret=config.jwt_secret, expiry_seconds=3600)
        access_token = module.create_access_token(sub=user_id_hex, ...)
        result = module.verify_token(access_token)
    """

    ALGORITHM = "HS256"

    def __init__(self, secret: str, expiry_seconds: int = 3600):
        if not secret:
            raise ValueError("TokenModule requires a non-empty secret.")
        self._secret  = secret
        self._expiry  = expiry_seconds

    def create_access_token(
        self,
        sub:      str,
        username: str,
        email:    str,
        extra:    Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a signed JWT access token.

        Returns the encoded token string. Caller does NOT store this —
        it is returned to the client.
        """
        now = int(time.time())
        payload: Dict[str, Any] = {
            "sub":      sub,
            "username": username,
            "email":    email,
            "iat":      now,
            "exp":      now + self._expiry,
            "jti":      secrets.token_hex(16),
            **(extra or {}),
        }
        return jwt.encode(payload, self._secret, algorithm=self.ALGORITHM)

    def verify_token(self, token: str) -> TokenVerifyResult:
        """
        Verify signature and expiry, return decoded payload.
        Does NOT check the JTI revocation list — caller does that.
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
                error=f"Token missing required claim: {exc}",
            )

        return TokenVerifyResult(valid=True, payload=payload)

    @staticmethod
    def hash_refresh_token(token: str) -> str:
        """SHA-256 hex hash of a refresh token. Store this, not the plain token."""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def generate_refresh_token() -> str:
        """Generate a cryptographically secure refresh token (plain)."""
        return secrets.token_urlsafe(48)
