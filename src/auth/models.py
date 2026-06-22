"""
auth/models.py — Pydantic models for the auth domain.

Zero I/O. Zero external dependencies beyond pydantic.
These are the data contracts used across all auth modules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


# ─────────────────────────────────────────────
# Shared enums
# ─────────────────────────────────────────────

class PasswordStrength(str, Enum):
    INVALID    = "invalid"
    WEAK       = "weak"
    FAIR       = "fair"
    GOOD       = "good"
    STRONG     = "strong"
    VERY_STRONG = "very_strong"


class EmailStatus(str, Enum):
    VALID          = "valid"
    DISPOSABLE     = "disposable"
    SPAM           = "spam"
    INVALID_FORMAT = "invalid_format"
    BLOCKED_DOMAIN = "blocked_domain"


class PoWStatus(str, Enum):
    SUCCESS          = "success"
    INVALID_CHALLENGE = "invalid_challenge"
    EXPIRED          = "expired"
    ALREADY_USED     = "already_used"
    INVALID_PROOF    = "invalid_proof"


# ─────────────────────────────────────────────
# TOTP
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class TOTPConfig:
    """Everything needed to display TOTP setup to the user."""
    secret:       str   # base32 secret (never send to untrusted clients)
    qr_code_uri:  str   # otpauth:// URI for QR display
    manual_key:   str   # same as secret, surfaced for manual entry
    issuer:       str
    account_name: str   # the email / username shown in the authenticator


@dataclass(frozen=True)
class TOTPVerifyResult:
    verified: bool
    message:  str
    delta:    Optional[int] = None  # time-step offset, useful for clock-skew logging


# ─────────────────────────────────────────────
# Email verification
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class VerificationCode:
    """
    A generated verification code + its metadata.

    The plain `code` must be sent to the user by the caller (email_client).
    Store only `code_hash` + `expires_at` server-side.
    """
    code:              str    # plain text — hand to email_client, then discard
    code_hash:         str    # bcrypt/sha256 hash — store this
    expires_at:        float  # unix timestamp
    expires_in_seconds: int


@dataclass(frozen=True)
class EmailValidationResult:
    is_valid:         bool
    status:           EmailStatus
    message:          str
    normalized_email: Optional[str] = None


# ─────────────────────────────────────────────
# Proof of Work
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class AuthChallenge:
    """PoW challenge sent to the client."""
    challenge_id: str
    challenge:    str
    difficulty:   int
    timestamp:    float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "challenge":    self.challenge,
            "difficulty":   self.difficulty,
            "timestamp":    self.timestamp,
        }


@dataclass(frozen=True)
class PoWVerifyResult:
    success:       bool
    message:       str
    status:        PoWStatus
    session_token: Optional[str] = None   # generated on success


# ─────────────────────────────────────────────
# Password
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class PasswordHash:
    """Result of hashing a password — store both fields."""
    hash_hex: str
    salt_hex: str
    iterations: int


@dataclass(frozen=True)
class PasswordValidationResult:
    valid:          bool
    message:        str
    strength:       int              # 0-5 criteria met
    strength_label: PasswordStrength
    details:        Optional[Dict[str, Any]] = None


# ─────────────────────────────────────────────
# JWT / Token
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class TokenPayload:
    """Claims stored inside a JWT."""
    sub:         str            # subject — user_id
    username:    str
    email:       str
    iat:         int            # issued-at  (unix)
    exp:         int            # expires-at (unix)
    jti:         str            # unique token id, used for revocation
    extra:       Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TokenVerifyResult:
    valid:   bool
    payload: Optional[TokenPayload]
    error:   Optional[str] = None
