"""
auth/models.py — Pydantic models for auth module inputs and outputs.

These are the data contracts between auth modules and the orchestrator.
No database models here — those live in models/schemas.py.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr


# ─────────────────────────────────────────────
# Email (send / basic format validation)
# ─────────────────────────────────────────────

class EmailSendResult(BaseModel):
    success:    bool
    email:      str
    code:       Optional[str] = None   # plain code — orchestrator stores this
    error:      Optional[str] = None


# ─────────────────────────────────────────────
# TOTP
# ─────────────────────────────────────────────

class TOTPSecret(BaseModel):
    secret:     str    # base32 — orchestrator stores this (encrypted)
    uri:        str    # otpauth:// URI — for QR display
    issuer:     str
    email:      str


# ─────────────────────────────────────────────
# Proof of Work
# ─────────────────────────────────────────────

class POWChallenge(BaseModel):
    challenge_id: str
    challenge:    str   # random string client must hash against
    difficulty:   int
    timestamp:    float

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class POWVerifyResult(BaseModel):
    success:  bool
    message:  str


# ─────────────────────────────────────────────
# Password
#
# PasswordHashResult is intentionally removed.
# Argon2id (PasswordModule.hash_password) returns a plain str — a single
# self-contained hash string that encodes algorithm, parameters, salt, and
# hash.  There is nothing else to store alongside it.
# ─────────────────────────────────────────────

class PasswordStrengthResult(BaseModel):
    valid:      bool
    score:      int            # 0-5
    strength:   str            # "weak" | "fair" | "good" | "strong" | "very_strong"
    issues:     List[str]      # human-readable list of what's missing


# ─────────────────────────────────────────────
# Email Verification (EmailVerification module)
#
# Previously EmailValidationResult was defined twice — once as a simple
# format-check result (valid, email, reason) and once as the richer
# verification result below.  The first definition was silently shadowed.
#
# Resolution:
#   • The richer model below keeps the EmailValidationResult name because
#     it is used throughout email_verification.py and its callers.
#   • The thin format-check result that email.py returns is now called
#     EmailFormatResult so callers can import the right type explicitly.
# ─────────────────────────────────────────────

class EmailFormatResult(BaseModel):
    """Returned by EmailAuthModule.validate_format() — basic syntax check only."""
    valid:      bool
    email:      str
    reason:     Optional[str] = None   # why it failed, if it did


class EmailStatus(str, Enum):
    VALID           = "valid"
    INVALID_FORMAT  = "invalid_format"
    DISPOSABLE      = "disposable"
    SPAM            = "spam"


class EmailValidationResult(BaseModel):
    """Returned by EmailVerificationModule — full disposable/spam check."""
    is_valid:         bool
    status:           EmailStatus
    message:          str
    normalized_email: Optional[str] = None


class VerificationCode(BaseModel):
    code:               str    # plain — caller sends this, does NOT persist
    code_hash:          str    # SHA-256 hex — persist this
    expires_at:         float  # unix timestamp
    expires_in_seconds: int
