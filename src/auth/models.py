"""
auth/models.py — Pydantic models for auth module inputs and outputs.

These are the data contracts between auth modules and the orchestrator.
No database models here — those live in models/schemas.py.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr


# ─────────────────────────────────────────────
# Email
# ─────────────────────────────────────────────

class EmailSendResult(BaseModel):
    success:    bool
    email:      str
    code:       Optional[str] = None   # plain code — orchestrator stores this
    error:      Optional[str] = None


class EmailValidationResult(BaseModel):
    valid:      bool
    email:      str
    reason:     Optional[str] = None   # why it failed, if it did


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
# ─────────────────────────────────────────────

class PasswordHashResult(BaseModel):
    hash_hex:   str
    salt_hex:   str
    iterations: int


class PasswordStrengthResult(BaseModel):
    valid:      bool
    score:      int            # 0-5
    strength:   str            # "weak" | "fair" | "good" | "strong" | "very_strong"
    issues:     List[str]      # human-readable list of what's missing
