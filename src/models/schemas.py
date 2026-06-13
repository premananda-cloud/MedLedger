"""
src/models/schemas.py
Pydantic v2 request / response schemas.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, EmailStr, field_validator
import re


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterStep1Request(BaseModel):
    """Client POW solution."""
    challenge_id: str
    nonce: str


class RegisterStep2Request(BaseModel):
    """Email submission."""
    session_token: str
    email: str


class RegisterStep3Request(BaseModel):
    """Email code verification."""
    session_token: str
    code: str


class RegisterStep4Request(BaseModel):
    """TOTP verification."""
    session_token: str
    totp_token: str


class RegisterStep5Request(BaseModel):
    """Account creation — final step."""
    session_token: str
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_chars(cls, v: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_]{3,30}", v):
            raise ValueError("Username must be 3-30 chars: letters, numbers, underscores only")
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class PublicKeysUpload(BaseModel):
    signing_public_key: str
    exchange_public_key: str
    user_id_hex: str
    username: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ── User ──────────────────────────────────────────────────────────────────────

class UserPublicKeys(BaseModel):
    signing_public_key: str | None
    exchange_public_key: str | None


class MeResponse(BaseModel):
    username: str
    user_id_hex: str
    full_name: str
    role: str
    public_keys: UserPublicKeys
    is_verified: bool


class UserSearchResult(BaseModel):
    username: str
    user_id_hex: str
    signing_public_key: str | None
    exchange_public_key: str | None


# ── Shares ────────────────────────────────────────────────────────────────────

class CreateShareRequest(BaseModel):
    grantee_user_id_hex: str
    filename: str
    mime_type: str | None = None
    size_bytes: int
    ciphertext_b64: str          # base64url encoded XSalsa20 ciphertext
    dek_bundle: str              # base64url sealed box (DEK encrypted to grantee)
    nonce: str                   # base64url XSalsa20 nonce
    signature: str               # base64url Ed25519 signature
    payload_canon: str | None = None
    file_hash: str | None = None
    expires_hours: int = 24
    delete_on_download: bool = True
    permission_level: str = "view_download"

    @field_validator("expires_hours")
    @classmethod
    def cap_expiry(cls, v: int) -> int:
        if v < 1 or v > 2160:  # max 90 days
            raise ValueError("expires_hours must be between 1 and 2160")
        return v


class ShareSummary(BaseModel):
    share_id: str
    short_code: str | None
    filename: str
    mime_type: str | None
    size_bytes: int
    owner_username: str
    grantee_username: str
    created_at: datetime
    expires_at: datetime
    delete_on_download: bool
    status: str
    permission_level: str


class ShareDetail(ShareSummary):
    dek_bundle: str
    nonce: str
    signature: str
    ciphertext_url: str          # endpoint to stream ciphertext


class RevokeShareRequest(BaseModel):
    share_id: str


# ── Vault (legacy grants system) ──────────────────────────────────────────────

class VaultRecordMeta(BaseModel):
    record_id: str
    filename: str
    mime_type: str
    size_bytes: int
    iv_hex: str
    tags: list[Any]
    created_at: datetime


class CreateVaultRecordRequest(BaseModel):
    record_id: str
    filename: str
    mime_type: str
    size_bytes: int
    iv_hex: str
    tags: list[Any] = []
    ciphertext_b64: str
    dek_bundle: dict[str, Any]


class GrantRequest(BaseModel):
    record_id: str
    grantee_user_id_hex: str
    grantee_public_key_hex: str
    permission_level: str = "view_only"
    time_start: datetime
    time_end: datetime
    dek_bundle_grantee: dict[str, Any]
    signature_hex: str


# ── Generic ───────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    detail: str
