"""
models/schemas.py — Pydantic models for all API request and response shapes.

No SQLAlchemy. No database imports. Pure validation and serialisation.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, field_validator, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Generic
# ─────────────────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str
    detail:  Optional[str] = None


class ErrorResponse(BaseModel):
    error:  str
    detail: Optional[str] = None
    field:  Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Auth — requests
# ─────────────────────────────────────────────────────────────────────────────

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


class RegisterRequest(BaseModel):
    email:               EmailStr
    username:            str
    password:            str
    full_name:           str
    signing_public_key:  str
    exchange_public_key: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "Username must be 3–30 characters and contain only letters, "
                "numbers, and underscores."
            )
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        v = v.strip()
        if not 1 <= len(v) <= 100:
            raise ValueError("Full name must be 1–100 characters.")
        return v


class LoginRequest(BaseModel):
    email:     EmailStr
    password:  str
    totp_code: Optional[str] = None


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code:  str

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if len(v) != 6:
            raise ValueError("Verification code must be 6 characters.")
        return v


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class SetupTOTPRequest(BaseModel):
    user_id_hex: str


class ConfirmTOTPRequest(BaseModel):
    user_id_hex: str
    totp_code:   str

    @field_validator("totp_code")
    @classmethod
    def validate_totp(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("TOTP code must be 6 digits.")
        return v


class DisableTOTPRequest(BaseModel):
    user_id_hex: str
    password:    str
    totp_code:   str

    @field_validator("totp_code")
    @classmethod
    def validate_totp(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("TOTP code must be 6 digits.")
        return v


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters.")
        return v


class RequestPasswordResetRequest(BaseModel):
    email: EmailStr


class ConfirmPasswordResetRequest(BaseModel):
    email:        EmailStr
    code:         str
    new_password: str

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if len(v) != 6:
            raise ValueError("Reset code must be 6 characters.")
        return v

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters.")
        return v


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class POWChallengeResponse(BaseModel):
    challenge_id: str
    challenge:    str
    difficulty:   int
    timestamp:    float


class POWVerifyRequest(BaseModel):
    challenge_id: str
    solution:     str


class VerifyTOTPLoginRequest(BaseModel):
    user_id_hex: str
    totp_code:   str

    @field_validator("totp_code")
    @classmethod
    def validate_totp(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("TOTP code must be 6 digits.")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Auth — responses
# ─────────────────────────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    user_id_hex:   str
    username:      str
    email:         str
    full_name:     str
    role:          str
    is_verified:   bool
    totp_enabled:  bool
    created_at:    Optional[str] = None
    last_login_at: Optional[str] = None


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int


class LoginResponse(BaseModel):
    requires_totp: bool                  = False
    user_id_hex:   Optional[str]         = None
    tokens:        Optional[TokenResponse] = None
    user:          Optional[UserResponse]  = None


class TOTPSetupResponse(BaseModel):
    uri:          str
    backup_codes: List[str]
    message:      str = "Store backup codes safely. They will never be shown again."


class RegisterResponse(BaseModel):
    user:    UserResponse
    message: str = "Registration complete. A verification code has been sent to your email."


# ─────────────────────────────────────────────────────────────────────────────
# Keys — requests & responses
# ─────────────────────────────────────────────────────────────────────────────

class UpdateKeysRequest(BaseModel):
    signing_public_key:  Optional[str] = None
    exchange_public_key: Optional[str] = None

    @model_validator(mode="after")
    def at_least_one(self) -> "UpdateKeysRequest":
        if not self.signing_public_key and not self.exchange_public_key:
            raise ValueError("At least one key must be provided.")
        return self


class PublicKeysResponse(BaseModel):
    user_id_hex:         str
    signing_public_key:  Optional[str]
    exchange_public_key: Optional[str]


class ExchangeKeyResponse(BaseModel):
    user_id_hex:         str
    exchange_public_key: Optional[str]


class SigningKeyResponse(BaseModel):
    user_id_hex:        str
    signing_public_key: Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# Shares / Relay — requests & responses
# ─────────────────────────────────────────────────────────────────────────────

class RequestShareRequest(BaseModel):
    owner_id_hex:         str
    record_id:            str
    requester_public_key: str


class SendEncryptedPayloadRequest(BaseModel):
    recipient_id_hex:  str
    record_id:         str
    encrypted_payload: str
    signature:         str


class RejectShareRequest(BaseModel):
    share_id: str


class ShareRequestResponse(BaseModel):
    status:   str
    share_id: str
    message:  str


class PendingRequestsResponse(BaseModel):
    requests: List[Dict[str, Any]]


class EncryptedPayloadResponse(BaseModel):
    encrypted_payload:  str
    signature:          str
    sender_signing_key: Optional[str]
    record_id:          str
    sender_id_hex:      str


class NotificationResponse(BaseModel):
    notifications: List[Dict[str, Any]]


# ─────────────────────────────────────────────────────────────────────────────
# Vault — requests & responses
# ─────────────────────────────────────────────────────────────────────────────

class CreateVaultRecordRequest(BaseModel):
    record_id:            str
    owner_key_hash:       str
    owner_public_key_hex: str
    filename:             str
    mime_type:            str
    size_bytes:           int
    iv_hex:               str
    tags:                 Optional[List[str]] = None
    ciphertext:           str          # bytes encoded as hex string
    dek_bundle:           Dict[str, Any]


class VaultRecordResponse(BaseModel):
    record_id:         str
    owner_user_id_hex: Optional[str]  = None
    filename:          str
    mime_type:         str
    size_bytes:        int
    iv_hex:            Optional[str]  = None
    tags:              List[Any]      = []
    created_at:        Optional[str]  = None
    updated_at:        Optional[str]  = None


class VaultRecordListResponse(BaseModel):
    records: List[VaultRecordResponse]
    total:   int


# ─────────────────────────────────────────────────────────────────────────────
# Grants — requests & responses
# ─────────────────────────────────────────────────────────────────────────────

class CreateGrantRequest(BaseModel):
    grantee_id_hex:     str
    record_id:          str
    permission_level:   str
    time_start:         str    # ISO 8601 datetime string
    time_end:           str    # ISO 8601 datetime string
    dek_bundle_grantee: Dict[str, Any]
    signature_hex:      str

    @field_validator("permission_level")
    @classmethod
    def validate_permission(cls, v: str) -> str:
        if v not in ("view_only", "view_download"):
            raise ValueError("permission_level must be 'view_only' or 'view_download'.")
        return v


class RevokeGrantRequest(BaseModel):
    grant_id: str


class GrantResponse(BaseModel):
    grant_id:            str
    record_id:           str
    grantor_key_hash:    Optional[str] = None
    grantee_key_hash:    Optional[str] = None
    grantee_user_id_hex: Optional[str] = None
    permission_level:    str
    time_start:          Optional[str] = None
    time_end:            Optional[str] = None
    revoked:             bool          = False
    created_at:          Optional[str] = None
    retrieved_at:        Optional[str] = None


class GrantListResponse(BaseModel):
    grants: List[GrantResponse]


class AccessCheckResponse(BaseModel):
    has_access:       bool
    grant:            Optional[GrantResponse] = None
    permission_level: Optional[str]           = None


class GrantDetailsResponse(GrantResponse):
    dek_bundle_grantee: Optional[Dict[str, Any]] = None


# ─────────────────────────────────────────────────────────────────────────────
# Shares (legacy — kept for backward-compat with old routes/shares.py)
# ─────────────────────────────────────────────────────────────────────────────

class CreateShareRequest(BaseModel):
    """Used by the legacy direct-share flow (not the relay flow)."""
    grantee_user_id_hex: str
    ciphertext_b64:      str
    dek_bundle:          str
    nonce:               str
    filename:            str
    mime_type:           str
    size_bytes:          int
    file_hash:           Optional[str] = None
    signature:           str
    payload_canon:       Optional[str] = None
    expires_hours:       int           = 24
    delete_on_download:  bool          = True
    permission_level:    str           = "view_only"


class ShareSummary(BaseModel):
    share_id:         str
    short_code:       Optional[str]      = None
    filename:         str
    mime_type:        Optional[str]      = None
    size_bytes:       Optional[int]      = None
    owner_username:   Optional[str]      = None
    grantee_username: Optional[str]      = None
    created_at:       Optional[datetime] = None
    expires_at:       Optional[datetime] = None
    delete_on_download: bool             = True
    status:           str                = "active"
    permission_level: str                = "view_only"

    model_config = {"from_attributes": True}


class ShareDetail(ShareSummary):
    dek_bundle:     Optional[str] = None
    nonce:          Optional[str] = None
    signature:      Optional[str] = None
    ciphertext_url: Optional[str] = None


class VaultRecordMeta(BaseModel):
    """Used by legacy vault routes."""
    record_id:  str
    filename:   str
    mime_type:  str
    size_bytes: int
    iv_hex:     str
    tags:       List[Any]      = []
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class GrantRequest(BaseModel):
    """Used by legacy vault grant routes."""
    record_id:              str
    grantee_user_id_hex:    str
    grantee_public_key_hex: str
    permission_level:       str
    time_start:             datetime
    time_end:               datetime
    dek_bundle_grantee:     Dict[str, Any]
    signature_hex:          str
