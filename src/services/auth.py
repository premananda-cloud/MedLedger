"""
Authentication Routes
Location: src/services/auth.py  (also served as src/api/routes/auth.py)

Thin HTTP layer — all logic lives in RegistrationService.
Fixed vs original:
  - No longer imports get_db / SQLAlchemy session (store is config-driven)
  - RegistrationService() takes no args (singleton store inside)
  - verify_token is a @staticmethod, called correctly
  - Removed duplicate route file confusion
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime, timezone

from slowapi import Limiter
from slowapi.util import get_remote_address

from src.services.registration import (
    RegistrationService, UserAlreadyExistsError, AuthenticationError,
    RegistrationError, InvalidTokenError, PasswordResetError,
)
from src.api.deps import require_auth, CallerIdentity
from src.database import get_user_store

limiter  = Limiter(key_func=get_remote_address)
router   = APIRouter(prefix="/api/auth", tags=["authentication"])
_service: "RegistrationService | None" = None


def _get_service() -> RegistrationService:
    global _service
    if _service is None:
        _service = RegistrationService()
    return _service


# ── Request schemas ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:     EmailStr
    password:  str = Field(..., min_length=8)
    username:  str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = ""
    role:      Optional[str] = "PATIENT"
    # Production SSI path — only needed when keygen_on_server=false in config
    public_key_hex:        Optional[str] = None
    public_key_compressed: Optional[str] = None
    public_key_hash:       Optional[str] = None

class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


class VerifyRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str = Field(..., min_length=8)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register", status_code=201)
@limiter.limit("10/minute")
async def register(request: Request, body: RegisterRequest):
    """
    Register a new user. Server generates the P-256 keypair (keygen_on_server=true).
    Returns private_key_pem ONCE — save it immediately, it is never stored.
    """
    try:
        result = _get_service().register(
            email=body.email,
            password=body.password,
            username=body.username,
            full_name=body.full_name or "",
            role=body.role or "PATIENT",
            public_key_hex=body.public_key_hex,
            public_key_compressed=body.public_key_compressed,
            public_key_hash=body.public_key_hash,
        )
        return result.to_dict()
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except RegistrationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login", status_code=200)
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest):
    """Authenticate with email + password. Returns JWT and public key material."""
    try:
        result = _get_service().login(body.email, body.password)
        return result.to_dict()
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/verify", status_code=200)
@limiter.limit("10/minute")
async def verify_email(request: Request, body: VerifyRequest):
    """
    Verify email with the token sent to the user's inbox.
    Returns private_key_pem ONCE — the client must save it immediately.
    It is never stored server-side.
    """
    try:
        result = _get_service().verify_email(body.token)
        return result.to_dict()
    except InvalidTokenError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/forgot-password", status_code=200)
@limiter.limit("5/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest):
    """
    Request a password-reset token.
    Always returns 200 to prevent user enumeration.
    In dev the plaintext token is returned directly in the response.
    In production you would email it instead and return only {"status": "sent"}.
    """
    result = _get_service().request_password_reset(body.email)
    return result.to_dict()


@router.post("/reset-password", status_code=200)
@limiter.limit("10/minute")
async def reset_password(request: Request, body: ResetPasswordRequest):
    """
    Complete a password reset using the token from /forgot-password.
    The token is valid for 30 minutes and single-use.
    """
    try:
        _get_service().confirm_password_reset(body.token, body.new_password)
        return {"status": "ok", "message": "Password updated. Please log in."}
    except PasswordResetError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/me", status_code=200)
async def me(caller: CallerIdentity = Depends(require_auth)):
    """
    Return profile of the currently authenticated user (requires Bearer token).
    Auth is handled by the require_auth dependency — no manual token parsing needed.
    """
    store = get_user_store()
    user  = store.get_by_id(caller.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "user_id":               user.id,
        "email":                 user.email,
        "username":              user.username,
        "full_name":             user.full_name,
        "role":                  user.role,
        "public_key_hash":       user.public_key_hash,
        "public_key_compressed": user.public_key_compressed,
        "is_active":             user.is_active,
        "created_at":            user.created_at,
        "last_login":            user.last_login,
    }


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "auth",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
