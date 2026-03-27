"""
Authentication Routes
Location: src/api/routes/auth.py

Thin HTTP layer — all logic lives in RegistrationService.
"""

from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

from slowapi import Limiter
from slowapi.util import get_remote_address

from src.services.registration import (
    RegistrationService, UserAlreadyExistsError, AuthenticationError, RegistrationError
)

limiter  = Limiter(key_func=get_remote_address)
router   = APIRouter(prefix="/api/auth", tags=["authentication"])
_service = RegistrationService()   # singleton — store is already a singleton inside


# ── Request / Response schemas ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:     EmailStr
    password:  str = Field(..., min_length=8)
    username:  str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = ""
    role:      Optional[str] = "PATIENT"
    # Production SSI path (only needed when keygen_on_server=false in config)
    public_key_hex:        Optional[str] = None
    public_key_compressed: Optional[str] = None
    public_key_hash:       Optional[str] = None

class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register", status_code=201)
@limiter.limit("10/minute")
async def register(request: Request, body: RegisterRequest):
    """
    Register a new user.
    Server generates the keypair (config keygen_on_server=true).
    Returns private_key_pem ONCE — save it immediately.
    """
    try:
        result = _service.register(
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
    """Authenticate with email + password. Returns JWT."""
    try:
        result = _service.login(body.email, body.password)
        return result.to_dict()
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.get("/me", status_code=200)
async def me(request: Request):
    """Return profile of the currently authenticated user."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = auth.split(" ", 1)[1]
    try:
        payload = RegistrationService.verify_token(token)
        user_id = int(payload["sub"])
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))

    store = _service.store
    user  = store.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Return safe fields only (no password_hash)
    return {
        "user_id":              user["id"],
        "email":                user["email"],
        "username":             user["username"],
        "full_name":            user["full_name"],
        "role":                 user["role"],
        "public_key_hash":      user["public_key_hash"],
        "public_key_compressed":user["public_key_compressed"],
        "is_active":            user["is_active"],
        "created_at":           user["created_at"],
        "last_login":           user.get("last_login"),
    }


@router.get("/health")
async def health():
    return {"status": "ok", "service": "auth", "timestamp": datetime.utcnow().isoformat()}
