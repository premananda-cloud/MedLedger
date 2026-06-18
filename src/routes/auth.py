"""
src/routes/auth.py

FastAPI router — exposes the AuthFlow orchestrator as REST endpoints.

Registration (4-step state machine):
  POST /auth/pow/init              → get PoW challenge
  POST /auth/pow/verify            → solve PoW, get session token
  POST /auth/email/submit          → send verification code
  POST /auth/email/verify          → verify code, get TOTP QR
  POST /auth/totp/verify           → confirm TOTP setup
  POST /auth/register              → create account (username + password + ciphertext)

Auth:
  POST /auth/login                 → password [+ TOTP] → JWT tokens
  POST /auth/logout                → revoke refresh token
  POST /auth/refresh               → rotate refresh token → new access token

Password reset:
  POST /auth/password-reset/init   → send reset code
  POST /auth/password-reset/complete → verify code + set new password

Misc:
  GET  /auth/session/{token}       → inspect registration session state
  GET  /auth/status                → system health / active sessions
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, field_validator

from src.auth.orchestrator.authFlow import AuthFlow
from src.services.database import get_db

# ---------------------------------------------------------------------------
# Router & shared singletons
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/auth", tags=["auth"])
bearer = HTTPBearer(auto_error=False)

# One shared AuthFlow instance (thread-safe per the docs)
_auth_flow: Optional[AuthFlow] = None


def get_auth_flow() -> AuthFlow:
    global _auth_flow
    if _auth_flow is None:
        _auth_flow = AuthFlow(
            session_expiry_minutes=int(os.getenv("AUTH_SESSION_EXPIRY_MINUTES", "30")),
            pow_difficulty=int(os.getenv("AUTH_POW_DIFFICULTY", "4")),
            blocklist_path=os.getenv("AUTH_EMAIL_BLOCKLIST_PATH"),
        )
    return _auth_flow


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))


def _make_access_token(user_id_hex: str, username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id_hex,
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": secrets.token_hex(16),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _make_refresh_token(user_id_hex: str, family_id: str) -> tuple[str, str]:
    """Returns (raw_token, token_hash). Store the hash; give raw to client."""
    raw = secrets.token_hex(40)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, token_hash


def _decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db=Depends(get_db),
) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = _decode_access_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Not an access token")
    # Check revocation
    if await db.is_token_revoked(payload["jti"]):
        raise HTTPException(status_code=401, detail="Token revoked")
    user = await db.get_user_by_id(payload["sub"])
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class PowVerifyRequest(BaseModel):
    challenge_id: str
    nonce: str


class EmailSubmitRequest(BaseModel):
    session_token: str
    email: EmailStr


class EmailVerifyRequest(BaseModel):
    session_token: str
    code: str


class TotpVerifyRequest(BaseModel):
    session_token: str
    token: str


class RegisterRequest(BaseModel):
    session_token: str
    username: str
    password: str
    # Client-generated public keys — front-end key-gen responsibility
    signing_public_key: str
    exchange_public_key: str
    # Encrypted private key bundle (ciphertext from client key-gen)
    encrypted_private_key_bundle: Optional[str] = None

    @field_validator("username")
    @classmethod
    def username_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("username must not be empty")
        return v.strip()


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_token: str = ""


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class PasswordResetInitRequest(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str


# ---------------------------------------------------------------------------
# Helper: turn AuthResponse into an HTTP error when step == "error"
# ---------------------------------------------------------------------------

def _check_auth_response(resp) -> dict:
    if resp.step == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=resp.data.get("message", "Auth error"),
        )
    return {
        "step": resp.step,
        "data": resp.data,
        "next_action": resp.next_action,
        **({"session_token": resp.session_token} if resp.session_token else {}),
    }


# ===========================================================================
# REGISTRATION FLOW
# ===========================================================================

# ---------------------------------------------------------------------------
# Step 1a — issue PoW challenge
# ---------------------------------------------------------------------------
@router.post("/pow/init", summary="Get a Proof-of-Work challenge")
async def pow_init():
    """
    Returns a SHA-256 challenge. Client must find a nonce whose hash
    starts with `difficulty` leading zeros, then call /pow/verify.
    """
    af = get_auth_flow()
    resp = af.init_pow()
    return _check_auth_response(resp)


# ---------------------------------------------------------------------------
# Step 1b — verify PoW solution → session token
# ---------------------------------------------------------------------------
@router.post("/pow/verify", summary="Submit PoW solution, receive session token")
async def pow_verify(body: PowVerifyRequest):
    af = get_auth_flow()
    resp = af.verify_pow(body.challenge_id, body.nonce)
    return _check_auth_response(resp)


# ---------------------------------------------------------------------------
# Step 2a — submit email → code sent
# ---------------------------------------------------------------------------
@router.post("/email/submit", summary="Submit email address for verification")
async def email_submit(body: EmailSubmitRequest):
    af = get_auth_flow()
    resp = af.submit_email(body.session_token, body.email)
    return _check_auth_response(resp)


# ---------------------------------------------------------------------------
# Step 2b — verify email code → TOTP QR returned
# ---------------------------------------------------------------------------
@router.post("/email/verify", summary="Verify email code, receive TOTP setup data")
async def email_verify(body: EmailVerifyRequest):
    af = get_auth_flow()
    resp = af.verify_email_code(body.session_token, body.code)
    return _check_auth_response(resp)


# ---------------------------------------------------------------------------
# Step 3 — confirm TOTP token
# ---------------------------------------------------------------------------
@router.post("/totp/verify", summary="Confirm TOTP setup with first token")
async def totp_verify(body: TotpVerifyRequest):
    af = get_auth_flow()
    resp = af.verify_totp(body.session_token, body.token)
    return _check_auth_response(resp)


# ---------------------------------------------------------------------------
# Step 4 — create account (persists to DB)
# ---------------------------------------------------------------------------
@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="Create account after completing all verification steps",
)
async def register(body: RegisterRequest, db=Depends(get_db)):
    """
    Final registration step.  The orchestrator validates the session and
    creates the user in its own storage.  We then mirror the record into
    PostgreSQL so the rest of the application can query it.

    The client is responsible for key-gen; it must supply:
      - signing_public_key   (hex or base64)
      - exchange_public_key  (hex or base64)
      - encrypted_private_key_bundle  (ciphertext, optional but expected)
    """
    af = get_auth_flow()

    # Check username uniqueness against the DB before hitting the orchestrator
    if await db.username_exists(body.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    # Let the orchestrator create the account in its own (file-backed) store
    resp = af.create_account_sync(
        body.session_token,
        username=body.username,
        password=body.password,
    )
    if resp.step == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=resp.data.get("message", "Registration failed"),
        )

    # ---- Mirror to PostgreSQL ------------------------------------------------
    # The orchestrator returns user_id and the hashed credentials via resp.data.
    # We store the public keys and the encrypted private key bundle (ciphertext)
    # supplied by the client.  Password hash comes from the orchestrator.

    orchestrator_user = resp.data  # contains user_id, username, email, etc.

    # Derive a stable user_id_hex from the signing public key
    user_id_hex = hashlib.sha256(body.signing_public_key.encode()).hexdigest()

    # Retrieve the password hash from the orchestrator's user store so we don't
    # duplicate hashing logic.  Fall back to a placeholder if unavailable (the
    # orchestrator is the source of truth for auth).
    try:
        orch_user_detail = af._user_manager.get_user(body.username)  # type: ignore[attr-defined]
        password_hash = getattr(orch_user_detail, "password_hash", "")
        pwhash_salt   = getattr(orch_user_detail, "salt", "")
        totp_secret   = getattr(orch_user_detail, "totp_secret", "")
    except Exception:
        password_hash = orchestrator_user.get("password_hash", "")
        pwhash_salt   = orchestrator_user.get("pwhash_salt", "")
        totp_secret   = ""

    db_user = await db.create_user({
        "user_id_hex":               user_id_hex,
        "username":                  body.username,
        "email":                     orchestrator_user.get("email", ""),
        "role":                      "PATIENT",
        "password_hash":             password_hash,
        "pwhash_salt":               pwhash_salt,
        "signing_public_key":        body.signing_public_key,
        "exchange_public_key":       body.exchange_public_key,
        # Store the TOTP secret as part of the exchange_public_key field or
        # a dedicated column if your schema has one.  Here we embed it in
        # server_salt so it travels with the user row and stays server-side.
        "server_salt":               totp_secret or secrets.token_hex(32),
        "is_verified":               True,
        "is_active":                 True,
    })

    if db_user is None:
        # Orchestrator succeeded but DB insert failed — rare; surface clearly
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Account created in auth store but failed to persist to database",
        )

    # Log audit event
    await db.log_audit({
        "actor_user_id_hex": user_id_hex,
        "action": "REGISTER",
        "detail": {"username": body.username},
    })

    return {
        "step":       "account_created",
        "user_id":    user_id_hex,
        "username":   body.username,
        "email":      orchestrator_user.get("email", ""),
        "created_at": db_user.get("created_at"),
    }


# ===========================================================================
# LOGIN
# ===========================================================================

@router.post("/login", summary="Authenticate with username + password [+ TOTP]")
async def login(body: LoginRequest, db=Depends(get_db)):
    """
    Returns:
      - step == "logged_in"      → access_token + refresh_token in response
      - step == "totp_required"  → 400 with hint to retry with totp_token
    """
    af = get_auth_flow()
    resp = af.login(
        username=body.username,
        password=body.password,
        totp_token=body.totp_token,
    )

    if resp.step == "totp_required":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"step": "totp_required", "message": "TOTP token required"},
        )

    if resp.step == "error":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=resp.data.get("message", "Invalid credentials"),
        )

    # Fetch full user record from DB for role / user_id_hex
    db_user = await db.get_user_by_username(body.username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User record not found in database")

    user_id_hex = db_user["user_id_hex"]
    role        = db_user.get("role", "PATIENT")
    family_id   = secrets.token_hex(16)

    access_token              = _make_access_token(user_id_hex, body.username, role)
    raw_refresh, refresh_hash = _make_refresh_token(user_id_hex, family_id)

    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    await db.store_refresh_token(refresh_hash, user_id_hex, family_id, expires_at)
    await db.update_user(user_id_hex, {"last_login_at": datetime.now(timezone.utc)})
    await db.log_audit({
        "actor_user_id_hex": user_id_hex,
        "action": "LOGIN",
        "detail": {"username": body.username},
    })

    return {
        "access_token":  access_token,
        "refresh_token": raw_refresh,
        "token_type":    "bearer",
        "expires_in":    ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# ===========================================================================
# REFRESH
# ===========================================================================

@router.post("/refresh", summary="Exchange refresh token for a new access token")
async def refresh_token(body: RefreshRequest, db=Depends(get_db)):
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()

    # Fetch by hash — no raw token touches the DB
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT token_hash, user_id_hex, family_id, expires_at, revoked_at
            FROM refresh_tokens
            WHERE token_hash = $1
            """,
            token_hash,
        )

    if row is None:
        raise HTTPException(status_code=401, detail="Refresh token not found")
    if row["revoked_at"] is not None:
        # Possible token theft — revoke entire family
        await db.revoke_refresh_token_family(row["family_id"])
        raise HTTPException(status_code=401, detail="Refresh token reuse detected; all sessions revoked")
    if row["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user_id_hex = row["user_id_hex"]
    db_user     = await db.get_user_by_id(user_id_hex)
    if not db_user or not db_user.get("is_active"):
        raise HTTPException(status_code=401, detail="User inactive")

    # Rotate: revoke old, issue new in same family
    await db.revoke_refresh_token(token_hash)
    family_id               = row["family_id"]
    new_raw, new_hash       = _make_refresh_token(user_id_hex, family_id)
    new_expires             = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    await db.store_refresh_token(new_hash, user_id_hex, family_id, new_expires)

    access_token = _make_access_token(
        user_id_hex,
        db_user["username"],
        db_user.get("role", "PATIENT"),
    )

    return {
        "access_token":  access_token,
        "refresh_token": new_raw,
        "token_type":    "bearer",
        "expires_in":    ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


# ===========================================================================
# LOGOUT
# ===========================================================================

@router.post("/logout", summary="Revoke refresh token (logout)")
async def logout(
    body: LogoutRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db=Depends(get_db),
):
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    await db.revoke_refresh_token(token_hash)

    # Also revoke the access token JTI if provided
    if credentials:
        try:
            payload    = _decode_access_token(credentials.credentials)
            jti        = payload.get("jti")
            exp        = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            user_id    = payload.get("sub", "")
            if jti:
                await db.revoke_token(jti, user_id, exp)
        except HTTPException:
            pass  # already expired — fine

    return {"message": "Logged out"}


# ===========================================================================
# PASSWORD RESET
# ===========================================================================

@router.post("/password-reset/init", summary="Request password reset code via email")
async def password_reset_init(body: PasswordResetInitRequest):
    af = get_auth_flow()
    # Always returns step='reset_code_sent' regardless of email existence
    resp = af.initiate_password_reset(body.email)
    return _check_auth_response(resp)


@router.post("/password-reset/complete", summary="Verify reset code and set new password")
async def password_reset_complete(body: PasswordResetCompleteRequest, db=Depends(get_db)):
    af = get_auth_flow()
    resp = af.complete_password_reset(
        email=body.email,
        code=body.code,
        new_password=body.new_password,
    )
    if resp.step == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=resp.data.get("message", "Password reset failed"),
        )

    # Revoke all refresh token families for this user as a security measure
    db_user = await db.get_user_by_email(body.email)
    if db_user:
        pool = await db.get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE refresh_tokens SET revoked_at = NOW() "
                "WHERE user_id_hex = $1 AND revoked_at IS NULL",
                db_user["user_id_hex"],
            )
        await db.log_audit({
            "actor_user_id_hex": db_user["user_id_hex"],
            "action": "PASSWORD_RESET",
            "detail": {"email": body.email},
        })

    return _check_auth_response(resp)


# ===========================================================================
# SESSION INSPECTION (registration flow helper)
# ===========================================================================

@router.get("/session/{session_token}", summary="Inspect a registration session's current state")
async def session_status(session_token: str):
    af = get_auth_flow()
    info = af.get_session_status(session_token)
    if not info:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    return info


# ===========================================================================
# SYSTEM STATUS
# ===========================================================================

@router.get("/status", summary="Auth system health / active sessions")
async def auth_status():
    af = get_auth_flow()
    return af.get_status()


# ===========================================================================
# PROTECTED ROUTE EXAMPLE — /auth/me
# ===========================================================================

@router.get("/me", summary="Return the authenticated user's profile")
async def me(current_user: dict = Depends(get_current_user)):
    return {
        "user_id":    current_user["user_id_hex"],
        "username":   current_user["username"],
        "email":      current_user["email"],
        "role":       current_user.get("role"),
        "is_verified": current_user.get("is_verified"),
        "created_at": current_user.get("created_at"),
    }
