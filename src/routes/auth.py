"""
src/routes/auth.py
Authentication routes:
  POST /api/auth/pow              — generate PoW challenge
  POST /api/auth/verify-pow       — verify PoW, open session
  POST /api/auth/submit-email     — submit email for code
  POST /api/auth/verify-email     — verify 6-digit code
  POST /api/auth/verify-totp      — verify TOTP token
  POST /api/auth/create-account   — create account (final step)
  POST /api/login                 — password login
  POST /api/auth/logout           — logout (revoke token + clear cookie)
  POST /api/auth/refresh          — rotate refresh token
  GET  /api/me                    — current user info
  POST /api/users/keys            — upload public keys after registration
  GET  /api/users/:username/keys  — get public keys for a user
"""
import logging
from datetime import timezone
from fastapi import APIRouter, HTTPException, Response, Request, status, Depends
from jose import JWTError

from src.services.database import DB
from src.services.auth_service import (
    hash_password, verify_password,
    create_access_token, decode_access_token,
    revoke_token, create_refresh_token, rotate_refresh_token,
    revoke_all_refresh_tokens,
)
from src.services.config import get_settings
from src.middleware.auth_middleware import get_current_user, CurrentUser
from src.models.schemas import (
    LoginRequest, RegisterStep1Request, RegisterStep2Request,
    RegisterStep3Request, RegisterStep4Request, RegisterStep5Request,
    PublicKeysUpload, RefreshRequest, MeResponse, UserPublicKeys,
    MessageResponse,
)

# We re-use the Node.js authFlow via in-process session map stored in memory.
# For the Python backend we implement the same logic directly.
import hashlib
import secrets
import time
import pyotp
import qrcode
import io
import base64

logger = logging.getLogger("medledger.auth")
router = APIRouter()
settings = get_settings()

# ── In-memory registration sessions (mirrors Node.js authFlow) ────────────────
_sessions: dict[str, dict] = {}
POW_DIFFICULTY = 4  # leading hex zeros


def _set_cookie(response: Response, name: str, value: str, max_age: int, httponly: bool = True):
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=httponly,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        path="/",
    )


def _clear_cookie(response: Response, name: str):
    response.delete_cookie(key=name, path="/", domain=settings.cookie_domain)


# ── PoW ───────────────────────────────────────────────────────────────────────

_pow_challenges: dict[str, dict] = {}


@router.post("/auth/pow")
async def init_pow():
    challenge_id = secrets.token_hex(16)
    challenge = secrets.token_hex(32)
    _pow_challenges[challenge_id] = {
        "challenge": challenge,
        "difficulty": POW_DIFFICULTY,
        "created_at": time.time(),
        "used": False,
    }
    # Prune old challenges
    cutoff = time.time() - 300
    stale = [k for k, v in _pow_challenges.items() if v["created_at"] < cutoff]
    for k in stale:
        del _pow_challenges[k]
    return {"challenge_id": challenge_id, "challenge": challenge, "difficulty": POW_DIFFICULTY}


@router.post("/auth/verify-pow")
async def verify_pow(body: RegisterStep1Request):
    entry = _pow_challenges.get(body.challenge_id)
    if not entry:
        raise HTTPException(400, "Invalid or expired challenge")
    if entry["used"]:
        raise HTTPException(400, "Challenge already used")
    if time.time() - entry["created_at"] > 300:
        raise HTTPException(400, "Challenge expired")

    # Verify: SHA-256(challenge + nonce) starts with POW_DIFFICULTY hex zeros
    digest = hashlib.sha256(f"{entry['challenge']}{body.nonce}".encode()).hexdigest()
    if not digest.startswith("0" * POW_DIFFICULTY):
        raise HTTPException(400, "Invalid proof-of-work solution")

    entry["used"] = True
    session_token = secrets.token_hex(32)
    _sessions[session_token] = {
        "pow_verified": True,
        "email_verified": False,
        "totp_verified": False,
        "email": None,
        "totp_secret": None,
        "created_at": time.time(),
    }
    return {"session_token": session_token, "message": "PoW verified"}


# ── Email ─────────────────────────────────────────────────────────────────────

import random

_email_codes: dict[str, dict] = {}


@router.post("/auth/submit-email")
async def submit_email(body: RegisterStep2Request):
    session = _sessions.get(body.session_token)
    if not session or not session["pow_verified"]:
        raise HTTPException(400, "Invalid session")

    # Check email not already registered
    async with DB() as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM users WHERE lower(email) = lower($1)", body.email
        )
    if exists:
        raise HTTPException(409, "Email already registered")

    code = f"{secrets.randbelow(1000000):06d}"
    _email_codes[body.email] = {
        "code": code,
        "attempts": 0,
        "created_at": time.time(),
    }
    session["email"] = body.email

    # In production: send actual email here
    # For development, log the code
    logger.info(f"[DEV] Email code for {body.email}: {code}")

    masked = body.email[:3] + "***@" + body.email.split("@")[-1]
    return {"message": f"Code sent to {masked}", "expires_in": 600, "email": masked}


@router.post("/auth/verify-email")
async def verify_email(body: RegisterStep3Request):
    session = _sessions.get(body.session_token)
    if not session or not session.get("email"):
        raise HTTPException(400, "Invalid session")

    email = session["email"]
    entry = _email_codes.get(email)
    if not entry:
        raise HTTPException(400, "No code found for this email")
    if time.time() - entry["created_at"] > 600:
        raise HTTPException(400, "Code expired")
    if entry["attempts"] >= 3:
        raise HTTPException(429, "Too many attempts")

    if entry["code"] != body.code:
        entry["attempts"] += 1
        raise HTTPException(400, f"Invalid code. {3 - entry['attempts']} attempts left")

    # Generate TOTP secret
    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=email, issuer_name="MedLedger"
    )

    # Generate QR code as base64 data URL
    qr = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    session["email_verified"] = True
    session["totp_secret"] = totp_secret
    del _email_codes[email]

    return {
        "message": "Email verified",
        "totp": {
            "qr_code_uri": totp_uri,
            "manual_key": totp_secret,
            "qr_code": f"data:image/png;base64,{qr_b64}",
        },
    }


# ── TOTP ──────────────────────────────────────────────────────────────────────

@router.post("/auth/verify-totp")
async def verify_totp(body: RegisterStep4Request):
    session = _sessions.get(body.session_token)
    if not session or not session.get("email_verified"):
        raise HTTPException(400, "Invalid session")

    totp = pyotp.TOTP(session["totp_secret"])
    if not totp.verify(body.totp_token, valid_window=1):
        raise HTTPException(400, "Invalid TOTP token")

    session["totp_verified"] = True
    return {"message": "TOTP verified"}


# ── Create account ────────────────────────────────────────────────────────────

@router.post("/auth/create-account")
async def create_account(body: RegisterStep5Request):
    session = _sessions.get(body.session_token)
    if not session:
        raise HTTPException(400, "Invalid session")
    if not session.get("totp_verified"):
        raise HTTPException(400, "Complete all verification steps first")

    async with DB() as conn:
        # Username uniqueness (case-insensitive)
        exists = await conn.fetchval(
            "SELECT 1 FROM users WHERE lower(username) = lower($1)", body.username
        )
        if exists:
            raise HTTPException(409, "Username already taken")

        pw_hash = hash_password(body.password)
        row = await conn.fetchrow(
            """
            INSERT INTO users (username, email, password_hash, is_verified, is_active, user_id_hex)
            VALUES (lower($1), $2, $3, TRUE, TRUE, encode(gen_random_bytes(16), 'hex'))
            RETURNING id, user_id_hex, username
            """,
            body.username, session["email"], pw_hash,
        )

    del _sessions[body.session_token]
    return {
        "message": "Account created",
        "user_id": row["user_id_hex"] or str(row["id"]),
        "username": row["username"],
    }


# ── Upload public keys ────────────────────────────────────────────────────────

@router.post("/users/keys")
async def upload_public_keys(
    body: PublicKeysUpload,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        await conn.execute(
            """
            UPDATE users
            SET signing_public_key  = $1,
                exchange_public_key = $2,
                user_id_hex         = $3
            WHERE lower(username) = lower($4)
            """,
            body.signing_public_key,
            body.exchange_public_key,
            body.user_id_hex,
            body.username,
        )
    return {"message": "Public keys stored"}


# ── Get public keys for a user ────────────────────────────────────────────────

@router.get("/users/{username}/keys")
async def get_user_keys(
    username: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        row = await conn.fetchrow(
            """
            SELECT signing_public_key, exchange_public_key
            FROM users
            WHERE lower(username) = lower($1) AND is_active = TRUE AND account_deleted = FALSE
            """,
            username,
        )
    if not row:
        raise HTTPException(404, "User not found")
    return {
        "signing_public_key": row["signing_public_key"],
        "exchange_public_key": row["exchange_public_key"],
    }


# ── Login ─────────────────────────────────────────────────────────────────────

@router.post("/login")
async def login(body: LoginRequest, response: Response, request: Request):
    async with DB() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, user_id_hex, username, password_hash, full_name, role,
                   signing_public_key, exchange_public_key, is_active, account_deleted
            FROM users
            WHERE lower(username) = lower($1)
            """,
            body.username,
        )

    if not row or not row["is_active"] or row["account_deleted"]:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if not verify_password(body.password, row["password_hash"]):
        # Audit log failed attempt
        async with DB() as conn:
            await conn.execute(
                "INSERT INTO user_audit (user_id, action, description, ip_address) VALUES ($1,$2,$3,$4)",
                row["id"], "login_failure", "Bad password",
                request.client.host if request.client else None,
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    user_id_hex = row["user_id_hex"] or str(row["id"])
    access_token = create_access_token(user_id_hex, row["username"])
    refresh_raw = await create_refresh_token(user_id_hex)

    _set_cookie(response, "access_token", access_token, max_age=30 * 60)
    _set_cookie(response, "refresh_token", refresh_raw, max_age=7 * 24 * 3600)

    async with DB() as conn:
        await conn.execute(
            "UPDATE users SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2",
            request.client.host if request.client else None,
            row["id"],
        )
        await conn.execute(
            "INSERT INTO user_audit (user_id, action, description, ip_address) VALUES ($1,$2,$3,$4)",
            row["id"], "login_success", "", request.client.host if request.client else None,
        )

    return {
        "username": row["username"],
        "user_id_hex": user_id_hex,
        "full_name": row["full_name"],
        "role": row["role"],
        "public_keys": {
            "signing_public_key": row["signing_public_key"],
            "exchange_public_key": row["exchange_public_key"],
        },
    }


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/auth/logout")
async def logout(
    response: Response,
    current_user: CurrentUser = Depends(get_current_user),
):
    # Revoke current access token
    try:
        payload = decode_access_token(
            # We already validated in the dependency; just need exp for TTL
            # Re-read from cookie isn't straightforward here, so we use current_user.jti
            # and a far-future expires to ensure it's always stored
        )
    except Exception:
        pass

    from datetime import datetime, timedelta, timezone
    await revoke_token(
        current_user.jti,
        current_user.user_id_hex,
        datetime.now(timezone.utc) + timedelta(hours=1),
    )
    await revoke_all_refresh_tokens(current_user.user_id_hex)

    _clear_cookie(response, "access_token")
    _clear_cookie(response, "refresh_token")
    return {"message": "Logged out"}


# ── Refresh ───────────────────────────────────────────────────────────────────

@router.post("/auth/refresh")
async def refresh_token_endpoint(request: Request, response: Response):
    raw = request.cookies.get("refresh_token")
    if not raw:
        raise HTTPException(401, "No refresh token")

    result = await rotate_refresh_token(raw)
    if not result:
        _clear_cookie(response, "access_token")
        _clear_cookie(response, "refresh_token")
        raise HTTPException(401, "Invalid or expired refresh token")

    new_raw, user_id_hex = result

    async with DB() as conn:
        row = await conn.fetchrow(
            "SELECT username FROM users WHERE user_id_hex = $1", user_id_hex
        )
    if not row:
        raise HTTPException(401, "User not found")

    access_token = create_access_token(user_id_hex, row["username"])
    _set_cookie(response, "access_token", access_token, max_age=30 * 60)
    _set_cookie(response, "refresh_token", new_raw, max_age=7 * 24 * 3600)
    return {"message": "Token refreshed"}


# ── /api/me ───────────────────────────────────────────────────────────────────

@router.get("/me", response_model=MeResponse)
async def me(current_user: CurrentUser = Depends(get_current_user)):
    async with DB() as conn:
        row = await conn.fetchrow(
            """
            SELECT username, user_id_hex, full_name, role,
                   signing_public_key, exchange_public_key, is_verified
            FROM users
            WHERE user_id_hex = $1
            """,
            current_user.user_id_hex,
        )
    if not row:
        raise HTTPException(404, "User not found")
    return MeResponse(
        username=row["username"],
        user_id_hex=row["user_id_hex"],
        full_name=row["full_name"] or "",
        role=row["role"],
        public_keys=UserPublicKeys(
            signing_public_key=row["signing_public_key"],
            exchange_public_key=row["exchange_public_key"],
        ),
        is_verified=row["is_verified"],
    )
