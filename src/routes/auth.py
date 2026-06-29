"""
routes/auth.py — Authentication endpoints.

Public:
  POST /auth/pow/challenge           → issue PoW challenge
  POST /auth/pow/verify              → verify PoW solution
  POST /auth/register                → register user
  POST /auth/verify-email            → verify email code
  POST /auth/resend-verification     → resend verification code
  POST /auth/login                   → login (password [+ TOTP])
  POST /auth/verify-totp-login       → TOTP second factor
  POST /auth/refresh                 → rotate refresh token
  POST /auth/request-password-reset  → request reset code
  POST /auth/confirm-password-reset  → confirm reset + new password

Protected (JWT required):
  POST /auth/logout                  → logout current device
  POST /auth/logout-all              → logout all devices
  POST /auth/change-password         → change password
  POST /auth/totp/setup              → begin TOTP setup
  POST /auth/totp/confirm            → confirm TOTP setup
  POST /auth/totp/disable            → disable TOTP
  GET  /auth/me                      → current user profile
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from database.exceptions import DuplicateError, RecordNotFoundError
from models.schemas import (
    ChangePasswordRequest, ConfirmPasswordResetRequest, ConfirmTOTPRequest,
    DisableTOTPRequest, LoginRequest, LoginResponse, LogoutRequest,  # Added LoginRequest
    MessageResponse, POWChallengeResponse, POWVerifyRequest,
    RefreshTokenRequest, RegisterRequest,
    RequestPasswordResetRequest, ResendVerificationRequest,
    SetupTOTPRequest, TOTPSetupResponse, TokenResponse, UserResponse,
    VerifyEmailRequest, VerifyTOTPLoginRequest,
)
from services.auth_service import AuthService

from .deps import get_auth_service, get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


def _user_response(user: dict) -> UserResponse:
    return UserResponse(
        user_id_hex=user.get("user_id_hex", ""),
        username=user.get("username", ""),
        email=user.get("email", ""),
        full_name=user.get("full_name", ""),
        role=user.get("role", "PATIENT"),
        is_verified=bool(user.get("is_verified")),
        totp_enabled=bool(user.get("totp_enabled")),
        created_at=str(user["created_at"]) if user.get("created_at") else None,
        last_login_at=str(user["last_login_at"]) if user.get("last_login_at") else None,
    )


def _token_response(result: dict) -> TokenResponse:
    return TokenResponse(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        token_type=result.get("token_type", "bearer"),
        expires_in=result.get("expires_in", 3600),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Proof of Work
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/pow/challenge", response_model=POWChallengeResponse)
async def pow_challenge(
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Issue a Proof-of-Work challenge. Client must solve before registering."""
    try:
        result = await auth_svc.issue_pow_challenge(
            ip_address=request.client.host if request.client else "",
        )
        return POWChallengeResponse(**result)
    except Exception:
        log.exception("pow_challenge failed")
        raise HTTPException(500, "Internal server error")


@router.post("/pow/verify", response_model=MessageResponse)
async def pow_verify(
    body: POWVerifyRequest,
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Verify a PoW solution. Returns success or 400 on invalid solution."""
    try:
        ok = await auth_svc.verify_pow_challenge(
            challenge_id=body.challenge_id,
            solution=body.solution,
            ip_address=request.client.host if request.client else "",
        )
        if not ok:
            raise HTTPException(400, "Invalid proof-of-work solution.")
        return MessageResponse(message="Proof of work verified.")
    except HTTPException:
        raise
    except Exception:
        log.exception("pow_verify failed")
        raise HTTPException(500, "Internal server error")


# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/register", response_model=MessageResponse, status_code=202)
async def register(
    body: RegisterRequest,
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Register a new user. Sends a verification code to the provided email."""
    try:
        result = await auth_svc.register_user(
            email=body.email,
            username=body.username,
            password=body.password,
            full_name=body.full_name,
            signing_public_key=body.signing_public_key,
            exchange_public_key=body.exchange_public_key,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message=result["message"])
    except DuplicateError as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("register failed")
        raise HTTPException(500, "Internal server error")


# ─────────────────────────────────────────────────────────────────────────────
# Email verification
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/verify-email", response_model=LoginResponse)
async def verify_email(
    body: VerifyEmailRequest,
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """
    Verify email code and auto-login.

    Stage 2 of registration. On success creates the user account and
    returns tokens — the client is immediately authenticated.
    body.email + body.code (user_id_hex field is ignored if present).
    """
    try:
        result = await auth_svc.verify_email(
            email=body.email,
            code=body.code,
            ip_address=request.client.host if request.client else "",
        )
        if result.get("requires_totp"):
            return LoginResponse(
                requires_totp=True,
                user_id_hex=result.get("user_id_hex"),
            )
        return LoginResponse(
            tokens=_token_response(result),
            user=_user_response(result["user"]),
        )
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("verify_email failed")
        raise HTTPException(500, "Internal server error")


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Resend the email verification code to a pending registration."""
    try:
        result = await auth_svc.resend_verification_code(
            email=body.email,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message=result.get("message", "Verification code sent."))
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("resend_verification failed")
        raise HTTPException(500, "Internal server error")


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,  # ✅ Use actual type, no quotes
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """
    Authenticate with email + password.
    Returns tokens on success, or requires_totp=True if TOTP is enabled.
    """
    try:  # ✅ No local import needed
        result = await auth_svc.login(
            email=body.email,
            password=body.password,
            ip_address=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent"),
        )
        if result.get("requires_totp"):
            return LoginResponse(
                requires_totp=True,
                user_id_hex=result.get("user_id_hex"),
            )
        return LoginResponse(
            requires_totp=False,
            tokens=_token_response(result),
            user=_user_response(result["user"]),
        )
    except ValueError as exc:
        raise HTTPException(401, str(exc))
    except Exception:
        log.exception("login failed")
        raise HTTPException(500, "Internal server error")


@router.post("/verify-totp-login", response_model=LoginResponse)
async def verify_totp_login(
    body: VerifyTOTPLoginRequest,
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Complete login with TOTP second factor."""
    try:
        result = await auth_svc.verify_totp_login(
            user_id_hex=body.user_id_hex,
            totp_code=body.totp_code,
            ip_address=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent"),
        )
        return LoginResponse(
            requires_totp=False,
            tokens=_token_response(result),
            user=_user_response(result["user"]),
        )
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(401, str(exc))
    except Exception:
        log.exception("verify_totp_login failed")
        raise HTTPException(500, "Internal server error")


# ─────────────────────────────────────────────────────────────────────────────
# Token management
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshTokenRequest,
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Rotate a refresh token — returns a new access + refresh token pair."""
    try:
        result = await auth_svc.refresh_access_token(
            refresh_token=body.refresh_token,
            ip_address=request.client.host if request.client else "",
        )
        return _token_response(result)
    except ValueError as exc:
        raise HTTPException(401, str(exc))
    except Exception:
        log.exception("refresh failed")
        raise HTTPException(500, "Internal server error")


@router.post("/logout", response_model=MessageResponse)
async def logout(
    body: LogoutRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Logout from the current device."""
    try:
        await auth_svc.logout(
            user_id_hex=current_user["user_id_hex"],
            refresh_token=body.refresh_token,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="Logged out successfully.")
    except Exception:
        log.exception("logout failed")
        raise HTTPException(500, "Internal server error")


@router.post("/logout-all", response_model=MessageResponse)
async def logout_all(
    request: Request,
    current_user: dict = Depends(get_current_user),
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Logout from all devices by revoking all tokens."""
    try:
        await auth_svc.logout_all_devices(
            user_id_hex=current_user["user_id_hex"],
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="Logged out from all devices.")
    except Exception:
        log.exception("logout_all failed")
        raise HTTPException(500, "Internal server error")


# ─────────────────────────────────────────────────────────────────────────────
# Password management
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Change password — requires current password. Revokes all sessions."""
    try:
        await auth_svc.change_password(
            user_id_hex=current_user["user_id_hex"],
            old_password=body.old_password,
            new_password=body.new_password,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="Password changed. Please log in again.")
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("change_password failed")
        raise HTTPException(500, "Internal server error")


@router.post("/request-password-reset", response_model=MessageResponse)
async def request_password_reset(
    body: RequestPasswordResetRequest,
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Send a password reset code to an email address."""
    try:
        result = await auth_svc.request_password_reset(
            email=body.email,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message=result["message"])
    except Exception:
        log.exception("request_password_reset failed")
        raise HTTPException(500, "Internal server error")


@router.post("/confirm-password-reset", response_model=MessageResponse)
async def confirm_password_reset(
    body: ConfirmPasswordResetRequest,
    request: Request,
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Verify reset code and set a new password."""
    try:
        await auth_svc.confirm_password_reset(
            email=body.email,
            code=body.code,
            new_password=body.new_password,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="Password reset successfully. Please log in.")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("confirm_password_reset failed")
        raise HTTPException(500, "Internal server error")


# ─────────────────────────────────────────────────────────────────────────────
# TOTP
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/totp/setup", response_model=TOTPSetupResponse)
async def totp_setup(
    request: Request,
    current_user: dict = Depends(get_current_user),
    auth_svc: AuthService = Depends(get_auth_service),
):
    """
    Begin TOTP setup. Returns provisioning URI + backup codes.
    Backup codes are shown ONCE — store them safely.
    """
    try:
        result = await auth_svc.setup_totp(
            user_id_hex=current_user["user_id_hex"],
            ip_address=request.client.host if request.client else "",
        )
        return TOTPSetupResponse(uri=result["uri"], backup_codes=result["backup_codes"])
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except Exception:
        log.exception("totp_setup failed")
        raise HTTPException(500, "Internal server error")


@router.post("/totp/confirm", response_model=MessageResponse)
async def totp_confirm(
    body: ConfirmTOTPRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Confirm TOTP setup with a live 6-digit code from the authenticator app."""
    try:
        await auth_svc.confirm_totp(
            user_id_hex=current_user["user_id_hex"],
            totp_code=body.totp_code,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="TOTP enabled successfully.")
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("totp_confirm failed")
        raise HTTPException(500, "Internal server error")


@router.post("/totp/disable", response_model=MessageResponse)
async def totp_disable(
    body: DisableTOTPRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Disable TOTP — requires password + current TOTP code."""
    try:
        await auth_svc.disable_totp(
            user_id_hex=current_user["user_id_hex"],
            password=body.password,
            totp_code=body.totp_code,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="TOTP disabled. All sessions have been revoked.")
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("totp_disable failed")
        raise HTTPException(500, "Internal server error")


# ─────────────────────────────────────────────────────────────────────────────
# Profile
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/me", response_model=UserResponse)
async def me(
    current_user: dict = Depends(get_current_user),
    auth_svc: AuthService = Depends(get_auth_service),
):
    """Return the currently authenticated user's profile."""
    try:
        user = await auth_svc.db.get_user_by_id_hex(current_user["user_id_hex"])
        if not user:
            raise HTTPException(404, "User not found.")
        return _user_response(user)
    except HTTPException:
        raise
    except Exception:
        log.exception("me failed")
        raise HTTPException(500, "Internal server error")
