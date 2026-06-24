"""
middleware/auth.py — JWT authentication middleware.

Verifies the Bearer token on every request, checks JTI revocation,
and attaches user info to request.state for route handlers.

Responsibilities:
  ✓ Extract token from Authorization header
  ✓ Verify signature + expiry via TokenModule
  ✓ Check JTI revocation via DatabaseRepository
  ✓ Attach user_id_hex / username / email to request.state
  ✗ Not responsible for rate limiting
  ✗ Not responsible for role / permission checks (routes do that)
  ✗ Never raises — always returns a JSON response on failure
"""
from __future__ import annotations

import logging
from typing import Callable

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger(__name__)

# Routes that don't need a valid JWT
_PUBLIC_PREFIXES = (
    "/api/auth/pow/",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/verify-email",
    "/api/auth/resend-verification",
    "/api/auth/verify-totp-login",
    "/api/auth/refresh",
    "/api/auth/request-password-reset",
    "/api/auth/confirm-password-reset",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
)

_bearer = HTTPBearer(auto_error=False)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that validates JWTs for protected routes.

    Takes a TokenModule instance and an async factory that returns a
    DatabaseRepository bound to a fresh session — so revocation checks
    don't share sessions with route handlers.

    Usage (in main.py):
        app.add_middleware(
            AuthMiddleware,
            token_module=token_module,
            db_repo_factory=get_db_repo,
        )
    """

    def __init__(self, app, token_module, db_repo_factory: Callable):
        super().__init__(app)
        self._token   = token_module
        self._db_factory = db_repo_factory

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Let public routes through immediately
        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Extract Bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Not authenticated", "detail": "Missing Authorization header."},
            )

        raw_token = auth_header.removeprefix("Bearer ").strip()
        result    = self._token.verify_token(raw_token)

        if not result.valid:
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid token", "detail": result.error},
            )

        payload = result.payload

        # JTI revocation check
        try:
            repo    = await self._db_factory()
            revoked = await repo.is_token_revoked(payload.jti)
            if revoked:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Token revoked", "detail": "This token has been invalidated."},
                )
        except Exception:
            log.exception("JTI revocation check failed for jti=%s", payload.jti)
            # Fail open — don't block requests if the DB is temporarily unavailable.
            # Switch to fail-closed if your threat model demands it.

        # Attach to request state for route handlers
        request.state.user_id_hex = payload.sub
        request.state.username    = payload.username
        request.state.email       = payload.email
        request.state.jti         = payload.jti

        return await call_next(request)


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI dependency — get_current_user
# ─────────────────────────────────────────────────────────────────────────────

def get_current_user(request: Request) -> dict:
    """
    FastAPI dependency that extracts the authenticated user from request.state.

    Middleware must run before this. Returns a dict with:
        {user_id_hex, username, email}

    Raises:
        HTTPException 401 if the middleware didn't attach state
        (i.e. the route is incorrectly marked as public or middleware is missing).
    """
    user_id_hex = getattr(request.state, "user_id_hex", None)
    if not user_id_hex:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return {
        "user_id_hex": user_id_hex,
        "username":    getattr(request.state, "username", ""),
        "email":       getattr(request.state, "email", ""),
        "jti":         getattr(request.state, "jti", ""),
    }


# Alias kept for compatibility with old middleware import pattern
CurrentUser = dict
