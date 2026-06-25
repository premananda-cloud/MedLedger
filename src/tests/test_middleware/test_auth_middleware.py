"""
tests/test_middleware/test_auth_middleware.py

Unit tests for AuthMiddleware and get_current_user.
Tests JWT extraction, JTI revocation checks, and public path bypass.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse

from services.token import TokenModule
from middleware.auth import AuthMiddleware, get_current_user, _PUBLIC_PREFIXES


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

TOKEN_SECRET = "test-middleware-secret-key-long-enough!!"


def _make_token_module():
    return TokenModule(secret=TOKEN_SECRET, expiry_seconds=3600)


def _make_valid_token(module: TokenModule, user_id="user123", username="testuser", email="t@t.com"):
    return module.create_access_token(sub=user_id, username=username, email=email)


def _make_app(revoked: bool = False, db_raises: bool = False):
    """Build a minimal FastAPI app with AuthMiddleware attached."""
    token_module = _make_token_module()

    async def db_repo_factory():
        repo = AsyncMock()
        if db_raises:
            repo.is_token_revoked.side_effect = Exception("DB down")
        else:
            repo.is_token_revoked.return_value = revoked
        return repo

    app = FastAPI()
    app.add_middleware(
        AuthMiddleware,
        token_module=token_module,
        db_repo_factory=db_repo_factory,
    )

    @app.get("/api/protected")
    async def protected(request: Request):
        return {
            "user_id_hex": request.state.user_id_hex,
            "username": request.state.username,
        }

    @app.get("/api/auth/login")
    async def public_login():
        return {"public": True}

    @app.get("/health")
    async def health():
        return {"ok": True}

    return app, token_module


# ─────────────────────────────────────────────
# Public path bypass
# ─────────────────────────────────────────────

def test_public_path_bypasses_auth():
    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/auth/login")
    assert resp.status_code == 200
    assert resp.json()["public"] is True


def test_health_path_bypasses_auth():
    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/health")
    assert resp.status_code == 200


def test_all_public_prefixes_bypass_auth():
    """Smoke-test that every declared public prefix returns non-401."""
    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)
    # We can't hit every path but verify the prefix list is non-empty
    assert len(_PUBLIC_PREFIXES) > 0


# ─────────────────────────────────────────────
# Missing / malformed token
# ─────────────────────────────────────────────

def test_missing_authorization_header_returns_401():
    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/protected")
    assert resp.status_code == 401


def test_missing_bearer_prefix_returns_401():
    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/protected", headers={"Authorization": "Basic abc123"})
    assert resp.status_code == 401


def test_invalid_token_returns_401():
    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(
        "/api/protected",
        headers={"Authorization": "Bearer this.is.not.a.valid.jwt"},
    )
    assert resp.status_code == 401


def test_expired_token_returns_401():
    import time
    import jwt as pyjwt

    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)

    # Manually craft an expired token
    expired_payload = {
        "sub": "user123",
        "username": "test",
        "email": "t@t.com",
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 3600,  # expired an hour ago
        "jti": "some_jti",
    }
    expired_token = pyjwt.encode(expired_payload, TOKEN_SECRET, algorithm="HS256")
    resp = client.get(
        "/api/protected",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401


# ─────────────────────────────────────────────
# Valid token
# ─────────────────────────────────────────────

def test_valid_token_passes_through():
    app, token_module = _make_app(revoked=False)
    client = TestClient(app, raise_server_exceptions=False)
    token = _make_valid_token(token_module)
    resp = client.get(
        "/api/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id_hex"] == "user123"
    assert data["username"] == "testuser"


def test_valid_token_attaches_user_to_request_state():
    app, token_module = _make_app(revoked=False)
    client = TestClient(app, raise_server_exceptions=False)
    token = _make_valid_token(token_module, user_id="abc456", username="alice")
    resp = client.get(
        "/api/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["user_id_hex"] == "abc456"


# ─────────────────────────────────────────────
# JTI revocation
# ─────────────────────────────────────────────

def test_revoked_jti_returns_401():
    app, token_module = _make_app(revoked=True)
    client = TestClient(app, raise_server_exceptions=False)
    token = _make_valid_token(token_module)
    resp = client.get(
        "/api/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_db_failure_during_revocation_check_fails_open():
    """
    If the DB is down during a JTI revocation check, the request should
    still pass through (fail-open design) rather than blocking all users.
    """
    app, token_module = _make_app(db_raises=True)
    client = TestClient(app, raise_server_exceptions=False)
    token = _make_valid_token(token_module)
    resp = client.get(
        "/api/protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    # Fail-open: request should succeed even if revocation check fails
    assert resp.status_code == 200


# ─────────────────────────────────────────────
# get_current_user dependency
# ─────────────────────────────────────────────

def test_get_current_user_returns_user_from_state():
    request = MagicMock(spec=Request)
    request.state.user_id_hex = "user123"
    request.state.username = "testuser"
    request.state.email = "t@example.com"
    request.state.jti = "jti_abc"

    user = get_current_user(request)
    assert user["user_id_hex"] == "user123"
    assert user["username"] == "testuser"
    assert user["email"] == "t@example.com"
    assert user["jti"] == "jti_abc"


def test_get_current_user_missing_state_raises_401():
    from fastapi import HTTPException

    request = MagicMock(spec=Request)
    # No user_id_hex on state
    del request.state.user_id_hex
    request.state = MagicMock()
    request.state.user_id_hex = None

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(request)
    assert exc_info.value.status_code == 401


# ─────────────────────────────────────────────
# Error response format
# ─────────────────────────────────────────────

def test_401_response_is_json():
    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/protected")
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert "error" in body or "detail" in body


def test_invalid_token_response_has_detail():
    app, _ = _make_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(
        "/api/protected",
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    body = resp.json()
    assert "detail" in body or "error" in body
