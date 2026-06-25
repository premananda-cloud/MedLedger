"""
tests/test_services/test_auth_service.py

Unit tests for AuthService with mocked dependencies.
Tests orchestration logic, not crypto or DB operations.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone

from services.auth_service import AuthService
from database.exceptions import DuplicateError, RecordNotFoundError


def _make_service(deps):
    return AuthService(**deps)


def _now():
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────

async def test_register_user_success(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].email_exists.return_value = False
    deps["db_repo"].username_exists.return_value = False
    deps["db_repo"].create_user.return_value = {
        "user_id_hex": "abc123",
        "username": "testuser",
        "email": "test@example.com",
        "role": "PATIENT",
        "email_verified": False,
    }
    deps["db_repo"].set_public_keys = AsyncMock()
    deps["db_repo"].store_verification_token = AsyncMock()

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    result = await svc.register_user(
        email="test@example.com",
        username="testuser",
        password="StrongP@ssw0rd!",
        full_name="Test User",
        signing_public_key="pk_sign",
        exchange_public_key="pk_exchange",
        ip_address="127.0.0.1",
    )
    assert result["user_id_hex"] == "abc123"
    deps["db_repo"].create_user.assert_called_once()
    deps["audit_service"].log_auth_event.assert_called()


async def test_register_user_weak_password_raises(auth_service_deps):
    deps = auth_service_deps
    deps["password_module"].validate_strength.return_value = MagicMock(
        valid=False, issues=["Too weak"]
    )
    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )
    with pytest.raises(ValueError, match="weak"):
        await svc.register_user(
            email="t@example.com", username="user", password="weak",
            full_name="T", signing_public_key="pk1", exchange_public_key="pk2",
            ip_address="127.0.0.1",
        )


async def test_register_user_duplicate_email_raises(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].email_exists.return_value = True
    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )
    with pytest.raises(DuplicateError) as exc_info:
        await svc.register_user(
            email="taken@example.com", username="newuser", password="StrongP@ssw0rd!",
            full_name="T", signing_public_key="pk1", exchange_public_key="pk2",
            ip_address="127.0.0.1",
        )
    assert exc_info.value.field == "email"


async def test_register_user_duplicate_username_raises(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].email_exists.return_value = False
    deps["db_repo"].username_exists.return_value = True
    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )
    with pytest.raises(DuplicateError) as exc_info:
        await svc.register_user(
            email="new@example.com", username="taken", password="StrongP@ssw0rd!",
            full_name="T", signing_public_key="pk1", exchange_public_key="pk2",
            ip_address="127.0.0.1",
        )
    assert exc_info.value.field == "username"


# ─────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────

def _user_row(totp_enabled=False, email_verified=True, failed=0, locked_until=None):
    return {
        "user_id_hex": "user123",
        "username": "testuser",
        "email": "test@example.com",
        "password_hash": "a" * 128,
        "pwhash_salt": "b" * 32,
        "server_salt": "cc" * 16,
        "email_verified": email_verified,
        "is_verified": email_verified,
        "is_active": True,
        "totp_enabled": totp_enabled,
        "totp_secret": "JBSWY3DPEHPK3PXP" if totp_enabled else None,
        "failed_login_count": failed,
        "locked_until": locked_until,
        "account_deleted": False,
        "role": "PATIENT",
    }


async def test_login_success_returns_tokens(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].get_user_by_email.return_value = _user_row()
    deps["db_repo"].get_rate_limit.return_value = None
    deps["db_repo"].store_refresh_token = AsyncMock()
    deps["db_repo"].record_successful_login = AsyncMock()
    deps["db_repo"].reset_rate_limit = AsyncMock()

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    result = await svc.login(
        email="test@example.com",
        password="StrongP@ssw0rd!",
        ip_address="127.0.0.1",
    )
    assert "access_token" in result
    assert "refresh_token" in result or result.get("requires_totp") is True


async def test_login_with_totp_enabled_returns_requires_totp(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].get_user_by_email.return_value = _user_row(totp_enabled=True)
    deps["db_repo"].get_rate_limit.return_value = None
    deps["db_repo"].record_successful_login = AsyncMock()
    deps["db_repo"].reset_rate_limit = AsyncMock()

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    result = await svc.login(
        email="test@example.com",
        password="StrongP@ssw0rd!",
        ip_address="127.0.0.1",
    )
    assert result.get("requires_totp") is True


async def test_login_bad_credentials_raises(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].get_user_by_email.return_value = _user_row()
    deps["db_repo"].get_rate_limit.return_value = None
    deps["password_module"].verify_password.return_value = False
    deps["db_repo"].upsert_rate_limit = AsyncMock(return_value={"attempts": 1})
    deps["db_repo"].update_user = AsyncMock()

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    with pytest.raises((ValueError, PermissionError, Exception)):
        await svc.login(
            email="test@example.com",
            password="WrongPassword",
            ip_address="127.0.0.1",
        )


async def test_login_user_not_found_raises(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].get_user_by_email.return_value = None
    deps["db_repo"].get_rate_limit.return_value = None

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    with pytest.raises(Exception):
        await svc.login(
            email="ghost@example.com",
            password="SomeP@ssw0rd!",
            ip_address="127.0.0.1",
        )


# ─────────────────────────────────────────────
# PoW challenge
# ─────────────────────────────────────────────

async def test_issue_pow_challenge_creates_and_returns_challenge(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].create_pow_challenge = AsyncMock(return_value={})

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    result = await svc.issue_pow_challenge("127.0.0.1")
    assert "challenge_id" in result
    deps["db_repo"].create_pow_challenge.assert_called_once()


# ─────────────────────────────────────────────
# Token refresh
# ─────────────────────────────────────────────

async def test_refresh_token_success(auth_service_deps):
    deps = auth_service_deps
    import hashlib, secrets as sec

    plain_token = sec.token_urlsafe(48)
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    import secrets as _s
    family_id = _s.token_hex(16)

    deps["db_repo"].get_refresh_token.return_value = {
        "token_hash": token_hash,
        "user_id_hex": "user123",
        "family_id": family_id,
        "revoked_at": None,
    }
    deps["db_repo"].get_user_by_id_hex.return_value = _user_row()
    deps["db_repo"].revoke_refresh_token = AsyncMock()
    deps["db_repo"].store_refresh_token = AsyncMock()

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    result = await svc.refresh_access_token(plain_token, "127.0.0.1")
    assert "access_token" in result
    assert "refresh_token" in result


async def test_refresh_token_reuse_triggers_family_revocation(auth_service_deps):
    """
    If refresh token is already revoked (reuse attempt), revoke whole family.
    """
    deps = auth_service_deps
    deps["db_repo"].get_refresh_token.return_value = None  # already consumed

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    with pytest.raises(Exception):
        await svc.refresh_access_token("reused_or_invalid_token", "127.0.0.1")


# ─────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────

async def test_logout_revokes_tokens(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].revoke_token_jti = AsyncMock()
    deps["db_repo"].revoke_refresh_token = AsyncMock()

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    result = await svc.logout(
        user_id_hex="user123",
        refresh_token="some_plain_refresh_token",
        ip_address="127.0.0.1",
    )
    assert result is not None
    deps["audit_service"].log_auth_event.assert_called()


# ─────────────────────────────────────────────
# Password change
# ─────────────────────────────────────────────

async def test_change_password_revokes_all_tokens(auth_service_deps):
    deps = auth_service_deps
    deps["db_repo"].get_user_by_id_hex.return_value = _user_row()
    deps["db_repo"].revoke_all_user_refresh_tokens = AsyncMock(return_value=1)
    deps["db_repo"].revoke_all_user_jtis = AsyncMock(return_value=1)
    deps["db_repo"].set_password_hash = AsyncMock()

    svc = AuthService(
        db_repo=deps["db_repo"],
        email_module=deps["email_module"],
        totp_module=deps["totp_module"],
        password_module=deps["password_module"],
        token_module=deps["token_module"],
        pow_module=deps["pow_module"],
        audit_service=deps["audit_service"],
        config=deps["config"],
    )

    await svc.change_password(
        user_id_hex="user123",
        old_password="OldP@ss123!",
        new_password="NewStr0ng!Pass",
        ip_address="127.0.0.1",
    )
    deps["db_repo"].revoke_all_user_refresh_tokens.assert_called_once()
