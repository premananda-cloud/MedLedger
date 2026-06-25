"""
tests/test_services/test_key_service.py

Unit tests for KeyService with mocked dependencies.
"""
import pytest
from unittest.mock import AsyncMock

from services.key_service import KeyService
from database.exceptions import RecordNotFoundError


def _make_user(uid="user123"):
    return {
        "user_id_hex": uid,
        "username": "testuser",
        "email": "test@example.com",
        "signing_public_key": "ed25519_public_key_hex",
        "exchange_public_key": "x25519_public_key_hex",
    }


@pytest.fixture
def key_svc(mock_db_repo, mock_audit_service):
    return KeyService(db_repo=mock_db_repo, audit_service=mock_audit_service)


# ─────────────────────────────────────────────
# store_initial_keys
# ─────────────────────────────────────────────

async def test_store_initial_keys_calls_db_and_audit(key_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.set_public_keys = AsyncMock()
    result = await key_svc.store_initial_keys(
        user_id_hex="user123",
        signing_public_key="sig_key",
        exchange_public_key="exc_key",
        ip_address="127.0.0.1",
    )
    mock_db_repo.set_public_keys.assert_called_once()
    mock_audit_service.log_key_event.assert_called_once()
    assert result["stored"] is True


# ─────────────────────────────────────────────
# get_public_keys
# ─────────────────────────────────────────────

async def test_get_public_keys_returns_both_keys(key_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.get_user_by_id_hex.return_value = _make_user()
    result = await key_svc.get_public_keys(
        user_id_hex="user123",
        requester_id_hex="requester456",
        ip_address="127.0.0.1",
    )
    assert "signing_public_key" in result
    assert "exchange_public_key" in result
    assert result["user_id_hex"] == "user123"


async def test_get_public_keys_logs_access(key_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.get_user_by_id_hex.return_value = _make_user()
    await key_svc.get_public_keys("user123", "requester456", "127.0.0.1")
    mock_audit_service.log_key_event.assert_called()


async def test_get_public_keys_missing_user_raises(key_svc, mock_db_repo):
    mock_db_repo.get_user_by_id_hex.return_value = None
    with pytest.raises(RecordNotFoundError):
        await key_svc.get_public_keys("ghost", "requester", "127.0.0.1")


# ─────────────────────────────────────────────
# get_my_keys
# ─────────────────────────────────────────────

async def test_get_my_keys_returns_keys(key_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.get_user_by_id_hex.return_value = _make_user()
    result = await key_svc.get_my_keys("user123")
    assert "signing_public_key" in result
    assert "exchange_public_key" in result


async def test_get_my_keys_does_not_log_audit(key_svc, mock_db_repo, mock_audit_service):
    """Fetching own keys should not emit an audit log entry."""
    mock_db_repo.get_user_by_id_hex.return_value = _make_user()
    await key_svc.get_my_keys("user123")
    mock_audit_service.log_key_event.assert_not_called()


async def test_get_my_keys_missing_user_raises(key_svc, mock_db_repo):
    mock_db_repo.get_user_by_id_hex.return_value = None
    with pytest.raises(RecordNotFoundError):
        await key_svc.get_my_keys("ghost_user")


# ─────────────────────────────────────────────
# update_keys
# ─────────────────────────────────────────────

async def test_update_keys_signing_only(key_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.update_user = AsyncMock(return_value=_make_user())
    result = await key_svc.update_keys(
        user_id_hex="user123",
        ip_address="127.0.0.1",
        signing_public_key="new_sig_key",
    )
    assert any("signing" in f for f in result["fields"])
    mock_audit_service.log_key_event.assert_called()


async def test_update_keys_exchange_only(key_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.update_user = AsyncMock(return_value=_make_user())
    result = await key_svc.update_keys(
        user_id_hex="user123",
        ip_address="127.0.0.1",
        exchange_public_key="new_exc_key",
    )
    assert any("exchange" in f for f in result["fields"])


async def test_update_keys_both_keys(key_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.update_user = AsyncMock(return_value=_make_user())
    result = await key_svc.update_keys(
        user_id_hex="user123",
        ip_address="127.0.0.1",
        signing_public_key="new_sig",
        exchange_public_key="new_exc",
    )
    assert len(result["fields"]) == 2


async def test_update_keys_no_keys_provided_raises(key_svc, mock_db_repo):
    with pytest.raises(ValueError):
        await key_svc.update_keys(
            user_id_hex="user123",
            ip_address="127.0.0.1",
        )


# ─────────────────────────────────────────────
# get_exchange_key / get_signing_key
# ─────────────────────────────────────────────

async def test_get_exchange_key_returns_key(key_svc, mock_db_repo):
    mock_db_repo.get_user_by_id_hex.return_value = _make_user()
    result = await key_svc.get_exchange_key("user123", "requester", "127.0.0.1")
    assert "exchange_public_key" in result
    assert "signing_public_key" not in result


async def test_get_signing_key_returns_key(key_svc, mock_db_repo):
    mock_db_repo.get_user_by_id_hex.return_value = _make_user()
    result = await key_svc.get_signing_key("user123", "requester", "127.0.0.1")
    assert "signing_public_key" in result
    assert "exchange_public_key" not in result
