"""
tests/test_services/test_relay_service.py

Unit tests for RelayService with mocked dependencies.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock

from services.relay_service import RelayService
from database.exceptions import RecordNotFoundError


def _user(uid="user123"):
    return {
        "user_id_hex": uid,
        "username": "user_" + uid,
        "signing_public_key": "sig_key_" + uid,
        "exchange_public_key": "exc_key_" + uid,
    }


def _vault_record(owner_id="owner123", record_id="rec123"):
    return {
        "record_id": record_id,
        "owner_user_id_hex": owner_id,
        "filename": "test.pdf",
    }


@pytest.fixture
def mock_key_service():
    ks = AsyncMock()
    ks.get_my_keys.return_value = {"signing_public_key": "owner_sig_key"}
    ks.get_exchange_key.return_value = {"exchange_public_key": "user_exc_key"}
    return ks


@pytest.fixture
def mock_grant_service():
    gs = AsyncMock()
    gs.check_access.return_value = {"has_access": True, "permission_level": "view_only"}
    return gs


@pytest.fixture
def relay_svc(mock_db_repo, mock_key_service, mock_grant_service, mock_audit_service):
    # Patch audit to have log_relay_event
    mock_audit_service.log_relay_event = AsyncMock()
    return RelayService(
        db_repo=mock_db_repo,
        key_service=mock_key_service,
        grant_service=mock_grant_service,
        audit_service=mock_audit_service,
    )


# ─────────────────────────────────────────────
# request_share
# ─────────────────────────────────────────────

async def test_request_share_success(relay_svc, mock_db_repo, mock_grant_service):
    mock_db_repo.get_user_by_id_hex.side_effect = [_user("owner123"), _user("requester456")]
    mock_grant_service.check_access.return_value = {"has_access": True}
    mock_db_repo.create_share.return_value = {
        "share_id": "11111111-0000-0000-0000-000000000001",
        "status": "active",
    }

    result = await relay_svc.request_share(
        requester_id_hex="requester456",
        owner_id_hex="owner123",
        record_id="rec123",
        requester_public_key="req_pub_key",
        ip_address="127.0.0.1",
    )
    assert "share_id" in result
    assert result.get("status") == "pending" or "share_id" in result


async def test_request_share_owner_not_found_raises(relay_svc, mock_db_repo):
    mock_db_repo.get_user_by_id_hex.return_value = None
    with pytest.raises(RecordNotFoundError):
        await relay_svc.request_share(
            requester_id_hex="requester",
            owner_id_hex="ghost_owner",
            record_id="rec123",
            requester_public_key="pub_key",
            ip_address="127.0.0.1",
        )


async def test_request_share_without_grant_raises(relay_svc, mock_db_repo, mock_grant_service):
    mock_db_repo.get_user_by_id_hex.side_effect = [_user("owner"), _user("requester")]
    mock_grant_service.check_access.return_value = {"has_access": False}

    with pytest.raises(ValueError, match="grant"):
        await relay_svc.request_share(
            requester_id_hex="requester",
            owner_id_hex="owner",
            record_id="rec123",
            requester_public_key="pub_key",
            ip_address="127.0.0.1",
        )


# ─────────────────────────────────────────────
# send_encrypted_payload
# ─────────────────────────────────────────────

async def test_send_encrypted_payload_returns_payload(
    relay_svc, mock_db_repo, mock_grant_service, mock_key_service
):
    mock_db_repo.get_vault_record.return_value = _vault_record(owner_id="owner123")
    mock_grant_service.check_access.return_value = {
        "has_access": True, "permission_level": "view_only"
    }
    mock_key_service.get_my_keys.return_value = {"signing_public_key": "owner_sig_key"}

    result = await relay_svc.send_encrypted_payload(
        sender_id_hex="owner123",
        recipient_id_hex="grantee456",
        record_id="rec123",
        encrypted_payload="encrypted_data_here",
        signature="sig_hex",
        ip_address="127.0.0.1",
    )
    assert result["encrypted_payload"] == "encrypted_data_here"
    assert "sender_signing_key" in result


async def test_send_encrypted_payload_wrong_owner_raises(
    relay_svc, mock_db_repo
):
    mock_db_repo.get_vault_record.return_value = _vault_record(owner_id="real_owner")

    with pytest.raises(ValueError, match="own"):
        await relay_svc.send_encrypted_payload(
            sender_id_hex="not_owner",
            recipient_id_hex="grantee",
            record_id="rec123",
            encrypted_payload="data",
            signature="sig",
            ip_address="127.0.0.1",
        )


async def test_send_encrypted_payload_no_grant_raises(
    relay_svc, mock_db_repo, mock_grant_service
):
    mock_db_repo.get_vault_record.return_value = _vault_record(owner_id="owner123")
    mock_grant_service.check_access.return_value = {"has_access": False}

    with pytest.raises(ValueError, match="grant"):
        await relay_svc.send_encrypted_payload(
            sender_id_hex="owner123",
            recipient_id_hex="grantee",
            record_id="rec123",
            encrypted_payload="data",
            signature="sig",
            ip_address="127.0.0.1",
        )


async def test_send_encrypted_payload_record_not_found_raises(
    relay_svc, mock_db_repo
):
    mock_db_repo.get_vault_record.return_value = None

    with pytest.raises(RecordNotFoundError):
        await relay_svc.send_encrypted_payload(
            sender_id_hex="owner123",
            recipient_id_hex="grantee",
            record_id="ghost_record",
            encrypted_payload="data",
            signature="sig",
            ip_address="127.0.0.1",
        )


# ─────────────────────────────────────────────
# get_pending_requests
# ─────────────────────────────────────────────

async def test_get_pending_requests_returns_list(relay_svc, mock_db_repo):
    mock_db_repo.get_shares_by_owner.return_value = []
    result = await relay_svc.get_pending_requests("owner123")
    assert isinstance(result, list)


# ─────────────────────────────────────────────
# reject_share_request
# ─────────────────────────────────────────────

async def test_reject_share_request_by_owner(relay_svc, mock_db_repo):
    import uuid
    share_id = str(uuid.uuid4())
    mock_db_repo.get_share_by_id.return_value = {
        "share_id": share_id,
        "owner_user_id_hex": "owner123",
        "grantee_user_id_hex": "grantee456",
    }
    mock_db_repo.update_share_status = AsyncMock()

    result = await relay_svc.reject_share_request(
        owner_id_hex="owner123",
        share_id=share_id,
        ip_address="127.0.0.1",
    )
    assert result.get("rejected") is True
    mock_db_repo.update_share_status.assert_called_once()


async def test_reject_share_request_non_owner_raises(relay_svc, mock_db_repo):
    import uuid
    share_id = str(uuid.uuid4())
    mock_db_repo.get_share_by_id.return_value = {
        "share_id": share_id,
        "owner_user_id_hex": "real_owner",
        "grantee_user_id_hex": "grantee",
    }

    with pytest.raises(ValueError, match="owner"):
        await relay_svc.reject_share_request(
            owner_id_hex="imposter",
            share_id=share_id,
            ip_address="127.0.0.1",
        )


async def test_reject_share_request_not_found_raises(relay_svc, mock_db_repo):
    import uuid
    mock_db_repo.get_share_by_id.return_value = None

    with pytest.raises(RecordNotFoundError):
        await relay_svc.reject_share_request(
            owner_id_hex="owner",
            share_id=str(uuid.uuid4()),
            ip_address="127.0.0.1",
        )
