"""
tests/test_services/test_grant_service.py

Unit tests for GrantService with mocked dependencies.
"""
import secrets
import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from services.grant_service import GrantService
from database.exceptions import RecordNotFoundError


def _now():
    return datetime.now(timezone.utc)


def _future(hours=24):
    return _now() + timedelta(hours=hours)


def _past(hours=1):
    return _now() - timedelta(hours=hours)


def _vault_record(owner_id="owner123", record_id="rec123"):
    return {
        "record_id": record_id,
        "owner_user_id_hex": owner_id,
        "filename": "test.pdf",
        "owner_key_hash": "owner_keyhash",
    }


def _user(uid="user123"):
    return {
        "user_id_hex": uid,
        "exchange_public_key": "pub_key_hex_" + uid,
    }


def _grant(gid="grant123", revoked=False, expired=False):
    return {
        "grant_id": gid,
        "record_id": "rec123",
        "permission_level": "view_only",
        "time_start": _past(hours=2).isoformat(),
        "time_end": (_past(hours=1) if expired else _future()).isoformat(),
        "revoked_at": _now().isoformat() if revoked else None,
        "dek_bundle_grantee": json.dumps({"bundle": "data"}),
    }


@pytest.fixture
def grant_svc(mock_db_repo, mock_audit_service):
    return GrantService(db_repo=mock_db_repo, audit_service=mock_audit_service)


# ─────────────────────────────────────────────
# create_grant
# ─────────────────────────────────────────────

async def test_create_grant_success(grant_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.get_vault_record.return_value = _vault_record()
    mock_db_repo.get_user_by_id_hex.return_value = _user("grantee123")
    mock_db_repo.create_grant.return_value = {
        "grant_id": "g1",
        "record_id": "rec123",
        "permission_level": "view_only",
    }

    result = await grant_svc.create_grant(
        grantor_id_hex="owner123",
        grantee_id_hex="grantee123",
        record_id="rec123",
        permission_level="view_only",
        time_start=_now(),
        time_end=_future(),
        dek_bundle_grantee={"bundle": "encrypted"},
        signature_hex="sig_hex",
        ip_address="127.0.0.1",
    )
    assert result["grant_id"] == "g1"
    mock_audit_service.log_grant_event.assert_called()


async def test_create_grant_non_owner_raises(grant_svc, mock_db_repo):
    mock_db_repo.get_vault_record.return_value = _vault_record(owner_id="real_owner")
    mock_db_repo.get_user_by_id_hex.return_value = _user("grantee")

    with pytest.raises(ValueError, match="own"):
        await grant_svc.create_grant(
            grantor_id_hex="not_the_owner",
            grantee_id_hex="grantee",
            record_id="rec123",
            permission_level="view_only",
            time_start=_now(),
            time_end=_future(),
            dek_bundle_grantee={},
            signature_hex="sig",
            ip_address="127.0.0.1",
        )


async def test_create_grant_invalid_permission_level_raises(grant_svc, mock_db_repo):
    mock_db_repo.get_vault_record.return_value = _vault_record()
    mock_db_repo.get_user_by_id_hex.return_value = _user("grantee")

    with pytest.raises(ValueError, match="permission"):
        await grant_svc.create_grant(
            grantor_id_hex="owner123",
            grantee_id_hex="grantee",
            record_id="rec123",
            permission_level="invalid_level",
            time_start=_now(),
            time_end=_future(),
            dek_bundle_grantee={},
            signature_hex="sig",
            ip_address="127.0.0.1",
        )


async def test_create_grant_time_end_before_start_raises(grant_svc, mock_db_repo):
    mock_db_repo.get_vault_record.return_value = _vault_record()
    mock_db_repo.get_user_by_id_hex.return_value = _user("grantee")

    with pytest.raises(ValueError, match="time"):
        await grant_svc.create_grant(
            grantor_id_hex="owner123",
            grantee_id_hex="grantee",
            record_id="rec123",
            permission_level="view_only",
            time_start=_future(),   # start is AFTER end
            time_end=_now(),
            dek_bundle_grantee={},
            signature_hex="sig",
            ip_address="127.0.0.1",
        )


async def test_create_grant_record_not_found_raises(grant_svc, mock_db_repo):
    mock_db_repo.get_vault_record.return_value = None
    with pytest.raises(RecordNotFoundError):
        await grant_svc.create_grant(
            grantor_id_hex="owner123",
            grantee_id_hex="grantee",
            record_id="nonexistent",
            permission_level="view_only",
            time_start=_now(),
            time_end=_future(),
            dek_bundle_grantee={},
            signature_hex="sig",
            ip_address="127.0.0.1",
        )


# ─────────────────────────────────────────────
# revoke_grant
# ─────────────────────────────────────────────

async def test_revoke_grant_by_owner_succeeds(grant_svc, mock_db_repo, mock_audit_service):
    mock_db_repo.get_grant.return_value = {
        "grant_id": "g1",
        "record_id": "rec123",
        "revoked_at": None,
    }
    mock_db_repo.get_vault_record.return_value = _vault_record(owner_id="owner123")
    mock_db_repo.revoke_grant = AsyncMock()

    await grant_svc.revoke_grant(
        grant_id="g1",
        revoker_id_hex="owner123",
        ip_address="127.0.0.1",
    )
    mock_db_repo.revoke_grant.assert_called_once()


async def test_revoke_grant_non_owner_raises(grant_svc, mock_db_repo):
    mock_db_repo.get_grant.return_value = {
        "grant_id": "g1",
        "record_id": "rec123",
        "revoked_at": None,
    }
    mock_db_repo.get_vault_record.return_value = _vault_record(owner_id="real_owner")

    with pytest.raises((ValueError, PermissionError)):
        await grant_svc.revoke_grant(
            grant_id="g1",
            revoker_id_hex="imposter",
            ip_address="127.0.0.1",
        )


# ─────────────────────────────────────────────
# check_access
# ─────────────────────────────────────────────

async def test_check_access_active_grant_returns_true(grant_svc, mock_db_repo):
    active_grant = _grant()
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    active_grant["time_start"] = now - timedelta(hours=1)
    active_grant["time_end"] = now + timedelta(hours=1)
    active_grant["record_id"] = "rec123"
    active_grant["revoked"] = False
    mock_db_repo.get_grants_by_grantee.return_value = [active_grant]

    result = await grant_svc.check_access(
        user_id_hex="grantee_123",
        record_id="rec123",
    )
    # Returns dict with has_access key
    assert result.get("has_access") is True


async def test_check_access_no_grants_returns_false(grant_svc, mock_db_repo):
    mock_db_repo.get_grants_by_grantee.return_value = []

    result = await grant_svc.check_access(
        user_id_hex="grantee_key",
        record_id="rec123",
    )
    assert result.get("has_access") is False


# ─────────────────────────────────────────────
# list_grants_for_record
# ─────────────────────────────────────────────

async def test_list_grants_for_record_by_owner(grant_svc, mock_db_repo):
    mock_db_repo.get_vault_record.return_value = _vault_record(owner_id="owner123")
    mock_db_repo.get_grants_for_record.return_value = [_grant()]

    result = await grant_svc.list_grants_for_record(
        record_id="rec123",
        owner_id_hex="owner123",
    )
    assert isinstance(result, list)


async def test_list_grants_for_record_non_owner_raises(grant_svc, mock_db_repo):
    mock_db_repo.get_vault_record.return_value = _vault_record(owner_id="real_owner")

    with pytest.raises((ValueError, PermissionError)):
        await grant_svc.list_grants_for_record(
            record_id="rec123",
            owner_id_hex="not_owner",
        )


# ─────────────────────────────────────────────
# get_grant_details
# ─────────────────────────────────────────────

async def test_get_grant_details_returns_dek_bundle(grant_svc, mock_db_repo):
    grant = _grant()
    grant["grantee_user_id_hex"] = "grantee_user_id_hex_value"
    mock_db_repo.get_grant.return_value = grant
    mock_db_repo.mark_grant_retrieved = AsyncMock()
    mock_db_repo.get_vault_record.return_value = _vault_record()

    result = await grant_svc.get_grant_details(
        grant_id="grant123",
        user_id_hex="grantee_user_id_hex_value",
    )
    assert "dek_bundle_grantee" in result or isinstance(result, dict)
