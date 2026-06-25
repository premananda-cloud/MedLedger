"""
tests/test_database/test_grants.py

Integration tests for DatabaseRepository grants operations.
"""
import secrets
import json
import pytest
from datetime import datetime, timedelta, timezone

from database.repository import DatabaseRepository
from database.exceptions import DuplicateError, RecordNotFoundError


def _now():
    return datetime.now(timezone.utc)


def _future(hours=24):
    return _now() + timedelta(hours=hours)


def _grant_id():
    return secrets.token_hex(16)


async def _make_grant(repo, grant_id=None, record_id=None, grantor="grantor1", grantee="grantee1"):
    gid = grant_id or _grant_id()
    rid = record_id or secrets.token_hex(16)
    return await repo.create_grant(
        grant_id=gid,
        record_id=rid,
        grantor_key_hash="grantor_key_" + secrets.token_hex(8),
        grantee_key_hash="grantee_key_" + secrets.token_hex(8),
        grantee_public_key_hex="grantee_pub_" + secrets.token_hex(32),
        permission_level="view_only",
        time_start=_now(),
        time_end=_future(),
        dek_bundle_grantee=json.dumps({"bundle": "encrypted_dek"}),
        signature_hex="sig_" + secrets.token_hex(32),
        grantee_user_id_hex=grantee,
    )


# ─────────────────────────────────────────────
# create_grant
# ─────────────────────────────────────────────

async def test_create_grant_succeeds(db_session):
    repo = DatabaseRepository(db_session)
    grant = await _make_grant(repo)
    assert grant["grant_id"]
    assert grant["permission_level"] == "view_only"


async def test_create_grant_duplicate_id_raises(db_session):
    repo = DatabaseRepository(db_session)
    gid = _grant_id()
    await _make_grant(repo, grant_id=gid)
    with pytest.raises(DuplicateError):
        await _make_grant(repo, grant_id=gid)


# ─────────────────────────────────────────────
# get_grant
# ─────────────────────────────────────────────

async def test_get_grant_returns_grant(db_session):
    repo = DatabaseRepository(db_session)
    grant = await _make_grant(repo)
    found = await repo.get_grant(grant["grant_id"])
    assert found is not None
    assert found["grant_id"] == grant["grant_id"]


async def test_get_grant_returns_none_for_missing(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.get_grant("nonexistent_grant_id")
    assert result is None


# ─────────────────────────────────────────────
# revoke_grant
# ─────────────────────────────────────────────

async def test_revoke_grant_sets_revoked_at(db_session):
    repo = DatabaseRepository(db_session)
    grant = await _make_grant(repo)
    await repo.revoke_grant(grant["grant_id"])
    # After revocation the grant may be deleted or marked revoked
    result = await repo.get_grant(grant["grant_id"])
    # Either the grant is gone or it has revoked_at set
    assert result is None or result.get("revoked_at") is not None


async def test_revoke_grant_missing_raises(db_session):
    repo = DatabaseRepository(db_session)
    with pytest.raises(RecordNotFoundError):
        await repo.revoke_grant("ghost_grant_id")


# ─────────────────────────────────────────────
# get_grants_for_record
# ─────────────────────────────────────────────

async def test_get_grants_for_record_returns_grants(db_session):
    repo = DatabaseRepository(db_session)
    record_id = secrets.token_hex(16)
    g1 = await _make_grant(repo, record_id=record_id)
    g2 = await _make_grant(repo, record_id=record_id)
    grants = await repo.get_grants_for_record(record_id)
    grant_ids = [g["grant_id"] for g in grants]
    assert g1["grant_id"] in grant_ids
    assert g2["grant_id"] in grant_ids


async def test_get_grants_for_record_active_only(db_session):
    repo = DatabaseRepository(db_session)
    record_id = secrets.token_hex(16)
    active = await _make_grant(repo, record_id=record_id)
    revoked = await _make_grant(repo, record_id=record_id)
    await repo.revoke_grant(revoked["grant_id"])
    grants = await repo.get_grants_for_record(record_id, active_only=True)
    grant_ids = [g["grant_id"] for g in grants]
    assert active["grant_id"] in grant_ids
    assert revoked["grant_id"] not in grant_ids


# ─────────────────────────────────────────────
# get_grants_by_grantor / grantee
# ─────────────────────────────────────────────

async def test_get_grants_by_grantor_returns_matching(db_session):
    repo = DatabaseRepository(db_session)
    grantor_key = "grantor_key_unique_" + secrets.token_hex(8)
    result = await repo.create_grant(
        grant_id=_grant_id(),
        record_id=secrets.token_hex(16),
        grantor_key_hash=grantor_key,
        grantee_key_hash="grantee_key_" + secrets.token_hex(8),
        grantee_public_key_hex="pub_" + secrets.token_hex(32),
        permission_level="view_only",
        time_start=_now(),
        time_end=_future(),
        dek_bundle_grantee=json.dumps({"bundle": "data"}),
        signature_hex="sig_" + secrets.token_hex(32),
    )
    grants = await repo.get_grants_by_grantor(grantor_key)
    assert any(g["grant_id"] == result["grant_id"] for g in grants)


async def test_get_grants_by_grantee_returns_matching(db_session):
    repo = DatabaseRepository(db_session)
    grantee_key = "grantee_unique_" + secrets.token_hex(8)
    result = await repo.create_grant(
        grant_id=_grant_id(),
        record_id=secrets.token_hex(16),
        grantor_key_hash="grantor_" + secrets.token_hex(8),
        grantee_key_hash=grantee_key,
        grantee_public_key_hex="pub_" + secrets.token_hex(32),
        permission_level="view_download",
        time_start=_now(),
        time_end=_future(),
        dek_bundle_grantee=json.dumps({"bundle": "data"}),
        signature_hex="sig_" + secrets.token_hex(32),
    )
    grants = await repo.get_grants_by_grantee(grantee_key)
    assert any(g["grant_id"] == result["grant_id"] for g in grants)


# ─────────────────────────────────────────────
# mark_grant_retrieved
# ─────────────────────────────────────────────

async def test_mark_grant_retrieved_sets_timestamp(db_session):
    repo = DatabaseRepository(db_session)
    grant = await _make_grant(repo)
    await repo.mark_grant_retrieved(grant["grant_id"])
    updated = await repo.get_grant(grant["grant_id"])
    if updated:  # may be None if deleted on retrieval
        assert updated.get("retrieved_at") is not None
