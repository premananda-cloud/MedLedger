"""
tests/test_database/test_rate_limit.py

Integration tests for DatabaseRepository rate_limit operations.
"""
import secrets
import pytest
from datetime import datetime, timedelta, timezone

from database.repository import DatabaseRepository
from database.exceptions import RecordNotFoundError


def _now():
    return datetime.now(timezone.utc)


def _future(minutes=15):
    return _now() + timedelta(minutes=minutes)


def _key():
    return secrets.token_hex(16)


# ─────────────────────────────────────────────
# get_rate_limit
# ─────────────────────────────────────────────

async def test_get_rate_limit_returns_none_for_missing(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.get_rate_limit("nonexistent_key", "login")
    assert result is None


async def test_get_rate_limit_returns_record_after_upsert(db_session):
    repo = DatabaseRepository(db_session)
    key = _key()
    await repo.upsert_rate_limit(key, "login")
    result = await repo.get_rate_limit(key, "login")
    assert result is not None
    assert result["key_hash"] == key
    assert result["action"] == "login"


# ─────────────────────────────────────────────
# upsert_rate_limit
# ─────────────────────────────────────────────

async def test_upsert_rate_limit_creates_new_record(db_session):
    repo = DatabaseRepository(db_session)
    key = _key()
    result = await repo.upsert_rate_limit(key, "login")
    assert result["attempts"] == 1


async def test_upsert_rate_limit_increments_existing(db_session):
    repo = DatabaseRepository(db_session)
    key = _key()
    r1 = await repo.upsert_rate_limit(key, "login")
    r2 = await repo.upsert_rate_limit(key, "login")
    r3 = await repo.upsert_rate_limit(key, "login")
    assert r1["attempts"] == 1
    assert r2["attempts"] == 2
    assert r3["attempts"] == 3


async def test_upsert_rate_limit_different_actions_are_independent(db_session):
    repo = DatabaseRepository(db_session)
    key = _key()
    r_login = await repo.upsert_rate_limit(key, "login")
    r_reset = await repo.upsert_rate_limit(key, "password_reset")
    assert r_login["attempts"] == 1
    assert r_reset["attempts"] == 1


async def test_upsert_rate_limit_returns_dict(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.upsert_rate_limit(_key(), "verify")
    assert isinstance(result, dict)
    assert "attempts" in result
    assert "key_hash" in result


# ─────────────────────────────────────────────
# set_rate_limit_block
# ─────────────────────────────────────────────

async def test_set_rate_limit_block_sets_blocked_until(db_session):
    repo = DatabaseRepository(db_session)
    key = _key()
    await repo.upsert_rate_limit(key, "login")
    blocked_until = _future(minutes=15)
    await repo.set_rate_limit_block(key, "login", blocked_until)
    record = await repo.get_rate_limit(key, "login")
    assert record is not None
    assert record.get("blocked_until") is not None


async def test_set_rate_limit_block_missing_key_raises(db_session):
    repo = DatabaseRepository(db_session)
    with pytest.raises(RecordNotFoundError):
        await repo.set_rate_limit_block("ghost_key", "login", _future())


# ─────────────────────────────────────────────
# reset_rate_limit
# ─────────────────────────────────────────────

async def test_reset_rate_limit_deletes_record(db_session):
    repo = DatabaseRepository(db_session)
    key = _key()
    await repo.upsert_rate_limit(key, "login")
    assert await repo.get_rate_limit(key, "login") is not None
    await repo.reset_rate_limit(key, "login")
    assert await repo.get_rate_limit(key, "login") is None


async def test_reset_rate_limit_only_removes_matching_action(db_session):
    repo = DatabaseRepository(db_session)
    key = _key()
    await repo.upsert_rate_limit(key, "login")
    await repo.upsert_rate_limit(key, "verify")
    await repo.reset_rate_limit(key, "login")
    assert await repo.get_rate_limit(key, "login") is None
    assert await repo.get_rate_limit(key, "verify") is not None


async def test_reset_rate_limit_nonexistent_is_noop(db_session):
    repo = DatabaseRepository(db_session)
    # Should not raise even if record doesn't exist
    await repo.reset_rate_limit("nonexistent_key_abc", "login")
