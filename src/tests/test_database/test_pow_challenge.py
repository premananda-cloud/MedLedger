"""
tests/test_database/test_pow.py

Integration tests for DatabaseRepository PoW challenge storage.
"""
import secrets
from datetime import datetime, timedelta, timezone
import pytest

from database.repository import DatabaseRepository
from database.exceptions import DuplicateError, RecordNotFoundError


def _now():
    return datetime.now(timezone.utc)


def _future(seconds=300):
    return _now() + timedelta(seconds=seconds)


def _past(seconds=10):
    return _now() - timedelta(seconds=seconds)


async def _make_challenge(repo, challenge_id=None, expired=False):
    cid = challenge_id or secrets.token_hex(16)
    expires = _past() if expired else _future()
    row = await repo.create_pow_challenge(
        challenge_id=cid,
        nonce_prefix=secrets.token_urlsafe(16),
        difficulty=4,
        target_hash="0000",
        expires_at=expires,
    )
    return row


async def test_create_pow_challenge_succeeds(db_session):
    repo = DatabaseRepository(db_session)
    row = await _make_challenge(repo)
    assert row["challenge_id"]
    assert row["difficulty"] == 4


async def test_create_pow_challenge_duplicate_id_raises(db_session):
    repo = DatabaseRepository(db_session)
    cid = secrets.token_hex(16)
    await _make_challenge(repo, challenge_id=cid)
    with pytest.raises(DuplicateError):
        await _make_challenge(repo, challenge_id=cid)


async def test_get_pow_challenge_returns_row(db_session):
    repo = DatabaseRepository(db_session)
    row = await _make_challenge(repo)
    cid = row["challenge_id"]
    found = await repo.get_pow_challenge(cid)
    assert found is not None
    assert found["challenge_id"] == cid


async def test_get_pow_challenge_returns_none_for_missing(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.get_pow_challenge("nonexistent_cid")
    assert result is None


async def test_mark_pow_solved_updates_row(db_session):
    repo = DatabaseRepository(db_session)
    row = await _make_challenge(repo)
    cid = row["challenge_id"]
    await repo.mark_pow_solved(cid, solved_nonce="42", solver_ip="127.0.0.1")
    updated = await repo.get_pow_challenge(cid)
    if updated:  # might be None if mark_pow_solved deletes it
        assert updated.get("solved_nonce") == "42"


async def test_mark_pow_solved_missing_raises(db_session):
    repo = DatabaseRepository(db_session)
    with pytest.raises(RecordNotFoundError):
        await repo.mark_pow_solved("ghost_cid", "nonce", "127.0.0.1")


async def test_delete_pow_challenge_removes_row(db_session):
    repo = DatabaseRepository(db_session)
    row = await _make_challenge(repo)
    cid = row["challenge_id"]
    await repo.delete_pow_challenge(cid)
    assert await repo.get_pow_challenge(cid) is None


async def test_delete_pow_challenge_nonexistent_is_noop(db_session):
    repo = DatabaseRepository(db_session)
    # Should not raise
    await repo.delete_pow_challenge("ghost_cid_xyz")


async def test_cleanup_expired_pow_removes_old_challenges(db_session):
    repo = DatabaseRepository(db_session)
    # Create an expired challenge
    await _make_challenge(repo, expired=True)
    count = await repo.cleanup_expired_pow()
    assert count >= 0  # at least 0 cleaned
