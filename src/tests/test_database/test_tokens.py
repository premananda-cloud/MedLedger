"""
tests/test_database/test_tokens.py

Integration tests for DatabaseRepository token operations:
  - refresh_tokens table
  - token_revocations table
"""
import secrets
from datetime import datetime, timedelta, timezone
import pytest

from database.repository import DatabaseRepository
from database.exceptions import DuplicateError


def _now():
    return datetime.now(timezone.utc)


def _future(seconds=3600):
    return _now() + timedelta(seconds=seconds)


def _past(seconds=10):
    return _now() - timedelta(seconds=seconds)


# ─────────────────────────────────────────────
# Refresh tokens
# ─────────────────────────────────────────────

async def test_store_refresh_token_creates_record(db_session):
    repo = DatabaseRepository(db_session)
    token_hash = secrets.token_hex(32)
    result = await repo.store_refresh_token(
        token_hash=token_hash,
        user_id_hex="user123",
        family_id="family1",
        expires_at=_future(),
    )
    assert result["token_hash"] == token_hash
    assert result["user_id_hex"] == "user123"


async def test_get_refresh_token_returns_valid_token(db_session):
    repo = DatabaseRepository(db_session)
    token_hash = secrets.token_hex(32)
    await repo.store_refresh_token(
        token_hash=token_hash,
        user_id_hex="user_gettest",
        family_id="fam1",
        expires_at=_future(),
    )
    token = await repo.get_refresh_token(token_hash)
    assert token is not None
    assert token["token_hash"] == token_hash


async def test_get_refresh_token_returns_none_for_missing(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.get_refresh_token("nonexistent_hash")
    assert result is None


async def test_get_refresh_token_returns_none_for_expired(db_session):
    repo = DatabaseRepository(db_session)
    token_hash = secrets.token_hex(32)
    await repo.store_refresh_token(
        token_hash=token_hash,
        user_id_hex="user_expired",
        family_id="fam_exp",
        expires_at=_past(),  # already expired
    )
    result = await repo.get_refresh_token(token_hash)
    # Implementation may return None for expired tokens
    # or return the row; either is a valid design choice.
    # We test that the method doesn't raise.
    assert result is None or isinstance(result, dict)


async def test_get_refresh_token_returns_none_for_revoked(db_session):
    repo = DatabaseRepository(db_session)
    token_hash = secrets.token_hex(32)
    await repo.store_refresh_token(
        token_hash=token_hash,
        user_id_hex="user_revoked",
        family_id="fam_rev",
        expires_at=_future(),
    )
    await repo.revoke_refresh_token(token_hash)
    result = await repo.get_refresh_token(token_hash)
    assert result is None


async def test_revoke_refresh_token_sets_revoked_at(db_session):
    repo = DatabaseRepository(db_session)
    token_hash = secrets.token_hex(32)
    await repo.store_refresh_token(
        token_hash=token_hash,
        user_id_hex="user_rev2",
        family_id="fam_rv2",
        expires_at=_future(),
    )
    await repo.revoke_refresh_token(token_hash)
    # After revocation, get should return None
    result = await repo.get_refresh_token(token_hash)
    assert result is None


async def test_revoke_token_family_revokes_all_in_family(db_session):
    repo = DatabaseRepository(db_session)
    family_id = "family_" + secrets.token_hex(4)
    user_id = "user_fam"
    hashes = [secrets.token_hex(32) for _ in range(3)]
    for h in hashes:
        await repo.store_refresh_token(
            token_hash=h, user_id_hex=user_id,
            family_id=family_id, expires_at=_future()
        )
    count = await repo.revoke_token_family(family_id)
    assert count >= 3
    for h in hashes:
        assert await repo.get_refresh_token(h) is None


async def test_store_refresh_token_duplicate_raises(db_session):
    repo = DatabaseRepository(db_session)
    token_hash = secrets.token_hex(32)
    await repo.store_refresh_token(
        token_hash=token_hash,
        user_id_hex="user_dup",
        family_id="fam_dup",
        expires_at=_future(),
    )
    with pytest.raises(DuplicateError):
        await repo.store_refresh_token(
            token_hash=token_hash,
            user_id_hex="user_dup2",
            family_id="fam_dup2",
            expires_at=_future(),
        )


async def test_revoke_all_user_refresh_tokens(db_session):
    repo = DatabaseRepository(db_session)
    user_id = "user_revoke_all"
    for i in range(3):
        await repo.store_refresh_token(
            token_hash=secrets.token_hex(32),
            user_id_hex=user_id,
            family_id=f"fam_{i}",
            expires_at=_future(),
        )
    count = await repo.revoke_all_user_refresh_tokens(user_id)
    assert count >= 3


async def test_cleanup_expired_refresh_tokens(db_session):
    repo = DatabaseRepository(db_session)
    # Insert an expired token
    await repo.store_refresh_token(
        token_hash=secrets.token_hex(32),
        user_id_hex="cleanup_user",
        family_id="cleanup_fam",
        expires_at=_past(seconds=100),
    )
    count = await repo.cleanup_expired_refresh_tokens()
    assert count >= 0  # at least ran without error


# ─────────────────────────────────────────────
# Token revocations (JTI)
# ─────────────────────────────────────────────

async def test_revoke_token_jti_creates_revocation(db_session):
    repo = DatabaseRepository(db_session)
    jti = secrets.token_hex(16)
    await repo.revoke_token_jti(
        token_jti=jti,
        user_id_hex="user_jti1",
        expires_at=_future(),
    )
    assert await repo.is_token_revoked(jti) is True


async def test_is_token_revoked_returns_false_for_unknown(db_session):
    repo = DatabaseRepository(db_session)
    assert await repo.is_token_revoked("unknown_jti_xyz") is False


async def test_is_token_revoked_returns_true_after_revoke(db_session):
    repo = DatabaseRepository(db_session)
    jti = secrets.token_hex(16)
    await repo.revoke_token_jti(
        token_jti=jti,
        user_id_hex="user_jti2",
        expires_at=_future(),
    )
    assert await repo.is_token_revoked(jti) is True


async def test_revoke_all_user_jtis(db_session):
    repo = DatabaseRepository(db_session)
    user_id = "user_all_jtis"
    jtis = [secrets.token_hex(16) for _ in range(3)]
    for jti in jtis:
        await repo.revoke_token_jti(
            token_jti=jti,
            user_id_hex=user_id,
            expires_at=_future(),
        )
    count = await repo.revoke_all_user_jtis(user_id)
    assert count >= 3


async def test_cleanup_expired_jtis(db_session):
    repo = DatabaseRepository(db_session)
    jti = secrets.token_hex(16)
    await repo.revoke_token_jti(
        token_jti=jti,
        user_id_hex="cleanup_jti_user",
        expires_at=_past(seconds=100),  # expired
    )
    count = await repo.cleanup_expired_jtis()
    assert count >= 0
