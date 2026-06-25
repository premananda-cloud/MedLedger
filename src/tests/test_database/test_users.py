"""
tests/test_database/test_users.py

Integration tests for DatabaseRepository user operations.
Uses SQLite in-memory via db_session fixture.
"""
import pytest
from database.repository import DatabaseRepository
from database.exceptions import DuplicateError, RecordNotFoundError


async def make_user(repo, suffix="1", role="PATIENT"):
    return await repo.create_user(
        username=f"testuser{suffix}",
        email=f"test{suffix}@example.com",
        full_name=f"Test User {suffix}",
        password_hash=f"hash{suffix}",
        role=role,
    )


# ─────────────────────────────────────────────
# create_user
# ─────────────────────────────────────────────

async def test_create_user_succeeds(db_session):
    repo = DatabaseRepository(db_session)
    user = await make_user(repo, "a")
    assert user["username"] == "testusera"
    assert user["email"] == "testa@example.com"
    assert user["user_id_hex"]


async def test_create_user_returns_dict(db_session):
    repo = DatabaseRepository(db_session)
    user = await make_user(repo, "b")
    assert isinstance(user, dict)


async def test_create_user_lowercases_email_and_username(db_session):
    repo = DatabaseRepository(db_session)
    user = await repo.create_user(
        username="UPPERUSER",
        email="UPPER@EXAMPLE.COM",
        full_name="Upper",
        password_hash="hash",
    )
    assert user["username"] == "upperuser"
    assert user["email"] == "upper@example.com"


async def test_create_user_duplicate_email_raises(db_session):
    repo = DatabaseRepository(db_session)
    await repo.create_user("user_c1", "dup@example.com", "User 1", "hash")
    with pytest.raises(DuplicateError) as exc_info:
        await repo.create_user("user_c2", "dup@example.com", "User 2", "hash")
    assert exc_info.value.field == "email"


async def test_create_user_duplicate_username_raises(db_session):
    repo = DatabaseRepository(db_session)
    await repo.create_user("dupuser", "email1@example.com", "User 1", "hash")
    with pytest.raises(DuplicateError) as exc_info:
        await repo.create_user("dupuser", "email2@example.com", "User 2", "hash")
    assert exc_info.value.field == "username"


# ─────────────────────────────────────────────
# get_user_by_id_hex
# ─────────────────────────────────────────────

async def test_get_user_by_id_hex_returns_user(db_session):
    repo = DatabaseRepository(db_session)
    created = await make_user(repo, "d")
    found = await repo.get_user_by_id_hex(created["user_id_hex"])
    assert found is not None
    assert found["user_id_hex"] == created["user_id_hex"]


async def test_get_user_by_id_hex_returns_none_for_missing(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.get_user_by_id_hex("nonexistent_id")
    assert result is None


# ─────────────────────────────────────────────
# get_user_by_email
# ─────────────────────────────────────────────

async def test_get_user_by_email_returns_user(db_session):
    repo = DatabaseRepository(db_session)
    created = await make_user(repo, "e")
    found = await repo.get_user_by_email("teste@example.com")
    assert found is not None
    assert found["email"] == "teste@example.com"


async def test_get_user_by_email_case_insensitive(db_session):
    repo = DatabaseRepository(db_session)
    await make_user(repo, "f")
    found = await repo.get_user_by_email("TESTF@EXAMPLE.COM")
    assert found is not None


async def test_get_user_by_email_returns_none_for_missing(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.get_user_by_email("nobody@nowhere.com")
    assert result is None


# ─────────────────────────────────────────────
# email_exists / username_exists
# ─────────────────────────────────────────────

async def test_email_exists_true(db_session):
    repo = DatabaseRepository(db_session)
    await make_user(repo, "g")
    assert await repo.email_exists("testg@example.com") is True


async def test_email_exists_false(db_session):
    repo = DatabaseRepository(db_session)
    assert await repo.email_exists("ghost@example.com") is False


async def test_username_exists_true(db_session):
    repo = DatabaseRepository(db_session)
    await make_user(repo, "h")
    assert await repo.username_exists("testuserh") is True


async def test_username_exists_false(db_session):
    repo = DatabaseRepository(db_session)
    assert await repo.username_exists("ghostuser") is False


# ─────────────────────────────────────────────
# update_user
# ─────────────────────────────────────────────

async def test_update_user_updates_field(db_session):
    repo = DatabaseRepository(db_session)
    user = await make_user(repo, "i")
    updated = await repo.update_user(user["user_id_hex"], full_name="New Name")
    assert updated["full_name"] == "New Name"


async def test_update_user_returns_dict(db_session):
    repo = DatabaseRepository(db_session)
    user = await make_user(repo, "j")
    result = await repo.update_user(user["user_id_hex"], full_name="Updated")
    assert isinstance(result, dict)


async def test_update_user_not_found_raises(db_session):
    repo = DatabaseRepository(db_session)
    with pytest.raises(RecordNotFoundError):
        await repo.update_user("nonexistent_id_xyz", full_name="X")


# ─────────────────────────────────────────────
# mark_email_verified
# ─────────────────────────────────────────────

async def test_mark_email_verified_sets_flag(db_session):
    repo = DatabaseRepository(db_session)
    user = await make_user(repo, "k")
    await repo.mark_email_verified(user["user_id_hex"])
    refreshed = await repo.get_user_by_id_hex(user["user_id_hex"])
    # mark_email_verified sets is_verified=True via update_user
    assert refreshed.get("is_verified") or refreshed.get("email_verified")


# ─────────────────────────────────────────────
# soft_delete_user / restore_user
# ─────────────────────────────────────────────

async def test_soft_delete_hides_user(db_session):
    repo = DatabaseRepository(db_session)
    user = await make_user(repo, "l")
    await repo.soft_delete_user(user["user_id_hex"])
    result = await repo.get_user_by_id_hex(user["user_id_hex"])
    assert result is None  # get returns None for deleted users


async def test_restore_user_makes_user_visible_again(db_session):
    repo = DatabaseRepository(db_session)
    user = await make_user(repo, "m")
    await repo.soft_delete_user(user["user_id_hex"])
    await repo.restore_user(user["user_id_hex"])
    result = await repo.get_user_by_id_hex(user["user_id_hex"])
    assert result is not None


# ─────────────────────────────────────────────
# list_users / count_users
# ─────────────────────────────────────────────

async def test_list_users_returns_list(db_session):
    repo = DatabaseRepository(db_session)
    await make_user(repo, "n1")
    await make_user(repo, "n2")
    users = await repo.list_users(skip=0, limit=10)
    assert isinstance(users, list)
    assert len(users) >= 2


async def test_list_users_pagination(db_session):
    repo = DatabaseRepository(db_session)
    for i in range(5):
        await make_user(repo, f"page{i}")
    page1 = await repo.list_users(skip=0, limit=2)
    page2 = await repo.list_users(skip=2, limit=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert page1[0]["user_id_hex"] != page2[0]["user_id_hex"]


async def test_count_users_returns_int(db_session):
    repo = DatabaseRepository(db_session)
    await make_user(repo, "cnt1")
    count = await repo.count_users()
    assert isinstance(count, int)
    assert count >= 1
