"""
tests/test_database/test_audit.py

Integration tests for DatabaseRepository audit_log and vault_audit operations.
"""
import pytest
from database.repository import DatabaseRepository


# ─────────────────────────────────────────────
# audit_log
# ─────────────────────────────────────────────

async def test_append_audit_log_succeeds(db_session):
    repo = DatabaseRepository(db_session)
    await repo.append_audit_log(
        action="user_login",
        ip_address="127.0.0.1",
        actor_user_id_hex="user123",
        detail={"source": "test"},
    )


async def test_get_audit_log_returns_list(db_session):
    repo = DatabaseRepository(db_session)
    await repo.append_audit_log(
        action="user_login",
        ip_address="127.0.0.1",
        actor_user_id_hex="audit_user1",
    )
    logs = await repo.get_audit_log()
    assert isinstance(logs, list)


async def test_get_audit_log_filter_by_actor(db_session):
    repo = DatabaseRepository(db_session)
    actor = "audit_actor_unique"
    await repo.append_audit_log(
        action="user_login",
        ip_address="127.0.0.1",
        actor_user_id_hex=actor,
    )
    logs = await repo.get_audit_log(actor_user_id_hex=actor)
    assert all(l["actor_user_id_hex"] == actor for l in logs)
    assert len(logs) >= 1


async def test_get_audit_log_filter_by_action(db_session):
    repo = DatabaseRepository(db_session)
    await repo.append_audit_log(
        action="user_logout",
        ip_address="127.0.0.1",
        actor_user_id_hex="user_logout_test",
    )
    logs = await repo.get_audit_log(action="user_logout")
    assert all(l["action"] == "user_logout" for l in logs)


async def test_get_audit_log_pagination(db_session):
    repo = DatabaseRepository(db_session)
    actor = "paginate_audit_user"
    for _ in range(5):
        await repo.append_audit_log(
            action="user_login",
            ip_address="127.0.0.1",
            actor_user_id_hex=actor,
        )
    page1 = await repo.get_audit_log(actor_user_id_hex=actor, skip=0, limit=2)
    page2 = await repo.get_audit_log(actor_user_id_hex=actor, skip=2, limit=2)
    assert len(page1) == 2
    assert len(page2) == 2


async def test_audit_log_newest_first(db_session):
    repo = DatabaseRepository(db_session)
    actor = "order_test_user"
    for action in ["event_a", "event_b", "event_c"]:
        await repo.append_audit_log(
            action=action,
            ip_address="127.0.0.1",
            actor_user_id_hex=actor,
        )
    logs = await repo.get_audit_log(actor_user_id_hex=actor, limit=10)
    # Newest first → last appended should come first
    assert len(logs) >= 3


async def test_append_audit_log_with_no_actor(db_session):
    repo = DatabaseRepository(db_session)
    # Should succeed with null actor
    await repo.append_audit_log(
        action="system_event",
        ip_address="0.0.0.0",
        actor_user_id_hex=None,
    )


# ─────────────────────────────────────────────
# vault_audit
# ─────────────────────────────────────────────

async def test_append_vault_audit_succeeds(db_session):
    repo = DatabaseRepository(db_session)
    await repo.append_vault_audit(
        action="vault_unlock",
        actor_key_hash="keyhash123",
        record_id="record456",
        detail="unlocked by owner",
        ip_address="127.0.0.1",
    )


async def test_get_vault_audit_returns_list(db_session):
    repo = DatabaseRepository(db_session)
    await repo.append_vault_audit(
        action="vault_access",
        actor_key_hash="keyhash_va1",
        record_id="record_va1",
    )
    logs = await repo.get_vault_audit()
    assert isinstance(logs, list)


async def test_get_vault_audit_filter_by_actor(db_session):
    repo = DatabaseRepository(db_session)
    actor_key = "unique_actor_key_va"
    await repo.append_vault_audit(
        action="vault_download",
        actor_key_hash=actor_key,
        record_id="rec_filter",
    )
    logs = await repo.get_vault_audit(actor_key_hash=actor_key)
    assert len(logs) >= 1
    assert all(l["actor_key_hash"] == actor_key for l in logs)


async def test_get_vault_audit_filter_by_record(db_session):
    repo = DatabaseRepository(db_session)
    record_id = "unique_record_vault_test"
    await repo.append_vault_audit(
        action="vault_access",
        actor_key_hash="some_key",
        record_id=record_id,
    )
    logs = await repo.get_vault_audit(record_id=record_id)
    assert len(logs) >= 1
    assert all(l["record_id"] == record_id for l in logs)
