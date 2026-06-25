"""
tests/test_database/test_vault.py

Integration tests for DatabaseRepository vault_records and vault_ciphertext operations.
"""
import secrets
import json
import pytest

from database.repository import DatabaseRepository
from database.exceptions import DuplicateError, RecordNotFoundError


def _record_id():
    return secrets.token_hex(16)


async def _make_vault_record(repo, record_id=None, owner_id="owner123"):
    rid = record_id or _record_id()
    return await repo.create_vault_record(
        record_id=rid,
        owner_key_hash="keyhash_" + secrets.token_hex(8),
        owner_user_id_hex=owner_id,
        owner_public_key_hex="pubkey_" + secrets.token_hex(32),
        filename="test_file.pdf",
        mime_type="application/pdf",
        size_bytes=1024,
        iv_hex=secrets.token_hex(12),
        tags=["medical", "test"],
    )


# ─────────────────────────────────────────────
# vault_records
# ─────────────────────────────────────────────

async def test_create_vault_record_succeeds(db_session):
    repo = DatabaseRepository(db_session)
    record = await _make_vault_record(repo)
    assert record["record_id"]
    assert record["filename"] == "test_file.pdf"


async def test_create_vault_record_duplicate_id_raises(db_session):
    repo = DatabaseRepository(db_session)
    rid = _record_id()
    await _make_vault_record(repo, record_id=rid)
    with pytest.raises(DuplicateError):
        await _make_vault_record(repo, record_id=rid)


async def test_get_vault_record_returns_record(db_session):
    repo = DatabaseRepository(db_session)
    record = await _make_vault_record(repo)
    found = await repo.get_vault_record(record["record_id"])
    assert found is not None
    assert found["record_id"] == record["record_id"]


async def test_get_vault_record_returns_none_for_missing(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.get_vault_record("nonexistent_record_id")
    assert result is None


async def test_list_vault_records_returns_owner_records(db_session):
    repo = DatabaseRepository(db_session)
    owner = "owner_list_test"
    for _ in range(3):
        await _make_vault_record(repo, owner_id=owner)
    records = await repo.list_vault_records(owner_user_id_hex=owner)
    assert len(records) >= 3
    for r in records:
        assert r["owner_user_id_hex"] == owner


async def test_list_vault_records_pagination(db_session):
    repo = DatabaseRepository(db_session)
    owner = "owner_page_test"
    for _ in range(5):
        await _make_vault_record(repo, owner_id=owner)
    page1 = await repo.list_vault_records(owner_user_id_hex=owner, skip=0, limit=2)
    page2 = await repo.list_vault_records(owner_user_id_hex=owner, skip=2, limit=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert page1[0]["record_id"] != page2[0]["record_id"]


async def test_delete_vault_record_removes_it(db_session):
    repo = DatabaseRepository(db_session)
    record = await _make_vault_record(repo)
    await repo.delete_vault_record(record["record_id"])
    assert await repo.get_vault_record(record["record_id"]) is None


async def test_delete_vault_record_missing_raises(db_session):
    repo = DatabaseRepository(db_session)
    with pytest.raises(RecordNotFoundError):
        await repo.delete_vault_record("nonexistent_record_xyz")


# ─────────────────────────────────────────────
# vault_ciphertext
# ─────────────────────────────────────────────

async def test_create_vault_ciphertext_succeeds(db_session):
    repo = DatabaseRepository(db_session)
    record = await _make_vault_record(repo)
    dek_bundle = json.dumps({"encrypted_dek": "abc123", "algorithm": "ECIES"})
    await repo.create_vault_ciphertext(
        record_id=record["record_id"],
        ciphertext=b"encrypted_data_here",
        dek_bundle=dek_bundle,
    )


async def test_get_vault_ciphertext_returns_data(db_session):
    repo = DatabaseRepository(db_session)
    record = await _make_vault_record(repo)
    dek_bundle = json.dumps({"encrypted_dek": "xyz789"})
    await repo.create_vault_ciphertext(
        record_id=record["record_id"],
        ciphertext=b"some encrypted bytes",
        dek_bundle=dek_bundle,
    )
    ct = await repo.get_vault_ciphertext(record["record_id"])
    assert ct is not None
    assert ct["record_id"] == record["record_id"]


async def test_get_vault_ciphertext_returns_none_for_missing(db_session):
    repo = DatabaseRepository(db_session)
    result = await repo.get_vault_ciphertext("nonexistent_id")
    assert result is None
