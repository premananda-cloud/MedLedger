"""
database/pg_vault_store.py

PostgreSQL-backed vault store.
Drop-in replacement for VaultStore (JSON) — identical public interface.

Table layout mirrors the four logical tables in vault.json:
  vault_records     — VaultRecord  (metadata, never ciphertext)
  vault_ciphertext  — CiphertextRecord  (BYTEA blob + owner DEK bundle)
  grants            — Grant
  vault_audit       — VaultAuditEntry

Ciphertext is stored as BYTEA; JSON blobs (dek_bundle, tags) are stored as
JSONB.  All timestamps are ISO-8601 TEXT strings to match the existing schema
layer exactly — no datetime objects escape this module.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras
from psycopg2 import pool as pg_pool

from src.schemas import (
    VaultRecord, CiphertextRecord,
    Grant, VaultAuditEntry,
)


# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS vault_records (
    record_id             TEXT    PRIMARY KEY,
    owner_key_hash        TEXT    NOT NULL,
    owner_public_key_hex  TEXT    NOT NULL,
    filename              TEXT    NOT NULL,
    mime_type             TEXT    NOT NULL,
    size_bytes            INTEGER NOT NULL,
    iv_hex                TEXT    NOT NULL,
    tags                  JSONB   NOT NULL DEFAULT '[]',
    created_at            TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS vault_records_owner_idx
    ON vault_records (owner_key_hash);

CREATE TABLE IF NOT EXISTS vault_ciphertext (
    record_id   TEXT  PRIMARY KEY REFERENCES vault_records(record_id) ON DELETE CASCADE,
    ciphertext  BYTEA NOT NULL,
    dek_bundle  JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
    grant_id               TEXT    PRIMARY KEY,
    record_id              TEXT    NOT NULL REFERENCES vault_records(record_id),
    grantor_key_hash       TEXT    NOT NULL,
    grantee_key_hash       TEXT    NOT NULL,
    grantee_public_key_hex TEXT    NOT NULL,
    permission_level       TEXT    NOT NULL,
    time_start             TEXT    NOT NULL,
    time_end               TEXT    NOT NULL,
    dek_bundle_grantee     JSONB   NOT NULL,
    signature_hex          TEXT    NOT NULL,
    revoked                BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at             TEXT,
    created_at             TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS grants_grantor_idx  ON grants (grantor_key_hash);
CREATE INDEX IF NOT EXISTS grants_grantee_idx  ON grants (grantee_key_hash);
CREATE INDEX IF NOT EXISTS grants_record_idx   ON grants (record_id);

CREATE TABLE IF NOT EXISTS vault_audit (
    id              SERIAL  PRIMARY KEY,
    action          TEXT    NOT NULL,
    actor_key_hash  TEXT    NOT NULL DEFAULT '',
    record_id       TEXT    NOT NULL DEFAULT '',
    detail          TEXT    NOT NULL DEFAULT '',
    timestamp       TEXT    NOT NULL
);
"""


# ── helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_bytes(val) -> bytes:
    """Normalise psycopg2 BYTEA return (may be memoryview) to plain bytes."""
    if isinstance(val, memoryview):
        return bytes(val)
    return val


# ── store ─────────────────────────────────────────────────────────────────────

class PgVaultStore:

    def __init__(self, dsn: str):
        self._pool = pg_pool.ThreadedConnectionPool(1, 10, dsn=dsn)
        self._init_schema()

    # ── schema ────────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        with self._tx() as cur:
            cur.execute(_DDL)

    # ── connection context manager ────────────────────────────────────────────

    @contextmanager
    def _tx(self):
        """Yield a RealDictCursor inside a single transaction."""
        conn = self._pool.getconn()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            self._pool.putconn(conn)

    # ── row → schema conversion ───────────────────────────────────────────────

    @staticmethod
    def _to_vault_record(row) -> VaultRecord:
        d = dict(row)
        # JSONB tags come back as a Python list already
        return VaultRecord.from_dict(d)

    @staticmethod
    def _to_ct_record(row) -> CiphertextRecord:
        d = dict(row)
        d["ciphertext"] = _to_bytes(d["ciphertext"])
        # JSONB dek_bundle comes back as a Python dict already
        return CiphertextRecord.from_dict(d)

    @staticmethod
    def _to_grant(row) -> Grant:
        d = dict(row)
        # JSONB dek_bundle_grantee comes back as a Python dict already
        return Grant.from_dict(d)

    @staticmethod
    def _to_audit(row) -> VaultAuditEntry:
        return VaultAuditEntry.from_dict(dict(row))

    # ── record queries ────────────────────────────────────────────────────────

    def get_record(self, record_id: str) -> Optional[VaultRecord]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM vault_records WHERE record_id = %s", (record_id,)
            )
            row = cur.fetchone()
        return self._to_vault_record(row) if row else None

    def list_records_by_owner(self, owner_key_hash: str) -> list[VaultRecord]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM vault_records WHERE owner_key_hash = %s "
                "ORDER BY created_at DESC",
                (owner_key_hash,),
            )
            rows = cur.fetchall()
        return [self._to_vault_record(r) for r in rows]

    def get_ciphertext(self, record_id: str) -> Optional[CiphertextRecord]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM vault_ciphertext WHERE record_id = %s", (record_id,)
            )
            row = cur.fetchone()
        return self._to_ct_record(row) if row else None

    # ── record mutations ──────────────────────────────────────────────────────

    def save_record(
        self,
        record: VaultRecord,
        ct_record: CiphertextRecord,
    ) -> None:
        """Atomically insert VaultRecord + CiphertextRecord in one transaction."""
        with self._tx() as cur:
            cur.execute(
                """
                INSERT INTO vault_records
                    (record_id, owner_key_hash, owner_public_key_hex,
                     filename, mime_type, size_bytes, iv_hex, tags, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    record.record_id,
                    record.owner_key_hash,
                    record.owner_public_key_hex,
                    record.filename,
                    record.mime_type,
                    record.size_bytes,
                    record.iv_hex,
                    psycopg2.extras.Json(record.tags),
                    record.created_at,
                ),
            )
            cur.execute(
                """
                INSERT INTO vault_ciphertext (record_id, ciphertext, dek_bundle)
                VALUES (%s, %s, %s)
                """,
                (
                    ct_record.record_id,
                    psycopg2.Binary(ct_record.ciphertext),
                    psycopg2.extras.Json(ct_record.dek_bundle),
                ),
            )

    def update_record_dek(
        self,
        record_id: str,
        new_dek_bundle: dict,
        new_owner_key_hash: str,
        new_owner_public_key_hex: str,
    ) -> None:
        """Replace DEK bundle and owner key on a single record (key rotation)."""
        with self._tx() as cur:
            cur.execute(
                """
                UPDATE vault_records SET
                    owner_key_hash       = %s,
                    owner_public_key_hex = %s
                WHERE record_id = %s
                """,
                (new_owner_key_hash, new_owner_public_key_hex, record_id),
            )
            cur.execute(
                "UPDATE vault_ciphertext SET dek_bundle = %s WHERE record_id = %s",
                (psycopg2.extras.Json(new_dek_bundle), record_id),
            )

    def batch_rotate_owner(
        self,
        old_owner_key_hash: str,
        new_owner_key_hash: str,
        new_owner_public_key_hex: str,
        new_dek_bundles: dict[str, dict],   # record_id → new dek_bundle
    ) -> int:
        """
        Atomically rotate the owner key on ALL records owned by old_owner_key_hash.
        Returns the number of records updated.
        """
        with self._tx() as cur:
            cur.execute(
                """
                UPDATE vault_records SET
                    owner_key_hash       = %s,
                    owner_public_key_hex = %s
                WHERE owner_key_hash = %s
                """,
                (new_owner_key_hash, new_owner_public_key_hex, old_owner_key_hash),
            )
            updated = cur.rowcount

            # Update each DEK bundle individually (different bundle per record)
            for record_id, bundle in new_dek_bundles.items():
                cur.execute(
                    "UPDATE vault_ciphertext SET dek_bundle = %s WHERE record_id = %s",
                    (psycopg2.extras.Json(bundle), record_id),
                )
        return updated

    # ── grant queries ─────────────────────────────────────────────────────────

    def get_grant(self, grant_id: str) -> Optional[Grant]:
        with self._tx() as cur:
            cur.execute("SELECT * FROM grants WHERE grant_id = %s", (grant_id,))
            row = cur.fetchone()
        return self._to_grant(row) if row else None

    def list_grants_by_grantor(self, grantor_key_hash: str) -> list[Grant]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM grants WHERE grantor_key_hash = %s ORDER BY created_at DESC",
                (grantor_key_hash,),
            )
            rows = cur.fetchall()
        return [self._to_grant(r) for r in rows]

    def list_grants_by_grantee(self, grantee_key_hash: str) -> list[Grant]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM grants WHERE grantee_key_hash = %s ORDER BY created_at DESC",
                (grantee_key_hash,),
            )
            rows = cur.fetchall()
        return [self._to_grant(r) for r in rows]

    def list_active_grants_for_record(
        self,
        record_id: str,
        grantee_key_hash: str,
    ) -> list[Grant]:
        """Return non-revoked grants for a specific record + grantee pair."""
        with self._tx() as cur:
            cur.execute(
                """
                SELECT * FROM grants
                WHERE record_id        = %s
                  AND grantee_key_hash = %s
                  AND revoked          = FALSE
                """,
                (record_id, grantee_key_hash),
            )
            rows = cur.fetchall()
        return [self._to_grant(r) for r in rows]

    # ── grant mutations ───────────────────────────────────────────────────────

    def save_grant(self, grant: Grant) -> None:
        with self._tx() as cur:
            cur.execute(
                """
                INSERT INTO grants
                    (grant_id, record_id, grantor_key_hash, grantee_key_hash,
                     grantee_public_key_hex, permission_level,
                     time_start, time_end,
                     dek_bundle_grantee, signature_hex,
                     revoked, revoked_at, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    grant.grant_id,
                    grant.record_id,
                    grant.grantor_key_hash,
                    grant.grantee_key_hash,
                    grant.grantee_public_key_hex,
                    grant.permission_level,
                    grant.time_start,
                    grant.time_end,
                    psycopg2.extras.Json(grant.dek_bundle_grantee),
                    grant.signature_hex,
                    grant.revoked,
                    grant.revoked_at,
                    grant.created_at,
                ),
            )

    def revoke_grant(self, grant_id: str, revoked_at: str) -> bool:
        """
        Mark grant as revoked. Returns True if found + revoked,
        False if already revoked or not found.
        """
        with self._tx() as cur:
            cur.execute(
                """
                UPDATE grants
                SET revoked = TRUE, revoked_at = %s
                WHERE grant_id = %s AND revoked = FALSE
                """,
                (revoked_at, grant_id),
            )
            return cur.rowcount == 1

    def revoke_all_grants_for_records(
        self,
        record_ids: set[str],
        revoked_at: str,
    ) -> int:
        """Revoke all active grants for a set of record IDs (used in key rotation)."""
        if not record_ids:
            return 0
        with self._tx() as cur:
            cur.execute(
                """
                UPDATE grants
                SET revoked = TRUE, revoked_at = %s
                WHERE record_id = ANY(%s) AND revoked = FALSE
                """,
                (revoked_at, list(record_ids)),
            )
            return cur.rowcount

    # ── vault audit ───────────────────────────────────────────────────────────

    def append_audit(
        self,
        *,
        action: str,
        actor_key_hash: str,
        record_id: str = "",
        detail: str = "",
    ) -> VaultAuditEntry:
        with self._tx() as cur:
            cur.execute(
                """
                INSERT INTO vault_audit
                    (action, actor_key_hash, record_id, detail, timestamp)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING *
                """,
                (action, actor_key_hash, record_id, detail, _now()),
            )
            row = cur.fetchone()
        return self._to_audit(row)

    def get_audit_for_record(self, record_id: str) -> list[VaultAuditEntry]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM vault_audit WHERE record_id = %s ORDER BY id",
                (record_id,),
            )
            rows = cur.fetchall()
        return [self._to_audit(r) for r in rows]

    def get_audit_for_actor(self, actor_key_hash: str) -> list[VaultAuditEntry]:
        with self._tx() as cur:
            cur.execute(
                "SELECT * FROM vault_audit WHERE actor_key_hash = %s ORDER BY id",
                (actor_key_hash,),
            )
            rows = cur.fetchall()
        return [self._to_audit(r) for r in rows]
