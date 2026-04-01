"""
database/vault_store.py

Persistent store for the encrypted vault — written to database/vault.json.

Three logical tables, one JSON file (easy to split to SQLite later):
  records     — VaultRecord  (metadata, no ciphertext)
  ciphertext  — CiphertextRecord  (encrypted bytes + owner DEK bundle)
  grants      — Grant
  audit       — VaultAuditEntry

Ciphertext is stored separately so that listing records never loads
large binary blobs. Only download() touches CiphertextRecord.

All writes are atomic (tmp-file replace) and thread-safe.
All reads return typed schema objects — no raw dicts escape this module.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.schemas import (
    VaultRecord, CiphertextRecord,
    Grant, VaultAuditEntry,
)

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_id(records: list) -> int:
    return (max(r["id"] for r in records) + 1) if records else 1


_EMPTY = lambda: {"records": [], "ciphertext": [], "grants": [], "audit": []}


class VaultStore:

    def __init__(self, path: Path):
        self.path = path
        self._bootstrap()

    # ── I/O ──────────────────────────────────────────────────────────────────

    def _bootstrap(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write(_EMPTY())

    def _read(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, data: dict):
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        tmp.replace(self.path)

    # ── record queries ────────────────────────────────────────────────────────

    def get_record(self, record_id: str) -> Optional[VaultRecord]:
        data = self._read()
        raw  = next((r for r in data["records"]
                     if r["record_id"] == record_id), None)
        return VaultRecord.from_dict(raw) if raw else None

    def list_records_by_owner(self, owner_key_hash: str) -> list[VaultRecord]:
        data = self._read()
        return [
            VaultRecord.from_dict(r)
            for r in data["records"]
            if r["owner_key_hash"] == owner_key_hash
        ]

    def get_ciphertext(self, record_id: str) -> Optional[CiphertextRecord]:
        data = self._read()
        raw  = next((c for c in data["ciphertext"]
                     if c["record_id"] == record_id), None)
        return CiphertextRecord.from_dict(raw) if raw else None

    # ── record mutations ──────────────────────────────────────────────────────

    def save_record(
        self,
        record: VaultRecord,
        ct_record: CiphertextRecord,
    ) -> None:
        """
        Atomically write a new VaultRecord and its CiphertextRecord.
        Both are inserted in a single write so they are never out of sync.
        """
        with _lock:
            data = self._read()
            data["records"].append(record.to_dict())
            data["ciphertext"].append(ct_record.to_dict())
            self._write(data)

    def update_record_dek(
        self,
        record_id: str,
        new_dek_bundle: dict,
        new_owner_key_hash: str,
        new_owner_public_key_hex: str,
    ) -> None:
        """
        Used by key rotation: replace the DEK bundle and owner key fields.
        Called once per record inside a single batch write in rotate_key().
        """
        with _lock:
            data = self._read()
            for r in data["records"]:
                if r["record_id"] == record_id:
                    r["owner_key_hash"]       = new_owner_key_hash
                    r["owner_public_key_hex"] = new_owner_public_key_hex
                    break
            for c in data["ciphertext"]:
                if c["record_id"] == record_id:
                    c["dek_bundle"] = new_dek_bundle
                    break
            self._write(data)

    def batch_rotate_owner(
        self,
        old_owner_key_hash: str,
        new_owner_key_hash: str,
        new_owner_public_key_hex: str,
        new_dek_bundles: dict[str, dict],   # record_id → new dek_bundle
    ) -> int:
        """
        Atomically rotate the owner key on all records owned by old_owner_key_hash.
        new_dek_bundles maps record_id → new ECIES bundle.
        Returns the number of records updated.
        """
        with _lock:
            data    = self._read()
            updated = 0
            for r in data["records"]:
                if r["owner_key_hash"] == old_owner_key_hash:
                    r["owner_key_hash"]       = new_owner_key_hash
                    r["owner_public_key_hex"] = new_owner_public_key_hex
                    updated += 1
            for c in data["ciphertext"]:
                if c["record_id"] in new_dek_bundles:
                    c["dek_bundle"] = new_dek_bundles[c["record_id"]]
            self._write(data)
            return updated

    # ── grant queries ─────────────────────────────────────────────────────────

    def get_grant(self, grant_id: str) -> Optional[Grant]:
        data = self._read()
        raw  = next((g for g in data["grants"]
                     if g["grant_id"] == grant_id), None)
        return Grant.from_dict(raw) if raw else None

    def list_grants_by_grantor(self, grantor_key_hash: str) -> list[Grant]:
        data = self._read()
        return [
            Grant.from_dict(g) for g in data["grants"]
            if g["grantor_key_hash"] == grantor_key_hash
        ]

    def list_grants_by_grantee(self, grantee_key_hash: str) -> list[Grant]:
        data = self._read()
        return [
            Grant.from_dict(g) for g in data["grants"]
            if g["grantee_key_hash"] == grantee_key_hash
        ]

    def list_active_grants_for_record(
        self,
        record_id: str,
        grantee_key_hash: str,
    ) -> list[Grant]:
        """Return non-revoked grants for a specific record + grantee pair."""
        data = self._read()
        return [
            Grant.from_dict(g) for g in data["grants"]
            if g["record_id"]         == record_id
            and g["grantee_key_hash"] == grantee_key_hash
            and not g.get("revoked", False)
        ]

    # ── grant mutations ───────────────────────────────────────────────────────

    def save_grant(self, grant: Grant) -> None:
        with _lock:
            data = self._read()
            data["grants"].append(grant.to_dict())
            self._write(data)

    def revoke_grant(self, grant_id: str, revoked_at: str) -> bool:
        """
        Mark grant as revoked. Returns True if found and revoked,
        False if already revoked or not found.
        """
        with _lock:
            data = self._read()
            for g in data["grants"]:
                if g["grant_id"] == grant_id:
                    if g.get("revoked"):
                        return False
                    g["revoked"]    = True
                    g["revoked_at"] = revoked_at
                    self._write(data)
                    return True
            return False

    def revoke_all_grants_for_records(
        self,
        record_ids: set[str],
        revoked_at: str,
    ) -> int:
        """Revoke all active grants for a set of record IDs (used in key rotation)."""
        with _lock:
            data    = self._read()
            revoked = 0
            for g in data["grants"]:
                if g["record_id"] in record_ids and not g.get("revoked"):
                    g["revoked"]    = True
                    g["revoked_at"] = revoked_at
                    revoked += 1
            self._write(data)
            return revoked

    # ── vault audit ───────────────────────────────────────────────────────────

    def append_audit(
        self,
        *,
        action: str,
        actor_key_hash: str,
        record_id: str = "",
        detail: str = "",
    ) -> VaultAuditEntry:
        with _lock:
            data    = self._read()
            entries = data["audit"]
            entry   = VaultAuditEntry(
                id=_next_id(entries),
                action=action,
                actor_key_hash=actor_key_hash,
                record_id=record_id,
                detail=detail,
                timestamp=_now(),
            )
            entries.append(entry.to_dict())
            self._write(data)
            return entry

    def get_audit_for_record(self, record_id: str) -> list[VaultAuditEntry]:
        data = self._read()
        return [
            VaultAuditEntry.from_dict(e)
            for e in data["audit"]
            if e.get("record_id") == record_id
        ]

    def get_audit_for_actor(self, actor_key_hash: str) -> list[VaultAuditEntry]:
        data = self._read()
        return [
            VaultAuditEntry.from_dict(e)
            for e in data["audit"]
            if e.get("actor_key_hash") == actor_key_hash
        ]
