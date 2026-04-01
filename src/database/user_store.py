"""
database/user_store.py

Persistent store for UserRecord and AuditEntry — written to data/users.json.

All reads and writes go through typed schema objects (UserRecord, AuditEntry).
The JSON file is the only source of truth; this class never caches state.
Writes are atomic (tmp-file replace) and thread-safe.

Interface matches what registration.py and auth.py already call so the
swap from json_store.py is a one-line config change.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.schemas import UserRecord, AuditEntry

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_id(records: list) -> int:
    return (max(r["id"] for r in records) + 1) if records else 1


class UserStore:

    def __init__(self, path: Path):
        self.path = path
        self._bootstrap()

    # ── I/O ──────────────────────────────────────────────────────────────────

    def _bootstrap(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({"users": [], "audit": []})

    def _read(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, data: dict):
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        tmp.replace(self.path)

    # ── queries ───────────────────────────────────────────────────────────────

    def get_by_email(self, email: str) -> Optional[UserRecord]:
        data = self._read()
        raw  = next((u for u in data["users"]
                     if u["email"] == email.lower()), None)
        return UserRecord.from_dict(raw) if raw else None

    def get_by_id(self, user_id: int) -> Optional[UserRecord]:
        data = self._read()
        raw  = next((u for u in data["users"] if u["id"] == user_id), None)
        return UserRecord.from_dict(raw) if raw else None

    def get_by_verification_token(self, token: str) -> Optional[UserRecord]:
        data = self._read()
        raw  = next((u for u in data["users"]
                     if u.get("verification_token") == token), None)
        return UserRecord.from_dict(raw) if raw else None

    def get_by_public_key_hash(self, pkh: str) -> Optional[UserRecord]:
        data = self._read()
        raw  = next((u for u in data["users"]
                     if u.get("public_key_hash") == pkh), None)
        return UserRecord.from_dict(raw) if raw else None

    # ── mutations ─────────────────────────────────────────────────────────────

    def create_user(
        self,
        *,
        email: str,
        username: str,
        full_name: str = "",
        role: str = "PATIENT",
        password_hash: str,
        verification_token: str,
        token_expires_at: str,
    ) -> UserRecord:
        """
        Insert a new unverified user. Raises ValueError on duplicate
        email or username.
        """
        with _lock:
            data  = self._read()
            users = data["users"]

            for u in users:
                if u["email"] == email.lower():
                    raise ValueError(f"Email already registered: {email}")
                if u["username"].lower() == username.lower():
                    raise ValueError(f"Username already taken: {username}")

            record = UserRecord(
                id=_next_id(users),
                email=email.lower(),
                username=username,
                full_name=full_name,
                role=role,
                password_hash=password_hash,
                is_verified=False,
                is_active=False,
                created_at=_now(),
                verification_token=verification_token,
                token_expires_at=token_expires_at,
            )
            users.append(record.to_dict())
            self._write(data)
            return record

    def activate_user(
        self,
        *,
        user_id: int,
        public_key_hex: str,
        public_key_compressed: str,
        public_key_hash: str,
    ) -> None:
        """
        Called after email verification.
        Sets public key fields, marks verified + active, clears the token.
        """
        with _lock:
            data = self._read()
            for u in data["users"]:
                if u["id"] == user_id:
                    u["is_verified"]          = True
                    u["is_active"]            = True
                    u["public_key_hex"]        = public_key_hex
                    u["public_key_compressed"] = public_key_compressed
                    u["public_key_hash"]       = public_key_hash
                    u["verification_token"]    = None
                    u["token_expires_at"]      = None
                    break
            self._write(data)

    def set_last_login(self, *, user_id: int) -> None:
        with _lock:
            data = self._read()
            for u in data["users"]:
                if u["id"] == user_id:
                    u["last_login"] = _now()
                    break
            self._write(data)

    # ── audit ─────────────────────────────────────────────────────────────────

    def append_audit(
        self,
        *,
        user_id: int,
        action: str,
        description: str,
    ) -> AuditEntry:
        with _lock:
            data    = self._read()
            entries = data["audit"]
            entry   = AuditEntry(
                id=_next_id(entries),
                user_id=user_id,
                action=action,
                description=description,
                timestamp=_now(),
            )
            entries.append(entry.to_dict())
            self._write(data)
            return entry

    def get_audit_for_user(self, user_id: int) -> list[AuditEntry]:
        data = self._read()
        return [
            AuditEntry.from_dict(e)
            for e in data["audit"]
            if e.get("user_id") == user_id
        ]
