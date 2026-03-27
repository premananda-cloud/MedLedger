"""
JSON User Store
Location: src/database/json_store.py

Flat-file backend used when config.json → "db_backend": "json".
Stores everything in a single pretty-printed JSON file under data/.

NOT for production. This exists so you can test the full registration →
login → crypto flow without standing up SQLite or Postgres.

Public interface is intentionally thin — only what RegistrationService
needs. Nothing else should import from here directly.
"""

import json
import threading
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional


_lock = threading.Lock()


def _now() -> str:
    return datetime.utcnow().isoformat()


def _next_id(records: list) -> int:
    if not records:
        return 1
    return max(r["id"] for r in records) + 1


class JsonStore:
    """
    Minimal user store backed by a single JSON file.

    File layout:
    {
      "users": [ { id, email, username, full_name, role,
                   password_hash,
                   public_key_hex, public_key_compressed, public_key_hash,
                   is_active, created_at, last_login } ],
      "audit":  [ { id, user_id, action, description, timestamp } ]
    }
    """

    def __init__(self, path: Path):
        self.path = path
        self._bootstrap()

    # ── file I/O ──────────────────────────────────────────────────────────────

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
        tmp.replace(self.path)   # atomic rename

    # ── user queries ──────────────────────────────────────────────────────────

    def get_by_email(self, email: str) -> Optional[dict]:
        data = self._read()
        email_lower = email.lower()
        return next((u for u in data["users"] if u["email"].lower() == email_lower), None)

    def get_by_username(self, username: str) -> Optional[dict]:
        data = self._read()
        uname_lower = username.lower()
        return next((u for u in data["users"] if u["username"].lower() == uname_lower), None)

    def get_by_id(self, user_id: int) -> Optional[dict]:
        data = self._read()
        return next((u for u in data["users"] if u["id"] == user_id), None)

    def get_by_public_key_hash(self, pkh: str) -> Optional[dict]:
        data = self._read()
        return next((u for u in data["users"] if u["public_key_hash"] == pkh), None)

    # ── user mutations ────────────────────────────────────────────────────────

    def create_user(
        self,
        *,
        email: str,
        username: str,
        full_name: str,
        role: str,
        password_hash: str,
        public_key_hex: str,
        public_key_compressed: str,
        public_key_hash: str,
    ) -> dict:
        """
        Insert a new user row. Returns the created user dict (with id, created_at).
        Raises ValueError on duplicate email, username, or public_key_hash.
        """
        with _lock:
            data = self._read()
            users = data["users"]

            # uniqueness checks
            for u in users:
                if u["email"].lower() == email.lower():
                    raise ValueError(f"Email already registered: {email}")
                if u["username"].lower() == username.lower():
                    raise ValueError(f"Username already taken: {username}")
                if u["public_key_hash"] == public_key_hash:
                    raise ValueError("Public key hash collision — try again")

            user = {
                "id":                    _next_id(users),
                "email":                 email.lower(),
                "username":              username,
                "full_name":             full_name,
                "role":                  role,
                "password_hash":         password_hash,
                "public_key_hex":        public_key_hex,
                "public_key_compressed": public_key_compressed,
                "public_key_hash":       public_key_hash,
                "is_active":             True,
                "is_verified":           False,
                "created_at":            _now(),
                "last_login":            None,
            }
            users.append(user)
            self._write(data)
            return dict(user)   # return a copy

    def touch_last_login(self, user_id: int):
        with _lock:
            data = self._read()
            for u in data["users"]:
                if u["id"] == user_id:
                    u["last_login"] = _now()
                    break
            self._write(data)

    # ── audit ─────────────────────────────────────────────────────────────────

    def append_audit(self, *, user_id: int, action: str, description: str):
        with _lock:
            data = self._read()
            entry = {
                "id":          _next_id(data["audit"]),
                "user_id":     user_id,
                "action":      action,
                "description": description,
                "timestamp":   _now(),
            }
            data["audit"].append(entry)
            self._write(data)
