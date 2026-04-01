"""
JSON User Store
Location: src/services/json_store.py

File layout:
{
  "users": [
    {
      "id", "email", "username", "password_hash",
      "verification_token", "token_expires_at",
      "is_verified", "is_active",
      "public_key_hex", "public_key_compressed", "public_key_hash",
      "created_at"
    }
  ],
  "audit": [ { "id", "user_id", "action", "description", "timestamp" } ]
}

private_key_pem is NEVER written here — not a field, not a parameter.
Writes are atomic. Thread-safe.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_id(records: list) -> int:
    if not records:
        return 1
    return max(r["id"] for r in records) + 1


class JsonStore:

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
        tmp.replace(self.path)

    # ── queries ───────────────────────────────────────────────────────────────

    def get_by_email(self, email: str) -> Optional[dict]:
        data = self._read()
        return next(
            (u for u in data["users"] if u["email"] == email.lower()), None
        )

    def get_by_id(self, user_id: int) -> Optional[dict]:
        data = self._read()
        return next((u for u in data["users"] if u["id"] == user_id), None)

    def get_by_verification_token(self, token: str) -> Optional[dict]:
        data = self._read()
        return next(
            (u for u in data["users"] if u.get("verification_token") == token), None
        )

    def get_by_public_key_hash(self, pkh: str) -> Optional[dict]:
        data = self._read()
        return next(
            (u for u in data["users"] if u.get("public_key_hash") == pkh), None
        )

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
    ) -> dict:
        """
        Insert a new unverified user.
        No public key fields yet — those are set in activate_user().
        Raises ValueError on duplicate email or username.
        """
        with _lock:
            data  = self._read()
            users = data["users"]

            for u in users:
                if u["email"] == email.lower():
                    raise ValueError(f"Email already registered: {email}")
                if u["username"].lower() == username.lower():
                    raise ValueError(f"Username already taken: {username}")

            user = {
                "id":                 _next_id(users),
                "email":              email.lower(),
                "username":           username,
                "full_name":          full_name,
                "role":               role,
                "password_hash":      password_hash,
                "verification_token": verification_token,
                "token_expires_at":   token_expires_at,
                "is_verified":        False,
                "is_active":          False,
                # public key fields are null until verify_email()
                "public_key_hex":        None,
                "public_key_compressed": None,
                "public_key_hash":       None,
                "created_at":            _now(),
                "last_login":            None,
            }
            users.append(user)
            self._write(data)
            return dict(user)

    def activate_user(
        self,
        *,
        user_id: int,
        public_key_hex: str,
        public_key_compressed: str,
        public_key_hash: str,
    ):
        """
        Called after email verification.
        Sets public key fields, marks verified + active,
        clears the verification token.
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
                    u["verification_token"]    = None   # consumed
                    u["token_expires_at"]      = None
                    break
            self._write(data)

    # ── audit ─────────────────────────────────────────────────────────────────

    def set_last_login(self, *, user_id: int):
        """Stamp last_login = now on successful authentication."""
        with _lock:
            data = self._read()
            for u in data["users"]:
                if u["id"] == user_id:
                    u["last_login"] = _now()
                    break
            self._write(data)

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
