"""
schemas/user_schema.py

UserRecord — identity and authentication fields stored in data/users.json.

This schema covers everything registration.py writes and pg_user_store.py reads.
No vault/crypto fields live here — public_key_hex is the bridge to the vault
but does not belong to the vault itself.

Fields
──────
id                      int         auto-increment primary key
email                   str         unique, lowercase
username                str         unique, case-insensitive
full_name               str         display name, may be empty
role                    str         PATIENT | DOCTOR | ADMIN
password_hash           str         "sha256$iter$salt_hex$hash_hex"
public_key_hex          str | None  uncompressed P-256, 130 hex chars (set on verify)
public_key_compressed   str | None  compressed P-256, 66 hex chars
public_key_hash         str | None  SHA-256 of pub key bytes — FK into vault records
is_verified             bool        email confirmed
is_active               bool        account usable
verification_token      str | None  12-hour email token (cleared after use)
token_expires_at        str | None  ISO UTC
created_at              str         ISO UTC
last_login              str | None  ISO UTC
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional


VALID_ROLES = {"PATIENT", "DOCTOR", "ADMIN"}


@dataclass
class UserRecord:
    id:                     int
    email:                  str
    username:               str
    full_name:              str
    role:                   str
    password_hash:          str
    is_verified:            bool
    is_active:              bool
    created_at:             str

    # set after email verification
    public_key_hex:         Optional[str] = None
    public_key_compressed:  Optional[str] = None
    public_key_hash:        Optional[str] = None

    # transient — cleared once consumed
    verification_token:     Optional[str] = None
    token_expires_at:       Optional[str] = None

    # password-reset token (hashed server-side, returned plaintext once)
    reset_token_hash:       Optional[str] = None
    reset_token_expires_at: Optional[str] = None

    last_login:             Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "UserRecord":
        return cls(
            id=d["id"],
            email=d["email"],
            username=d["username"],
            full_name=d.get("full_name", ""),
            role=d.get("role", "PATIENT"),
            password_hash=d["password_hash"],
            is_verified=d.get("is_verified", False),
            is_active=d.get("is_active", False),
            created_at=d["created_at"],
            public_key_hex=d.get("public_key_hex"),
            public_key_compressed=d.get("public_key_compressed"),
            public_key_hash=d.get("public_key_hash"),
            verification_token=d.get("verification_token"),
            token_expires_at=d.get("token_expires_at"),
            reset_token_hash=d.get("reset_token_hash"),
            reset_token_expires_at=d.get("reset_token_expires_at"),
            last_login=d.get("last_login"),
        )

    def is_role_valid(self) -> bool:
        return self.role in VALID_ROLES


@dataclass
class AuditEntry:
    """
    Shared audit table used by both the user store and the vault.
    Lives in data/ when associated with user actions; database/ when
    associated with vault actions.
    """
    id:          int
    user_id:     int        # 0 for vault-level actions with no user context
    action:      str        # e.g. REGISTRATION_STARTED, LOGIN_SUCCESS
    description: str
    timestamp:   str        # ISO UTC

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEntry":
        return cls(
            id=d["id"],
            user_id=d.get("user_id", 0),
            action=d["action"],
            description=d.get("description", ""),
            timestamp=d["timestamp"],
        )
