"""
schemas/grant_schema.py

Grant — a cryptographically signed permission for a grantee to access a record.

Security fields
───────────────
dek_bundle_grantee  ECIES-wrapped DEK re-encrypted under grantee's public key.
                    The plaintext DEK is never stored — only this bundle.

signature_hex       ECDSA P-256 signature by the grantor over the canonical
                    permission payload (sorted-key JSON of the seven core fields).
                    Verified on every access attempt — a revoked row is rejected
                    even if the signature is valid.

Fields
──────
grant_id                str         uuid4 primary key
record_id               str         FK → VaultRecord.record_id
grantor_key_hash        str         FK → UserRecord.public_key_hash (owner)
grantee_key_hash        str         FK → UserRecord.public_key_hash (recipient)
grantee_public_key_hex  str         stored for DEK re-encryption; also used to
                                    resolve the grantee's key on inbox lookups
permission_level        str         "view_only" | "view_download"
time_start              str         ISO UTC — access window start
time_end                str         ISO UTC — access window end
dek_bundle_grantee      dict        ECIES bundle for grantee
signature_hex           str         ECDSA sig over canonical permission payload
revoked                 bool        True after revoke(); checked before every access
revoked_at              str | None  ISO UTC timestamp of revocation
created_at              str         ISO UTC
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional


VALID_PERMISSION_LEVELS = {"view_only", "view_download"}


@dataclass
class Grant:
    grant_id:               str
    record_id:              str
    grantor_key_hash:       str
    grantee_key_hash:       str
    grantee_public_key_hex: str
    permission_level:       str
    time_start:             str     # ISO UTC
    time_end:               str     # ISO UTC
    dek_bundle_grantee:     dict    # ECIES bundle — never plaintext DEK
    signature_hex:          str     # ECDSA sig over canonical permission payload
    created_at:             str
    revoked:                bool    = False
    revoked_at:             Optional[str] = None

    def is_permission_level_valid(self) -> bool:
        return self.permission_level in VALID_PERMISSION_LEVELS

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Grant":
        return cls(
            grant_id=d["grant_id"],
            record_id=d["record_id"],
            grantor_key_hash=d["grantor_key_hash"],
            grantee_key_hash=d["grantee_key_hash"],
            grantee_public_key_hex=d["grantee_public_key_hex"],
            permission_level=d["permission_level"],
            time_start=d["time_start"],
            time_end=d["time_end"],
            dek_bundle_grantee=d["dek_bundle_grantee"],
            signature_hex=d["signature_hex"],
            created_at=d["created_at"],
            revoked=d.get("revoked", False),
            revoked_at=d.get("revoked_at"),
        )


@dataclass
class VaultAuditEntry:
    """
    Audit trail for vault operations (upload, download, grant, revoke, rotate).
    Stored in database/ alongside vault records, not in data/ with user records.
    """
    id:             int
    action:         str     # UPLOAD | DOWNLOAD_OWNER | DOWNLOAD_GRANT |
                            # GRANT_CREATED | GRANT_REVOKED | KEY_ROTATED
    actor_key_hash: str     # public_key_hash of the acting user
    record_id:      str     # empty string when not record-specific
    detail:         str     # human-readable context
    timestamp:      str     # ISO UTC

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "VaultAuditEntry":
        return cls(
            id=d["id"],
            action=d["action"],
            actor_key_hash=d.get("actor_key_hash", ""),
            record_id=d.get("record_id", ""),
            detail=d.get("detail", ""),
            timestamp=d["timestamp"],
        )
