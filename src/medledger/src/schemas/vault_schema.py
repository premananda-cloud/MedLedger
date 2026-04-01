"""
schemas/vault_schema.py

VaultRecord — metadata for an encrypted file stored in database/.

Ciphertext is intentionally separated into CiphertextRecord so that
listing/searching records never loads large binary blobs. Download is
the only operation that touches CiphertextRecord.

Fields
──────
record_id               str     uuid4 primary key
owner_key_hash          str     FK → UserRecord.public_key_hash
owner_public_key_hex    str     stored so grant verification can resolve
                                the owner's pubkey without a user-db lookup
filename                str     original filename (not a path — no traversal)
mime_type               str     guessed from filename
size_bytes              int     plaintext size (useful for display before decrypt)
iv_hex                  str     12-byte AES-GCM IV, hex-encoded
tags                    list    user-supplied string tags
created_at              str     ISO UTC
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class VaultRecord:
    record_id:            str
    owner_key_hash:       str
    owner_public_key_hex: str
    filename:             str
    mime_type:            str
    size_bytes:           int
    iv_hex:               str
    created_at:           str
    tags:                 list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "VaultRecord":
        return cls(
            record_id=d["record_id"],
            owner_key_hash=d["owner_key_hash"],
            owner_public_key_hex=d["owner_public_key_hex"],
            filename=d["filename"],
            mime_type=d["mime_type"],
            size_bytes=d["size_bytes"],
            iv_hex=d["iv_hex"],
            created_at=d["created_at"],
            tags=d.get("tags", []),
        )


@dataclass
class CiphertextRecord:
    """
    Holds the actual encrypted bytes and the owner's DEK bundle.
    Stored separately from VaultRecord — only fetched on download.

    dek_bundle is the ECIES-wrapped DEK dict:
        { "epk": hex, "iv": hex, "ct": hex, "tag": hex }
    """
    record_id:   str        # PK, FK → VaultRecord.record_id
    ciphertext:  bytes      # raw AES-256-GCM ciphertext (includes GCM tag)
    dek_bundle:  dict       # ECIES bundle for owner

    def to_dict(self) -> dict:
        return {
            "record_id":  self.record_id,
            "ciphertext": self.ciphertext.hex(),
            "dek_bundle": self.dek_bundle,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CiphertextRecord":
        ct = d["ciphertext"]
        return cls(
            record_id=d["record_id"],
            ciphertext=bytes.fromhex(ct) if isinstance(ct, str) else ct,
            dek_bundle=d["dek_bundle"],
        )
