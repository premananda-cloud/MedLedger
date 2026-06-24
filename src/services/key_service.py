"""
services/key_service.py — KeyService

Public key storage and retrieval.
No crypto operations — all key generation happens on the frontend.
Backend is a dumb store for public keys only.

Layer contract:
  ✓ Imports from database/ only
  ✗ No key generation
  ✗ No signing or encryption
  ✗ No private keys ever arrive here
"""
from __future__ import annotations

import logging
from typing import Dict

from database import DatabaseRepository
from database.exceptions import RecordNotFoundError

from .audit_service import AuditService

log = logging.getLogger(__name__)


class KeyService:
    """
    Public key storage and lookup.

    Frontend generates all key pairs. This service stores the public halves
    and hands them to whoever needs to encrypt data for a user or verify
    a signature from a user.

    Usage:
        key_svc = KeyService(db_repo=repo, audit_service=audit_svc)
        keys = await key_svc.get_public_keys(target_id, requester_id, ip)
    """

    def __init__(self, db_repo: DatabaseRepository, audit_service: AuditService):
        self.db    = db_repo
        self.audit = audit_service

    # ──────────────────────────────────────────
    # Write
    # ──────────────────────────────────────────

    async def store_initial_keys(
        self,
        user_id_hex:         str,
        signing_public_key:  str,
        exchange_public_key: str,
        ip_address:          str,
    ) -> dict:
        """
        Store public keys for a newly registered user.

        Called by AuthService during registration — not called directly
        by routes. Logs a key event.

        Raises:
            RecordNotFoundError: user does not exist
        """
        await self.db.set_public_keys(
            user_id_hex=user_id_hex,
            signing_public_key=signing_public_key,
            exchange_public_key=exchange_public_key,
        )
        await self.audit.log_key_event(
            "keys_stored", user_id_hex, ip_address,
            detail={"action": "initial_store"},
        )
        return {"stored": True, "user_id_hex": user_id_hex}

    async def update_keys(
        self,
        user_id_hex:          str,
        ip_address:           str,
        signing_public_key:   str | None = None,
        exchange_public_key:  str | None = None,
    ) -> dict:
        """
        Update one or both public keys.

        Only updates fields that are provided. Revoking/rotating keys
        invalidates all existing grants encrypted to the old key — the
        caller (service layer) must handle grant cleanup.

        Raises:
            ValueError: no keys provided
            RecordNotFoundError: user does not exist
        """
        if not signing_public_key and not exchange_public_key:
            raise ValueError("At least one key must be provided.")

        fields: Dict[str, str] = {}
        if signing_public_key:
            fields["signing_public_key"]  = signing_public_key
        if exchange_public_key:
            fields["exchange_public_key"] = exchange_public_key

        await self.db.update_user(user_id_hex, **fields)
        await self.audit.log_key_event(
            "keys_updated", user_id_hex, ip_address,
            detail={"updated_fields": list(fields.keys())},
        )
        return {"updated": True, "fields": list(fields.keys())}

    # ──────────────────────────────────────────
    # Read
    # ──────────────────────────────────────────

    async def get_public_keys(
        self,
        user_id_hex:      str,
        requester_id_hex: str,
        ip_address:       str,
    ) -> dict:
        """
        Get both public keys for a user.

        Used when requester needs to both encrypt data (exchange key)
        and later verify a signature (signing key) from this user.

        Logs a key access event.

        Returns:
            {signing_public_key, exchange_public_key, user_id_hex}

        Raises:
            RecordNotFoundError: user does not exist
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError(f"User '{user_id_hex}' not found.")

        await self.audit.log_key_event(
            "keys_accessed", requester_id_hex, ip_address,
            detail={"target_user_id_hex": user_id_hex, "key_type": "both"},
        )
        return {
            "user_id_hex":         user_id_hex,
            "signing_public_key":  user.get("signing_public_key"),
            "exchange_public_key": user.get("exchange_public_key"),
        }

    async def get_exchange_key(
        self,
        user_id_hex:      str,
        requester_id_hex: str,
        ip_address:       str,
    ) -> dict:
        """
        Get just the X25519 exchange public key for a user.

        Used when requester wants to encrypt data for this user.
        Logs a key access event.

        Raises:
            RecordNotFoundError: user does not exist
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError(f"User '{user_id_hex}' not found.")

        await self.audit.log_key_event(
            "keys_accessed", requester_id_hex, ip_address,
            detail={"target_user_id_hex": user_id_hex, "key_type": "exchange"},
        )
        return {
            "user_id_hex":         user_id_hex,
            "exchange_public_key": user.get("exchange_public_key"),
        }

    async def get_signing_key(
        self,
        user_id_hex:      str,
        requester_id_hex: str,
        ip_address:       str,
    ) -> dict:
        """
        Get just the Ed25519 signing public key for a user.

        Used to verify signatures from this user.
        Logs a key access event.

        Raises:
            RecordNotFoundError: user does not exist
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError(f"User '{user_id_hex}' not found.")

        await self.audit.log_key_event(
            "keys_accessed", requester_id_hex, ip_address,
            detail={"target_user_id_hex": user_id_hex, "key_type": "signing"},
        )
        return {
            "user_id_hex":        user_id_hex,
            "signing_public_key": user.get("signing_public_key"),
        }

    async def get_my_keys(self, user_id_hex: str) -> dict:
        """
        Get own public keys. No audit log — not a sensitive access.

        Returns:
            {signing_public_key, exchange_public_key, user_id_hex}

        Raises:
            RecordNotFoundError: user does not exist
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError("User not found.")

        return {
            "user_id_hex":         user_id_hex,
            "signing_public_key":  user.get("signing_public_key"),
            "exchange_public_key": user.get("exchange_public_key"),
        }
