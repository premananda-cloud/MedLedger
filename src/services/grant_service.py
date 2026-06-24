"""
services/grant_service.py — GrantService

Time-bound, revocable access grants for vault records.
Grantor encrypts the DEK for the grantee on the frontend — backend
only stores the bundle and enforces time windows.

Layer contract:
  ✓ Imports from database/ only
  ✗ No encryption or decryption (frontend)
  ✗ No DEK generation (frontend)
  ✗ No signature verification (frontend / middleware)
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone

from database import DatabaseRepository
from database.exceptions import RecordNotFoundError

from .audit_service import AuditService

log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class GrantService:
    """
    Time-bound access grants for vault records.

    Grantors create grants with a time window and a DEK bundle
    (DEK encrypted for the grantee by the frontend). Grantees
    fetch the bundle when they need to decrypt the record.

    Usage:
        grant_svc = GrantService(db_repo=repo, audit_service=audit_svc)
        grant = await grant_svc.create_grant(grantor_id, grantee_id, ...)
        access = await grant_svc.check_access(user_id, record_id)
    """

    def __init__(self, db_repo: DatabaseRepository, audit_service: AuditService):
        self.db    = db_repo
        self.audit = audit_service

    # ──────────────────────────────────────────
    # Create
    # ──────────────────────────────────────────

    async def create_grant(
        self,
        grantor_id_hex:     str,
        grantee_id_hex:     str,
        record_id:          str,
        permission_level:   str,
        time_start:         datetime,
        time_end:           datetime,
        dek_bundle_grantee: dict,
        signature_hex:      str,
        ip_address:         str,
    ) -> dict:
        """
        Create a time-bounded access grant.

        The grantor's frontend encrypts the DEK for the grantee and signs
        the grant. Backend stores both without inspecting them.

        1. Verify grantor owns the record
        2. Verify grantee exists
        3. Validate time window
        4. Fetch grantee's public key (stored in grant row for future verification)
        5. Create grant
        6. Audit log

        Args:
            dek_bundle_grantee: DEK encrypted for grantee (ECIES, from frontend)
            signature_hex:      Ed25519 signature by grantor (frontend)

        Raises:
            RecordNotFoundError: record or grantee not found
            ValueError: grantor doesn't own record, invalid time window,
                        invalid permission_level
        """
        if permission_level not in ("view_only", "view_download"):
            raise ValueError("permission_level must be 'view_only' or 'view_download'.")

        if time_end <= time_start:
            raise ValueError("time_end must be after time_start.")

        # Verify record exists and belongs to grantor
        record = await self.db.get_vault_record(record_id)
        if not record:
            raise RecordNotFoundError(f"Record '{record_id}' not found.")
        if record.get("owner_user_id_hex") != grantor_id_hex:
            raise ValueError("You do not own this record.")

        # Verify grantee exists and get their public key
        grantee = await self.db.get_user_by_id_hex(grantee_id_hex)
        if not grantee:
            raise RecordNotFoundError(f"Grantee '{grantee_id_hex}' not found.")

        grantee_public_key_hex = grantee.get("exchange_public_key") or ""
        grantee_key_hash       = grantee.get("public_key_hash") or grantee_id_hex
        grantor_key_hash       = record.get("owner_key_hash") or grantor_id_hex

        grant_id = secrets.token_hex(16)

        grant = await self.db.create_grant(
            grant_id=grant_id,
            record_id=record_id,
            grantor_key_hash=grantor_key_hash,
            grantee_key_hash=grantee_key_hash,
            grantee_user_id_hex=grantee_id_hex,
            grantee_public_key_hex=grantee_public_key_hex,
            permission_level=permission_level,
            time_start=time_start,
            time_end=time_end,
            dek_bundle_grantee=dek_bundle_grantee,
            signature_hex=signature_hex,
        )

        await self.audit.log_grant_event(
            "grant_create", grantor_id_hex, ip_address,
            grant_id=grant_id, record_id=record_id,
            detail={"grantee": grantee_id_hex, "permission": permission_level},
        )
        return grant

    # ──────────────────────────────────────────
    # Revoke
    # ──────────────────────────────────────────

    async def revoke_grant(
        self,
        grant_id:       str,
        revoker_id_hex: str,
        ip_address:     str,
    ) -> dict:
        """
        Revoke a grant.

        Only the grantor (record owner) may revoke. Raises ValueError
        if revoker is not the grantor.

        Raises:
            RecordNotFoundError: grant not found
            ValueError: revoker is not the grantor
        """
        grant = await self.db.get_grant(grant_id)
        if not grant:
            raise RecordNotFoundError(f"Grant '{grant_id}' not found.")

        # Verify revoker owns the record
        record = await self.db.get_vault_record(grant["record_id"])
        if not record or record.get("owner_user_id_hex") != revoker_id_hex:
            raise ValueError("You do not have permission to revoke this grant.")

        await self.db.revoke_grant(grant_id)
        await self.audit.log_grant_event(
            "grant_revoke", revoker_id_hex, ip_address,
            grant_id=grant_id, record_id=grant["record_id"],
        )
        return {"revoked": True, "grant_id": grant_id}

    # ──────────────────────────────────────────
    # Access check
    # ──────────────────────────────────────────

    async def check_access(self, user_id_hex: str, record_id: str) -> dict:
        """
        Check if a user has active access to a record.

        Checks: grant exists, not revoked, within time window.

        Returns:
            {"has_access": bool, "grant": dict | None, "permission_level": str | None}
        """
        grants = await self.db.get_grants_by_grantee(
            grantee_key_hash=user_id_hex,   # falls back gracefully
            active_only=True,
        )

        now = _now()
        for g in grants:
            if g.get("record_id") != record_id:
                continue
            if g.get("revoked"):
                continue
            time_start = g.get("time_start")
            time_end   = g.get("time_end")
            if time_start and time_end and time_start <= now <= time_end:
                return {
                    "has_access":       True,
                    "grant":            g,
                    "permission_level": g.get("permission_level"),
                }

        return {"has_access": False, "grant": None, "permission_level": None}

    # ──────────────────────────────────────────
    # Read
    # ──────────────────────────────────────────

    async def list_grants_for_record(
        self,
        record_id:    str,
        owner_id_hex: str,
    ) -> list[dict]:
        """
        List all grants on a record. Only callable by the record owner.

        Raises:
            RecordNotFoundError: record not found
            ValueError: caller is not the owner
        """
        record = await self.db.get_vault_record(record_id)
        if not record:
            raise RecordNotFoundError(f"Record '{record_id}' not found.")
        if record.get("owner_user_id_hex") != owner_id_hex:
            raise ValueError("You do not own this record.")

        return await self.db.get_grants_for_record(record_id, active_only=False)

    async def list_my_grants(
        self,
        user_id_hex: str,
        as_grantor:  bool = True,
    ) -> list[dict]:
        """
        List grants where this user is the grantor or grantee.

        Args:
            as_grantor: True → grants I created; False → grants I received
        """
        user = await self.db.get_user_by_id_hex(user_id_hex)
        if not user:
            raise RecordNotFoundError("User not found.")

        key_hash = user.get("public_key_hash") or user_id_hex

        if as_grantor:
            return await self.db.get_grants_by_grantor(key_hash, active_only=False)
        else:
            return await self.db.get_grants_by_grantee(key_hash, active_only=False)

    async def get_grant_details(
        self,
        grant_id:    str,
        user_id_hex: str,
    ) -> dict:
        """
        Get full grant details including the DEK bundle.

        Only callable by the grantor or the grantee.
        Marks the grant as retrieved if it hasn't been yet.

        Raises:
            RecordNotFoundError: grant not found
            ValueError: caller is neither grantor nor grantee
        """
        grant = await self.db.get_grant(grant_id)
        if not grant:
            raise RecordNotFoundError(f"Grant '{grant_id}' not found.")

        is_grantee = grant.get("grantee_user_id_hex") == user_id_hex
        is_grantor = (
            await self.db.get_vault_record(grant["record_id"]) or {}
        ).get("owner_user_id_hex") == user_id_hex

        if not is_grantee and not is_grantor:
            raise ValueError("You do not have access to this grant.")

        # Mark retrieved on first grantee access
        if is_grantee and not grant.get("retrieved_at"):
            try:
                await self.db.mark_grant_retrieved(grant_id)
            except RecordNotFoundError:
                pass

        return grant
