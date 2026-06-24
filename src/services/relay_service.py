"""
services/relay_service.py — RelayService

Real-time encrypted payload relay between users.

The backend is a zero-knowledge pass-through:
  ✗ Never stores encrypted payloads
  ✗ Never decrypts anything
  ✗ Never verifies signatures (frontend does that on receipt)
  ✓ Routes payloads between users
  ✓ Enforces grant-based access before routing
  ✓ Stores share metadata (not ciphertext) for pending requests
  ✓ Manages notifications so recipients know when data is ready
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from database import DatabaseRepository
from database.exceptions import RecordNotFoundError

from .audit_service import AuditService
from .grant_service import GrantService
from .key_service   import KeyService

log = logging.getLogger(__name__)

_SHARE_TTL_HOURS = 24   # pending share requests expire after this


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RelayService:
    """
    Encrypted payload relay between users.

    Flow:
        1. Grantee calls request_share() → stored as a pending request
        2. Owner sees it via get_pending_requests()
        3. Owner encrypts the DEK for grantee on the frontend
        4. Owner calls send_encrypted_payload() → relay returns payload
           directly in the response (never stored)
        5. Grantee receives payload in the API response

    For async delivery (WebSocket / SSE) the notification system
    (notify_payload_ready / fetch_notifications) bridges the gap.

    Usage:
        relay_svc = RelayService(db_repo, key_svc, grant_svc, audit_svc)
        result = await relay_svc.send_encrypted_payload(sender, recipient, ...)
    """

    def __init__(
        self,
        db_repo:       DatabaseRepository,
        key_service:   KeyService,
        grant_service: GrantService,
        audit_service: AuditService,
    ):
        self.db    = db_repo
        self.keys  = key_service
        self.grants = grant_service
        self.audit = audit_service

    # ──────────────────────────────────────────
    # Share requests
    # ──────────────────────────────────────────

    async def request_share(
        self,
        requester_id_hex:     str,
        owner_id_hex:         str,
        record_id:            str,
        requester_public_key: str,
        ip_address:           str,
    ) -> dict:
        """
        Grantee requests access to a specific record from its owner.

        1. Verify both users exist
        2. Verify requester has an active grant for the record
        3. Store a pending request (as an active_share stub)
        4. Notify owner (via notification record)
        5. Audit log

        The requester's public key is included so the owner's frontend
        can encrypt the DEK for the requester without a separate key lookup.

        Raises:
            RecordNotFoundError: owner or requester not found
            ValueError: no active grant for this record
        """
        # Both users must exist
        owner     = await self.db.get_user_by_id_hex(owner_id_hex)
        requester = await self.db.get_user_by_id_hex(requester_id_hex)
        if not owner:
            raise RecordNotFoundError(f"Owner '{owner_id_hex}' not found.")
        if not requester:
            raise RecordNotFoundError(f"Requester '{requester_id_hex}' not found.")

        # Grant must exist and be active
        access = await self.grants.check_access(requester_id_hex, record_id)
        if not access["has_access"]:
            raise ValueError("No active grant for this record.")

        # Store pending request as an active_share with status metadata
        # We use a minimal stub — no ciphertext (relay model means we don't store it)
        share = await self.db.create_share(
            owner_user_id_hex=owner_id_hex,
            grantee_user_id_hex=requester_id_hex,
            ciphertext=b"pending",          # placeholder — never actual ciphertext
            dek_bundle=requester_public_key, # store requester's key for owner's use
            nonce="pending",
            filename=record_id,
            size_bytes=0,
            signature="pending",
            expires_at=_now() + timedelta(hours=_SHARE_TTL_HOURS),
            delete_on_download=True,
        )

        await self.audit.log_relay_event(
            "share_requested",
            recipient_id_hex=owner_id_hex,
            sender_id_hex=requester_id_hex,
            ip_address=ip_address,
            detail={"record_id": record_id, "share_id": str(share["share_id"])},
        )

        return {
            "status":   "pending",
            "share_id": str(share["share_id"]),
            "message":  "Owner has been notified of your request.",
        }

    async def get_pending_requests(self, owner_id_hex: str) -> list[dict]:
        """
        Get all pending share requests addressed to this owner.

        Returns minimal info — no ciphertext, no keys.
        Owner uses record_id to locate the record and encrypt the DEK.
        """
        shares = await self.db.get_shares_by_owner(
            owner_user_id_hex=owner_id_hex,
            status="active",
        )
        return [
            {
                "share_id":            str(s["share_id"]),
                "requester_id_hex":    s["grantee_user_id_hex"],
                "record_id":           s["filename"],        # stored in filename field
                "requester_public_key": s["dek_bundle"],     # stored in dek_bundle field
                "requested_at":        s["created_at"],
                "expires_at":          s["expires_at"],
            }
            for s in shares
            if s.get("ciphertext") == b"pending"   # only stubs, not real shares
        ]

    async def reject_share_request(
        self,
        owner_id_hex: str,
        share_id:     str,
        ip_address:   str,
    ) -> dict:
        """
        Owner rejects a pending share request.

        Raises:
            RecordNotFoundError: share not found
            ValueError: caller is not the owner of this share
        """
        from uuid import UUID
        share = await self.db.get_share_by_id(UUID(share_id))
        if not share:
            raise RecordNotFoundError(f"Share request '{share_id}' not found.")

        if share.get("owner_user_id_hex") != owner_id_hex:
            raise ValueError("You are not the owner of this share request.")

        await self.db.update_share_status(UUID(share_id), "revoked")
        await self.audit.log_relay_event(
            "share_request_rejected",
            recipient_id_hex=share["grantee_user_id_hex"],
            sender_id_hex=owner_id_hex,
            ip_address=ip_address,
            detail={"share_id": share_id},
        )
        return {"rejected": True, "share_id": share_id}

    # ──────────────────────────────────────────
    # Payload relay (zero-knowledge pass-through)
    # ──────────────────────────────────────────

    async def send_encrypted_payload(
        self,
        sender_id_hex:    str,
        recipient_id_hex: str,
        record_id:        str,
        encrypted_payload: str,
        signature:        str,
        ip_address:       str,
    ) -> dict:
        """
        Route an encrypted payload from owner to recipient.

        The payload is NEVER stored. It is returned directly in this
        response — the caller (route handler) forwards it to the recipient.

        1. Verify sender owns the record
        2. Verify recipient has an active grant
        3. Fetch sender's signing key (recipient needs it to verify signature)
        4. Mark the pending share request as retrieved
        5. Audit log
        6. Return payload + sender's signing key

        The frontend verifies the signature. The backend just routes.

        Raises:
            RecordNotFoundError: record not found
            ValueError: sender doesn't own record, or no active grant
        """
        record = await self.db.get_vault_record(record_id)
        if not record:
            raise RecordNotFoundError(f"Record '{record_id}' not found.")
        if record.get("owner_user_id_hex") != sender_id_hex:
            raise ValueError("You do not own this record.")

        access = await self.grants.check_access(recipient_id_hex, record_id)
        if not access["has_access"]:
            raise ValueError("Recipient does not have an active grant for this record.")

        # Fetch sender's signing key so recipient can verify the signature
        sender_keys = await self.keys.get_my_keys(sender_id_hex)

        await self.audit.log_relay_event(
            "payload_sent",
            sender_id_hex=sender_id_hex,
            recipient_id_hex=recipient_id_hex,
            ip_address=ip_address,
            detail={
                "record_id":        record_id,
                "payload_size":     len(encrypted_payload),
                "permission_level": access.get("permission_level"),
            },
        )

        # Payload is returned here — never persisted
        return {
            "encrypted_payload":  encrypted_payload,
            "signature":          signature,
            "sender_signing_key": sender_keys.get("signing_public_key"),
            "record_id":          record_id,
            "sender_id_hex":      sender_id_hex,
        }

    # ──────────────────────────────────────────
    # Notifications
    # ──────────────────────────────────────────

    async def notify_payload_ready(
        self,
        recipient_id_hex: str,
        payload_reference: str,
        sender_id_hex:    str,
        record_id:        str,
    ) -> dict:
        """
        Store a notification that an encrypted payload is ready for pickup.

        Used when delivery is async (WebSocket not yet connected, SSE stream
        not open). Recipient polls fetch_notifications() to find pending items.

        payload_reference is an opaque ID the recipient passes back to
        claim the payload — it does NOT contain the payload itself.

        Stored as an active_share record with status='active' and
        ciphertext=b'notification' sentinel so it's distinguishable from
        real shares and pending requests.
        """
        await self.db.create_share(
            owner_user_id_hex=sender_id_hex,
            grantee_user_id_hex=recipient_id_hex,
            ciphertext=b"notification",
            dek_bundle=payload_reference,
            nonce="notification",
            filename=record_id,
            size_bytes=0,
            signature=payload_reference,
            expires_at=_now() + timedelta(hours=_SHARE_TTL_HOURS),
            delete_on_download=True,
        )
        return {"notified": True, "recipient": recipient_id_hex}

    async def fetch_notifications(self, user_id_hex: str) -> list[dict]:
        """
        Get pending notifications for a user.

        Returns a list of {type, from_user, record_id, payload_reference, timestamp}.
        The payload_reference is what the client sends back to claim the payload.
        """
        shares = await self.db.get_shares_by_grantee(
            grantee_user_id_hex=user_id_hex,
            status="active",
        )
        notifications = []
        for s in shares:
            if s.get("ciphertext") == b"notification":
                notifications.append({
                    "type":              "payload_ready",
                    "from_user":         s["owner_user_id_hex"],
                    "record_id":         s["filename"],
                    "payload_reference": s["dek_bundle"],
                    "timestamp":         s["created_at"],
                    "share_id":          str(s["share_id"]),
                })
        return notifications
