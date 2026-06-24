"""
services/audit_service.py — AuditService

Centralized audit logging wrapper used by all other services.
Formats events consistently and delegates to DatabaseRepository.

No business logic. No auth. Just structured writes to the audit tables.
"""
from __future__ import annotations

import logging
from typing import Any, Dict
from uuid import UUID

from database import DatabaseRepository

log = logging.getLogger(__name__)


class AuditService:
    """
    Wraps DatabaseRepository audit methods with consistent event formatting.

    Every significant action in the system goes through here so audit
    logs are uniform and nothing is logged in two different formats.

    Usage:
        audit = AuditService(db_repo)
        await audit.log_auth_event("login_success", user_id_hex, ip)
    """

    def __init__(self, db_repo: DatabaseRepository):
        self.db = db_repo

    # ──────────────────────────────────────────
    # Auth events
    # ──────────────────────────────────────────

    async def log_auth_event(
        self,
        action:            str,
        actor_user_id_hex: str,
        ip_address:        str,
        detail:            Dict[str, Any] | None = None,
        user_agent:        str | None = None,
    ) -> None:
        """
        Log an authentication event.

        action: 'register' | 'login_success' | 'login_failure' | 'logout' |
                'verify_email' | 'totp_setup' | 'totp_verify' |
                'password_change' | 'password_reset_request' | 'password_reset_confirm' |
                'totp_disabled' | 'logout_all'
        """
        try:
            await self.db.append_audit_log(
                action=action,
                actor_user_id_hex=actor_user_id_hex,
                ip_address=ip_address,
                detail=detail or {},
                user_agent=user_agent,
            )
        except Exception:
            log.exception("Failed to write auth audit log: action=%s user=%s", action, actor_user_id_hex)

    # ──────────────────────────────────────────
    # Key events
    # ──────────────────────────────────────────

    async def log_key_event(
        self,
        action:            str,
        actor_user_id_hex: str,
        ip_address:        str,
        detail:            Dict[str, Any] | None = None,
    ) -> None:
        """
        Log a public key operation.

        action: 'keys_stored' | 'keys_updated' | 'keys_accessed'
        """
        try:
            await self.db.append_audit_log(
                action=action,
                actor_user_id_hex=actor_user_id_hex,
                ip_address=ip_address,
                detail=detail or {},
            )
        except Exception:
            log.exception("Failed to write key audit log: action=%s user=%s", action, actor_user_id_hex)

    # ──────────────────────────────────────────
    # Relay events
    # ──────────────────────────────────────────

    async def log_relay_event(
        self,
        action:           str,
        recipient_id_hex: str,
        ip_address:       str,
        sender_id_hex:    str | None = None,
        detail:           Dict[str, Any] | None = None,
    ) -> None:
        """
        Log a payload relay event.

        action: 'payload_sent' | 'payload_received' | 'share_requested' |
                'share_request_rejected'

        No plaintext in detail — only IDs and sizes.
        """
        try:
            safe_detail = {k: v for k, v in (detail or {}).items()
                           if k not in ("payload", "ciphertext", "dek", "key")}
            if sender_id_hex:
                safe_detail["sender_id_hex"] = sender_id_hex

            await self.db.append_audit_log(
                action=action,
                actor_user_id_hex=sender_id_hex or recipient_id_hex,
                ip_address=ip_address,
                detail=safe_detail,
            )
        except Exception:
            log.exception("Failed to write relay audit log: action=%s", action)

    # ──────────────────────────────────────────
    # Grant events
    # ──────────────────────────────────────────

    async def log_grant_event(
        self,
        action:            str,
        actor_user_id_hex: str,
        ip_address:        str,
        grant_id:          str | None = None,
        record_id:         str | None = None,
        detail:            Dict[str, Any] | None = None,
    ) -> None:
        """
        Log a grant operation.

        action: 'grant_create' | 'grant_revoke' | 'grant_accessed'
        """
        try:
            merged = {**(detail or {})}
            if grant_id:
                merged["grant_id"] = grant_id
            if record_id:
                merged["record_id"] = record_id

            await self.db.append_audit_log(
                action=action,
                actor_user_id_hex=actor_user_id_hex,
                ip_address=ip_address,
                detail=merged,
            )
        except Exception:
            log.exception("Failed to write grant audit log: action=%s grant=%s", action, grant_id)

    # ──────────────────────────────────────────
    # Vault events
    # ──────────────────────────────────────────

    async def log_vault_event(
        self,
        action:            str,
        actor_user_id_hex: str,
        ip_address:        str,
        record_id:         str | None = None,
        detail:            Dict[str, Any] | None = None,
    ) -> None:
        """
        Log a vault operation.

        action: 'record_created' | 'record_deleted' | 'vault_unlock' | 'vault_lock'
        """
        try:
            await self.db.append_vault_audit(
                action=action,
                actor_user_id_hex=actor_user_id_hex,
                record_id=record_id or "",
                detail=str(detail or {}),
                ip_address=ip_address,
            )
        except Exception:
            log.exception("Failed to write vault audit log: action=%s record=%s", action, record_id)
