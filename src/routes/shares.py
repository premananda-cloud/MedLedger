"""
routes/shares.py — Share / relay endpoints.

All protected — JWT required.

POST /shares/request       → request encrypted payload from owner
POST /shares/send          → owner sends encrypted payload to recipient
POST /shares/reject        → owner rejects a pending share request
GET  /shares/pending       → owner sees pending requests
GET  /shares/notifications → recipient polls for ready payloads

Legacy direct-share endpoints (preserved from original routes/shares.py):
POST   /shares                       → create direct share (ciphertext stored)
GET    /shares/sent                  → shares I sent
GET    /shares/received              → shares received by me
GET    /shares/{share_id}            → share detail + keys
GET    /shares/{share_id}/ciphertext → stream ciphertext
DELETE /shares/{share_id}            → revoke share
GET    /shares/code/{code}           → resolve short code
GET    /users/search                 → search users for share recipient
"""
from __future__ import annotations

import base64
import io
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from database import DatabaseRepository
from database.exceptions import RecordNotFoundError
from models.schemas import (
    CreateShareRequest, EncryptedPayloadResponse, MessageResponse,
    NotificationResponse, PendingRequestsResponse, RejectShareRequest,
    RequestShareRequest, SendEncryptedPayloadRequest, ShareDetail,
    ShareRequestResponse, ShareSummary,
)
from services.relay_service import RelayService

from .deps import get_current_user, get_db_repo, get_relay_service

log = logging.getLogger(__name__)
router = APIRouter(prefix="/shares", tags=["shares"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Relay endpoints (new)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/request", response_model=ShareRequestResponse)
async def request_share(
    body:     RequestShareRequest,
    request:  Request,
    current_user: dict         = Depends(get_current_user),
    relay_svc:   RelayService  = Depends(get_relay_service),
):
    """Request an encrypted record from its owner."""
    try:
        result = await relay_svc.request_share(
            requester_id_hex=current_user["user_id_hex"],
            owner_id_hex=body.owner_id_hex,
            record_id=body.record_id,
            requester_public_key=body.requester_public_key,
            ip_address=request.client.host if request.client else "",
        )
        return ShareRequestResponse(**result)
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("request_share failed")
        raise HTTPException(500, "Internal server error")


@router.post("/send", response_model=EncryptedPayloadResponse)
async def send_encrypted_payload(
    body:     SendEncryptedPayloadRequest,
    request:  Request,
    current_user: dict         = Depends(get_current_user),
    relay_svc:   RelayService  = Depends(get_relay_service),
):
    """
    Owner sends encrypted payload to recipient.
    Payload is never stored — returned directly in this response.
    """
    try:
        result = await relay_svc.send_encrypted_payload(
            sender_id_hex=current_user["user_id_hex"],
            recipient_id_hex=body.recipient_id_hex,
            record_id=body.record_id,
            encrypted_payload=body.encrypted_payload,
            signature=body.signature,
            ip_address=request.client.host if request.client else "",
        )
        return EncryptedPayloadResponse(**result)
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(403, str(exc))
    except Exception:
        log.exception("send_encrypted_payload failed")
        raise HTTPException(500, "Internal server error")


@router.post("/reject", response_model=MessageResponse)
async def reject_share_request(
    body:     RejectShareRequest,
    request:  Request,
    current_user: dict         = Depends(get_current_user),
    relay_svc:   RelayService  = Depends(get_relay_service),
):
    """Owner rejects a pending share request."""
    try:
        await relay_svc.reject_share_request(
            owner_id_hex=current_user["user_id_hex"],
            share_id=body.share_id,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="Share request rejected.")
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(403, str(exc))
    except Exception:
        log.exception("reject_share_request failed")
        raise HTTPException(500, "Internal server error")


@router.get("/pending", response_model=PendingRequestsResponse)
async def get_pending_requests(
    current_user: dict         = Depends(get_current_user),
    relay_svc:   RelayService  = Depends(get_relay_service),
):
    """Get pending share requests addressed to the authenticated user."""
    try:
        requests = await relay_svc.get_pending_requests(current_user["user_id_hex"])
        return PendingRequestsResponse(requests=requests)
    except Exception:
        log.exception("get_pending_requests failed")
        raise HTTPException(500, "Internal server error")


@router.get("/notifications", response_model=NotificationResponse)
async def fetch_notifications(
    current_user: dict         = Depends(get_current_user),
    relay_svc:   RelayService  = Depends(get_relay_service),
):
    """Poll for pending payload-ready notifications."""
    try:
        notifications = await relay_svc.fetch_notifications(current_user["user_id_hex"])
        return NotificationResponse(notifications=notifications)
    except Exception:
        log.exception("fetch_notifications failed")
        raise HTTPException(500, "Internal server error")


# ─────────────────────────────────────────────────────────────────────────────
# Legacy direct-share endpoints (migrated from old routes/shares.py)
# These talk through DatabaseRepository — no raw SQL
# ─────────────────────────────────────────────────────────────────────────────

@router.post("", response_model=ShareDetail)
async def create_share(
    body:     CreateShareRequest,
    request:  Request,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """Create a direct encrypted share (ciphertext stored in DB)."""
    try:
        grantee = await db_repo.get_user_by_id_hex(body.grantee_user_id_hex)
        if not grantee:
            raise HTTPException(404, "Grantee user not found.")

        ciphertext_bytes = base64.urlsafe_b64decode(body.ciphertext_b64 + "==")
        expires_at       = _now() + timedelta(hours=body.expires_hours)

        share = await db_repo.create_share(
            owner_user_id_hex=current_user["user_id_hex"],
            grantee_user_id_hex=body.grantee_user_id_hex,
            ciphertext=ciphertext_bytes,
            dek_bundle=body.dek_bundle,
            nonce=body.nonce,
            filename=body.filename,
            size_bytes=body.size_bytes,
            signature=body.signature,
            expires_at=expires_at,
            mime_type=body.mime_type,
            file_hash=body.file_hash,
            payload_canon=body.payload_canon,
            delete_on_download=body.delete_on_download,
        )
        share_id = str(share["share_id"])

        await db_repo.append_audit_log(
            action="share_create",
            actor_user_id_hex=current_user["user_id_hex"],
            share_id=share["share_id"],
            ip_address=request.client.host if request.client else "",
            detail={"filename": body.filename},
        )

        return ShareDetail(
            share_id=share_id,
            short_code=share.get("short_code"),
            filename=body.filename,
            mime_type=body.mime_type,
            size_bytes=body.size_bytes,
            owner_username=current_user["username"],
            grantee_username=grantee.get("username"),
            created_at=share.get("created_at"),
            expires_at=share.get("expires_at"),
            delete_on_download=body.delete_on_download,
            status="active",
            permission_level=body.permission_level,
            dek_bundle=body.dek_bundle,
            nonce=body.nonce,
            signature=body.signature,
            ciphertext_url=f"/api/shares/{share_id}/ciphertext",
        )
    except HTTPException:
        raise
    except Exception:
        log.exception("create_share failed")
        raise HTTPException(500, "Internal server error")


@router.get("/sent", response_model=list[ShareSummary])
async def list_sent_shares(
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """List shares created by the authenticated user."""
    try:
        shares = await db_repo.get_shares_by_owner(
            owner_user_id_hex=current_user["user_id_hex"], limit=100
        )
        return [ShareSummary(share_id=str(s["share_id"]), **{
            k: v for k, v in s.items() if k != "share_id"
        }) for s in shares]
    except Exception:
        log.exception("list_sent_shares failed")
        raise HTTPException(500, "Internal server error")


@router.get("/received", response_model=list[ShareSummary])
async def list_received_shares(
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """List active shares received by the authenticated user."""
    try:
        shares = await db_repo.get_shares_by_grantee(
            grantee_user_id_hex=current_user["user_id_hex"],
            status="active", limit=100
        )
        return [ShareSummary(share_id=str(s["share_id"]), **{
            k: v for k, v in s.items() if k != "share_id"
        }) for s in shares]
    except Exception:
        log.exception("list_received_shares failed")
        raise HTTPException(500, "Internal server error")


@router.get("/code/{code}")
async def resolve_short_code(
    code:     str,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """Resolve a short alphanumeric code to a share_id."""
    try:
        share = await db_repo.get_share_by_short_code(code)
        if not share or share.get("status") != "active":
            raise HTTPException(404, "Share not found or expired.")
        return {"share_id": str(share["share_id"])}
    except HTTPException:
        raise
    except Exception:
        log.exception("resolve_short_code failed")
        raise HTTPException(500, "Internal server error")


@router.get("/{share_id}", response_model=ShareDetail)
async def get_share(
    share_id: str,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """Get share detail. Only accessible by owner or grantee."""
    try:
        from uuid import UUID
        share = await db_repo.get_share_by_id(UUID(share_id))
        if not share:
            raise HTTPException(404, "Share not found.")
        uid = current_user["user_id_hex"]
        if share.get("owner_user_id_hex") != uid and share.get("grantee_user_id_hex") != uid:
            raise HTTPException(403, "Access denied.")
        if share.get("status") not in ("active",):
            raise HTTPException(410, f"Share is {share.get('status')}.")
        return ShareDetail(
            share_id=share_id,
            short_code=share.get("short_code"),
            filename=share.get("filename", ""),
            mime_type=share.get("mime_type"),
            size_bytes=share.get("size_bytes"),
            created_at=share.get("created_at"),
            expires_at=share.get("expires_at"),
            delete_on_download=bool(share.get("delete_on_download")),
            status=share.get("status", "active"),
            permission_level=share.get("permission_level", "view_only"),
            dek_bundle=share.get("dek_bundle"),
            nonce=share.get("nonce"),
            signature=share.get("signature"),
            ciphertext_url=f"/api/shares/{share_id}/ciphertext",
        )
    except HTTPException:
        raise
    except Exception:
        log.exception("get_share failed")
        raise HTTPException(500, "Internal server error")


@router.get("/{share_id}/ciphertext")
async def get_ciphertext(
    share_id: str,
    request:  Request,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """Stream the encrypted ciphertext for a share."""
    try:
        from uuid import UUID
        share = await db_repo.get_share_by_id(UUID(share_id))
        if not share:
            raise HTTPException(404, "Share not found.")
        uid = current_user["user_id_hex"]
        if share.get("owner_user_id_hex") != uid and share.get("grantee_user_id_hex") != uid:
            raise HTTPException(403, "Access denied.")
        if share.get("status") not in ("active",):
            raise HTTPException(410, f"Share is {share.get('status')}.")

        ciphertext: bytes = share.get("ciphertext", b"")

        if share.get("grantee_user_id_hex") == uid:
            if share.get("delete_on_download"):
                await db_repo.update_share_status(UUID(share_id), "retrieved")
            else:
                await db_repo.mark_share_retrieved(UUID(share_id))
            await db_repo.append_audit_log(
                action="share_retrieve",
                actor_user_id_hex=uid,
                share_id=UUID(share_id),
                ip_address=request.client.host if request.client else "",
            )

        filename = share.get("filename", "file")
        return StreamingResponse(
            io.BytesIO(ciphertext),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}.enc"',
                "Content-Length": str(len(ciphertext)),
                "X-Mime-Type": share.get("mime_type", "application/octet-stream"),
            },
        )
    except HTTPException:
        raise
    except Exception:
        log.exception("get_ciphertext failed")
        raise HTTPException(500, "Internal server error")


@router.delete("/{share_id}", response_model=MessageResponse)
async def revoke_share(
    share_id: str,
    request:  Request,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """Revoke a share. Only the owner may revoke."""
    try:
        from uuid import UUID
        share = await db_repo.get_share_by_id(UUID(share_id))
        if not share or share.get("owner_user_id_hex") != current_user["user_id_hex"]:
            raise HTTPException(404, "Share not found or not owned by you.")
        await db_repo.update_share_status(UUID(share_id), "revoked")
        await db_repo.append_audit_log(
            action="share_revoke",
            actor_user_id_hex=current_user["user_id_hex"],
            share_id=UUID(share_id),
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="Share revoked.")
    except HTTPException:
        raise
    except Exception:
        log.exception("revoke_share failed")
        raise HTTPException(500, "Internal server error")


@router.get("/users/search")
async def search_users(
    q:        str,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """Search users by username prefix (for share recipient lookup)."""
    if len(q) < 2:
        raise HTTPException(400, "Query must be at least 2 characters.")
    try:
        users = await db_repo.list_users(active_only=True, limit=10)
        matches = [
            {
                "username":            u["username"],
                "user_id_hex":         u["user_id_hex"],
                "signing_public_key":  u.get("signing_public_key"),
                "exchange_public_key": u.get("exchange_public_key"),
            }
            for u in users
            if u["username"].lower().startswith(q.lower())
            and u["user_id_hex"] != current_user["user_id_hex"]
        ]
        return matches
    except Exception:
        log.exception("search_users failed")
        raise HTTPException(500, "Internal server error")
