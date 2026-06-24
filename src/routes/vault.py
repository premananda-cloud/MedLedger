"""
routes/vault.py — Vault (encrypted record store) endpoints.

All protected — JWT required.

POST   /vault/records                  → upload encrypted record
GET    /vault/records                  → list own records
GET    /vault/records/{record_id}      → get record metadata
GET    /vault/records/{record_id}/ciphertext → stream ciphertext
DELETE /vault/records/{record_id}      → delete record
"""
from __future__ import annotations

import io
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from database import DatabaseRepository
from database.exceptions import RecordNotFoundError
from models.schemas import (
    CreateVaultRecordRequest, VaultRecordListResponse,
    VaultRecordMeta, VaultRecordResponse, MessageResponse,
)
from services.audit_service import AuditService

from .deps import get_audit_service, get_current_user, get_db_repo

log = logging.getLogger(__name__)
router = APIRouter(prefix="/vault", tags=["vault"])


def _to_response(row: dict) -> VaultRecordResponse:
    return VaultRecordResponse(
        record_id=row["record_id"],
        owner_user_id_hex=row.get("owner_user_id_hex"),
        filename=row["filename"],
        mime_type=row["mime_type"],
        size_bytes=row["size_bytes"],
        iv_hex=row.get("iv_hex"),
        tags=row.get("tags") or [],
        created_at=str(row["created_at"]) if row.get("created_at") else None,
        updated_at=str(row.get("updated_at")) if row.get("updated_at") else None,
    )


@router.post("/records", response_model=VaultRecordMeta, status_code=201)
async def upload_record(
    body:     CreateVaultRecordRequest,
    request:  Request,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
    audit:       AuditService       = Depends(get_audit_service),
):
    """Upload a new encrypted record. Ciphertext is stored server-side."""
    try:
        # Verify the user has public keys before storing vault records
        user = await db_repo.get_user_by_id_hex(current_user["user_id_hex"])
        if not user or not user.get("signing_public_key"):
            raise HTTPException(400, "Upload public keys before storing vault records.")

        record = await db_repo.create_vault_record(
            record_id=body.record_id,
            owner_key_hash=body.owner_key_hash,
            owner_user_id_hex=current_user["user_id_hex"],
            owner_public_key_hex=body.owner_public_key_hex,
            filename=body.filename,
            mime_type=body.mime_type,
            size_bytes=body.size_bytes,
            iv_hex=body.iv_hex,
            tags=body.tags,
        )

        ciphertext_bytes = bytes.fromhex(body.ciphertext)
        await db_repo.create_vault_ciphertext(
            record_id=body.record_id,
            ciphertext=ciphertext_bytes,
            dek_bundle=body.dek_bundle,
        )

        await audit.log_vault_event(
            "record_created",
            actor_user_id_hex=current_user["user_id_hex"],
            record_id=body.record_id,
            ip_address=request.client.host if request.client else "",
            detail={"filename": body.filename, "size_bytes": body.size_bytes},
        )

        return VaultRecordMeta(
            record_id=record["record_id"],
            filename=record["filename"],
            mime_type=record["mime_type"],
            size_bytes=record["size_bytes"],
            iv_hex=record.get("iv_hex", ""),
            tags=record.get("tags") or [],
            created_at=record.get("created_at"),
        )
    except HTTPException:
        raise
    except Exception:
        log.exception("upload_record failed")
        raise HTTPException(500, "Internal server error")


@router.get("/records", response_model=list[VaultRecordMeta])
async def list_records(
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """List all vault records owned by the authenticated user."""
    try:
        records = await db_repo.list_vault_records(
            owner_user_id_hex=current_user["user_id_hex"], limit=200
        )
        return [VaultRecordMeta(
            record_id=r["record_id"],
            filename=r["filename"],
            mime_type=r["mime_type"],
            size_bytes=r["size_bytes"],
            iv_hex=r.get("iv_hex", ""),
            tags=r.get("tags") or [],
            created_at=r.get("created_at"),
        ) for r in records]
    except Exception:
        log.exception("list_records failed")
        raise HTTPException(500, "Internal server error")


@router.get("/records/{record_id}", response_model=VaultRecordMeta)
async def get_record(
    record_id: str,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """Get vault record metadata."""
    try:
        record = await db_repo.get_vault_record(record_id)
        if not record:
            raise HTTPException(404, "Record not found.")
        if record.get("owner_user_id_hex") != current_user["user_id_hex"]:
            raise HTTPException(403, "Access denied.")
        return VaultRecordMeta(
            record_id=record["record_id"],
            filename=record["filename"],
            mime_type=record["mime_type"],
            size_bytes=record["size_bytes"],
            iv_hex=record.get("iv_hex", ""),
            tags=record.get("tags") or [],
            created_at=record.get("created_at"),
        )
    except HTTPException:
        raise
    except Exception:
        log.exception("get_record failed")
        raise HTTPException(500, "Internal server error")


@router.get("/records/{record_id}/ciphertext")
async def get_record_ciphertext(
    record_id: str,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
):
    """Stream encrypted ciphertext. Only owner or active grantee may download."""
    try:
        ct_row = await db_repo.get_vault_ciphertext(record_id)
        record = await db_repo.get_vault_record(record_id)
        if not ct_row or not record:
            raise HTTPException(404, "Record not found.")

        uid = current_user["user_id_hex"]
        is_owner = record.get("owner_user_id_hex") == uid

        if not is_owner:
            # Check for active grant
            grants = await db_repo.get_grants_for_record(record_id, active_only=True)
            has_grant = any(g.get("grantee_user_id_hex") == uid for g in grants)
            if not has_grant:
                raise HTTPException(403, "Access denied.")

        ciphertext: bytes = ct_row["ciphertext"]
        return StreamingResponse(
            io.BytesIO(ciphertext),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{record["filename"]}.enc"',
                "Content-Length": str(len(ciphertext)),
            },
        )
    except HTTPException:
        raise
    except Exception:
        log.exception("get_record_ciphertext failed")
        raise HTTPException(500, "Internal server error")


@router.delete("/records/{record_id}", response_model=MessageResponse)
async def delete_record(
    record_id: str,
    request:   Request,
    current_user: dict              = Depends(get_current_user),
    db_repo:     DatabaseRepository = Depends(get_db_repo),
    audit:       AuditService       = Depends(get_audit_service),
):
    """Delete a vault record and its ciphertext (CASCADE)."""
    try:
        record = await db_repo.get_vault_record(record_id)
        if not record or record.get("owner_user_id_hex") != current_user["user_id_hex"]:
            raise HTTPException(404, "Record not found.")

        await db_repo.delete_vault_record(record_id)
        await audit.log_vault_event(
            "record_deleted",
            actor_user_id_hex=current_user["user_id_hex"],
            record_id=record_id,
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="Record deleted.")
    except HTTPException:
        raise
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except Exception:
        log.exception("delete_record failed")
        raise HTTPException(500, "Internal server error")
