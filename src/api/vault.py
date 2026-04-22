"""
Vault API Router
Location: src/api/vault.py

Endpoints
─────────
POST   /api/vault/upload            Upload + encrypt a file
GET    /api/vault/download/{id}     Download + decrypt a file
POST   /api/vault/grant             Grant access to a record
POST   /api/vault/revoke            Revoke a grant
GET    /api/vault/records           List caller's own records
GET    /api/vault/permissions       Grants caller issued (outbox)
GET    /api/vault/inbox             Grants caller received
POST   /api/vault/rotate-key        Re-wrap all DEKs under a new keypair

Auth: every endpoint requires Bearer JWT (issued by /api/auth/login).
The private key is NEVER sent to the server on read paths; the caller
must supply it in the request body for operations that need it
(upload, download, grant, rotate-key).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import Response
from pydantic import BaseModel

from src.services.transceiver import (
    Transceiver,
    VaultError, AccessDenied, RecordNotFound, GrantNotFound,
    ExpiredGrant, RevokedGrant,
)
from src.database import get_vault_store
from src.services.config import cfg
from src.api.deps import require_auth, CallerIdentity

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vault", tags=["vault"])

# Singleton transceiver — store backend is chosen by config.json db_backend
_transceiver = Transceiver(get_vault_store())


# ── Request / Response schemas ────────────────────────────────────────────────

class UploadRequest(BaseModel):
    private_key_pem: str
    filename: str
    plaintext_hex: str          # file bytes as hex — avoids multipart for simplicity
    tags: list[str] = []


class DownloadRequest(BaseModel):
    private_key_pem: str


class GrantRequest(BaseModel):
    private_key_pem: str
    record_id: str
    grantee_public_key_hex: str
    permission_level: str = "view_only"     # "view_only" | "view_download"
    duration_hours: float = 24.0


class RevokeRequest(BaseModel):
    private_key_pem: str
    grant_id: str


class RotateKeyRequest(BaseModel):
    old_private_key_pem: str
    new_private_key_pem: str
    new_public_key_hex: str


class PermissionsQuery(BaseModel):
    private_key_pem: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _vault_error_to_http(exc: VaultError) -> HTTPException:
    if isinstance(exc, (AccessDenied, RevokedGrant)):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, (RecordNotFound, GrantNotFound)):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ExpiredGrant):
        return HTTPException(status_code=410, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/upload", status_code=201)
async def upload(body: UploadRequest, caller: CallerIdentity = Depends(require_auth)):
    """
    Encrypt and store a file.
    Returns the record_id — save it to download later.

    plaintext_hex: hex-encoded raw file bytes
    """
    try:
        plaintext = bytes.fromhex(body.plaintext_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="plaintext_hex must be valid hex")
    try:
        result = _transceiver.upload(
            caller_private_key_pem=body.private_key_pem,
            plaintext=plaintext,
            filename=body.filename,
            tags=body.tags,
        )
        return result.to_dict()
    except VaultError as e:
        raise _vault_error_to_http(e)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/download/{record_id}")
async def download(
    record_id: str,
    body: DownloadRequest,
    caller: CallerIdentity = Depends(require_auth),
):
    """
    Decrypt and return a file as hex-encoded bytes.
    Caller must supply their private key; it is used locally, never stored.
    """
    try:
        result = _transceiver.download(
            caller_private_key_pem=body.private_key_pem,
            record_id=record_id,
        )
        return {
            "record_id":   result.record_id,
            "filename":    result.filename,
            "mime_type":   result.mime_type,
            "size_bytes":  result.size_bytes,
            "plaintext_hex": result.plaintext.hex(),
        }
    except VaultError as e:
        raise _vault_error_to_http(e)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/records")
async def list_records(caller: CallerIdentity = Depends(require_auth)):
    """
    List all records owned by the caller (metadata only, no ciphertext).
    """
    store = get_vault_store()
    records = store.list_records_by_owner(caller.public_key_hash)
    return [r.to_dict() for r in records]


@router.post("/grant", status_code=201)
async def grant(body: GrantRequest, caller: CallerIdentity = Depends(require_auth)):
    """
    Grant a grantee time-limited access to a record.
    The DEK is re-encrypted under the grantee's public key; the owner signs
    the permission payload with their private key.
    """
    try:
        result = _transceiver.grant(
            owner_private_key_pem=body.private_key_pem,
            record_id=body.record_id,
            grantee_public_key_hex=body.grantee_public_key_hex,
            permission_level=body.permission_level,
            duration_hours=body.duration_hours,
        )
        return result.to_dict()
    except VaultError as e:
        raise _vault_error_to_http(e)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/revoke")
async def revoke(body: RevokeRequest, caller: CallerIdentity = Depends(require_auth)):
    """
    Revoke a grant immediately. Only the record owner can revoke.
    """
    try:
        return _transceiver.revoke(
            owner_private_key_pem=body.private_key_pem,
            grant_id=body.grant_id,
        )
    except VaultError as e:
        raise _vault_error_to_http(e)


@router.post("/permissions")
async def permissions(body: PermissionsQuery, caller: CallerIdentity = Depends(require_auth)):
    """Grants the caller has issued (outbox — what they gave away)."""
    try:
        result = _transceiver.permissions(body.private_key_pem, as_owner=True)
        return [p.to_dict() for p in result]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/inbox")
async def inbox(body: PermissionsQuery, caller: CallerIdentity = Depends(require_auth)):
    """Grants the caller has received (inbox — what they can access)."""
    try:
        result = _transceiver.inbox(body.private_key_pem)
        return [p.to_dict() for p in result]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/rotate-key")
async def rotate_key(body: RotateKeyRequest, caller: CallerIdentity = Depends(require_auth)):
    """
    Replace caller's keypair.
    All owned DEKs are re-encrypted under the new key atomically.
    All existing grants are revoked (grantees must re-request access).
    """
    try:
        return _transceiver.rotate_key(
            old_private_key_pem=body.old_private_key_pem,
            new_public_key_hex=body.new_public_key_hex,
            new_private_key_pem=body.new_private_key_pem,
        )
    except VaultError as e:
        raise _vault_error_to_http(e)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
