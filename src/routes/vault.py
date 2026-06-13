"""
src/routes/vault.py
Vault (encrypted file store) routes:
  POST   /api/vault/records        — upload a new encrypted record
  GET    /api/vault/records        — list my records
  GET    /api/vault/records/:id    — get record metadata
  GET    /api/vault/records/:id/ciphertext — stream ciphertext
  DELETE /api/vault/records/:id    — delete record
  POST   /api/vault/grants         — create a grant on a record
  GET    /api/vault/grants/:record_id — list grants for a record
  DELETE /api/vault/grants/:grant_id  — revoke a grant
"""
import logging
import base64
import secrets
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
import io

from src.services.database import DB
from src.middleware.auth_middleware import get_current_user, CurrentUser
from src.models.schemas import (
    CreateVaultRecordRequest, VaultRecordMeta, GrantRequest,
)

logger = logging.getLogger("medledger.vault")
router = APIRouter()


# ── Upload record ─────────────────────────────────────────────────────────────

@router.post("/vault/records", response_model=VaultRecordMeta)
async def upload_record(
    body: CreateVaultRecordRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        # Owner must have a public_key_hash to satisfy vault_records FK
        owner = await conn.fetchrow(
            "SELECT public_key_hash, user_id_hex FROM users WHERE user_id_hex = $1",
            current_user.user_id_hex,
        )
        if not owner or not owner["public_key_hash"]:
            raise HTTPException(400, "Upload public keys before storing vault records")

        ciphertext_bytes = base64.urlsafe_b64decode(body.ciphertext_b64 + "==")

        import json
        row = await conn.fetchrow(
            """
            INSERT INTO vault_records (
                record_id, owner_key_hash, owner_user_id_hex,
                owner_public_key_hex, filename, mime_type,
                size_bytes, iv_hex, tags
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
            RETURNING record_id, filename, mime_type, size_bytes, iv_hex, tags, created_at
            """,
            body.record_id,
            owner["public_key_hash"],
            current_user.user_id_hex,
            "",  # owner_public_key_hex — filled from keys later
            body.filename,
            body.mime_type,
            body.size_bytes,
            body.iv_hex,
            json.dumps(body.tags),
        )

        await conn.execute(
            """
            INSERT INTO vault_ciphertext (record_id, ciphertext, dek_bundle)
            VALUES ($1, $2, $3::jsonb)
            """,
            body.record_id,
            ciphertext_bytes,
            json.dumps(body.dek_bundle),
        )

    import json as _json
    tags = row["tags"] if isinstance(row["tags"], list) else _json.loads(row["tags"])
    return VaultRecordMeta(
        record_id=row["record_id"],
        filename=row["filename"],
        mime_type=row["mime_type"],
        size_bytes=row["size_bytes"],
        iv_hex=row["iv_hex"],
        tags=tags,
        created_at=row["created_at"],
    )


# ── List records ──────────────────────────────────────────────────────────────

@router.get("/vault/records", response_model=list[VaultRecordMeta])
async def list_records(current_user: CurrentUser = Depends(get_current_user)):
    async with DB() as conn:
        rows = await conn.fetch(
            """
            SELECT record_id, filename, mime_type, size_bytes, iv_hex, tags, created_at
            FROM vault_records
            WHERE owner_user_id_hex = $1
            ORDER BY created_at DESC
            LIMIT 200
            """,
            current_user.user_id_hex,
        )
    import json
    return [
        VaultRecordMeta(
            record_id=r["record_id"],
            filename=r["filename"],
            mime_type=r["mime_type"],
            size_bytes=r["size_bytes"],
            iv_hex=r["iv_hex"],
            tags=r["tags"] if isinstance(r["tags"], list) else json.loads(r["tags"]),
            created_at=r["created_at"],
        )
        for r in rows
    ]


# ── Get record metadata ───────────────────────────────────────────────────────

@router.get("/vault/records/{record_id}", response_model=VaultRecordMeta)
async def get_record(
    record_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        row = await conn.fetchrow(
            """
            SELECT record_id, filename, mime_type, size_bytes, iv_hex, tags, created_at
            FROM vault_records
            WHERE record_id = $1 AND owner_user_id_hex = $2
            """,
            record_id, current_user.user_id_hex,
        )
    if not row:
        raise HTTPException(404, "Record not found")
    import json
    return VaultRecordMeta(
        record_id=row["record_id"],
        filename=row["filename"],
        mime_type=row["mime_type"],
        size_bytes=row["size_bytes"],
        iv_hex=row["iv_hex"],
        tags=row["tags"] if isinstance(row["tags"], list) else json.loads(row["tags"]),
        created_at=row["created_at"],
    )


# ── Stream ciphertext ─────────────────────────────────────────────────────────

@router.get("/vault/records/{record_id}/ciphertext")
async def get_record_ciphertext(
    record_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        row = await conn.fetchrow(
            """
            SELECT vc.ciphertext, vr.filename, vr.mime_type, vr.owner_user_id_hex,
                   vc.dek_bundle
            FROM vault_ciphertext vc
            JOIN vault_records vr ON vc.record_id = vr.record_id
            WHERE vc.record_id = $1
            """,
            record_id,
        )
    if not row:
        raise HTTPException(404, "Record not found")

    # Only owner or active grantee may download
    if row["owner_user_id_hex"] != current_user.user_id_hex:
        async with DB() as conn:
            grant = await conn.fetchrow(
                """
                SELECT 1 FROM grants
                WHERE record_id = $1 AND grantee_user_id_hex = $2
                  AND revoked = FALSE
                  AND time_start <= NOW() AND time_end >= NOW()
                """,
                record_id, current_user.user_id_hex,
            )
        if not grant:
            raise HTTPException(403, "Access denied")

    ciphertext: bytes = row["ciphertext"]
    return StreamingResponse(
        io.BytesIO(ciphertext),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{row["filename"]}.enc"',
            "Content-Length": str(len(ciphertext)),
        },
    )


# ── Delete record ─────────────────────────────────────────────────────────────

@router.delete("/vault/records/{record_id}")
async def delete_record(
    record_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        result = await conn.execute(
            "DELETE FROM vault_records WHERE record_id = $1 AND owner_user_id_hex = $2",
            record_id, current_user.user_id_hex,
        )
    if result == "DELETE 0":
        raise HTTPException(404, "Record not found")
    return {"message": "Record deleted"}


# ── Create grant ──────────────────────────────────────────────────────────────

@router.post("/vault/grants")
async def create_grant(
    body: GrantRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    import json
    grant_id = secrets.token_hex(16)
    async with DB() as conn:
        # Verify ownership
        owner = await conn.fetchrow(
            "SELECT public_key_hash FROM vault_records WHERE record_id = $1 AND owner_user_id_hex = $2",
            body.record_id, current_user.user_id_hex,
        )
        if not owner:
            raise HTTPException(404, "Record not found or not owned by you")

        await conn.execute(
            """
            INSERT INTO grants (
                grant_id, record_id,
                grantor_key_hash, grantee_key_hash,
                grantee_user_id_hex, grantee_public_key_hex,
                permission_level, time_start, time_end,
                dek_bundle_grantee, signature_hex
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)
            """,
            grant_id, body.record_id,
            owner["public_key_hash"], body.grantee_key_hash if hasattr(body, "grantee_key_hash") else "",
            body.grantee_user_id_hex, body.grantee_public_key_hex,
            body.permission_level, body.time_start, body.time_end,
            json.dumps(body.dek_bundle_grantee), body.signature_hex,
        )
    return {"grant_id": grant_id, "message": "Grant created"}


# ── List grants for a record ──────────────────────────────────────────────────

@router.get("/vault/grants/{record_id}")
async def list_grants(
    record_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        rows = await conn.fetch(
            """
            SELECT g.grant_id, g.grantee_user_id_hex, u.username as grantee_username,
                   g.permission_level, g.time_start, g.time_end, g.revoked, g.created_at
            FROM grants g
            LEFT JOIN users u ON g.grantee_user_id_hex = u.user_id_hex
            WHERE g.record_id = $1 AND g.revoked = FALSE
            ORDER BY g.created_at DESC
            """,
            record_id,
        )
    # Verify caller owns the record
    async with DB() as conn:
        owner = await conn.fetchval(
            "SELECT 1 FROM vault_records WHERE record_id = $1 AND owner_user_id_hex = $2",
            record_id, current_user.user_id_hex,
        )
    if not owner:
        raise HTTPException(403, "Access denied")
    return [dict(r) for r in rows]


# ── Revoke grant ──────────────────────────────────────────────────────────────

@router.delete("/vault/grants/{grant_id}")
async def revoke_grant(
    grant_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        result = await conn.execute(
            """
            UPDATE grants SET revoked = TRUE, revoked_at = NOW()
            WHERE grant_id = $1
              AND record_id IN (
                SELECT record_id FROM vault_records WHERE owner_user_id_hex = $2
              )
              AND revoked = FALSE
            """,
            grant_id, current_user.user_id_hex,
        )
    if result == "UPDATE 0":
        raise HTTPException(404, "Grant not found or already revoked")
    return {"message": "Grant revoked"}
