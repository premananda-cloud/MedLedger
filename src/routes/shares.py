"""
src/routes/shares.py
Share management routes:
  POST   /api/shares              — create a share
  GET    /api/shares/sent         — shares I sent
  GET    /api/shares/received     — shares received by me
  GET    /api/shares/:share_id    — get share detail + dek_bundle + nonce
  GET    /api/shares/:share_id/ciphertext — stream encrypted ciphertext
  DELETE /api/shares/:share_id    — revoke / delete a share
  GET    /api/shares/code/:code   — resolve short code
"""
import logging
import base64
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends, Response, Request
from fastapi.responses import StreamingResponse
import io

from src.services.database import DB
from src.middleware.auth_middleware import get_current_user, CurrentUser
from src.models.schemas import (
    CreateShareRequest, ShareSummary, ShareDetail, RevokeShareRequest,
)

logger = logging.getLogger("medledger.shares")
router = APIRouter()


def _now():
    return datetime.now(timezone.utc)


# ── Create share ──────────────────────────────────────────────────────────────

@router.post("/shares", response_model=ShareDetail)
async def create_share(
    body: CreateShareRequest,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
):
    expires_at = _now() + timedelta(hours=body.expires_hours)

    # Decode base64url ciphertext to bytes for storage
    ciphertext_bytes = base64.urlsafe_b64decode(
        body.ciphertext_b64 + "=="  # padding tolerance
    )

    async with DB() as conn:
        # Resolve grantee
        grantee = await conn.fetchrow(
            "SELECT user_id_hex, username FROM users WHERE user_id_hex = $1 AND is_active = TRUE",
            body.grantee_user_id_hex,
        )
        if not grantee:
            raise HTTPException(404, "Grantee user not found")

        row = await conn.fetchrow(
            """
            INSERT INTO active_shares (
                owner_user_id_hex, grantee_user_id_hex,
                ciphertext, dek_bundle, nonce,
                filename, mime_type, size_bytes, file_hash,
                signature, payload_canon, expires_at,
                delete_on_download, permission_level
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            RETURNING share_id, short_code, created_at, expires_at
            """,
            current_user.user_id_hex,
            body.grantee_user_id_hex,
            ciphertext_bytes,
            body.dek_bundle,
            body.nonce,
            body.filename,
            body.mime_type,
            body.size_bytes,
            body.file_hash,
            body.signature,
            body.payload_canon,
            expires_at,
            body.delete_on_download,
            body.permission_level,
        )

        # Audit log
        await conn.execute(
            """INSERT INTO audit_log (actor_user_id_hex, action, share_id, detail, ip_address)
               VALUES ($1, 'share_create', $2, $3, $4)""",
            current_user.user_id_hex,
            row["share_id"],
            '{"filename": "' + body.filename + '"}',
            request.client.host if request.client else None,
        )

    share_id = str(row["share_id"])
    return ShareDetail(
        share_id=share_id,
        short_code=row["short_code"],
        filename=body.filename,
        mime_type=body.mime_type,
        size_bytes=body.size_bytes,
        owner_username=current_user.username,
        grantee_username=grantee["username"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        delete_on_download=body.delete_on_download,
        status="active",
        permission_level=body.permission_level,
        dek_bundle=body.dek_bundle,
        nonce=body.nonce,
        signature=body.signature,
        ciphertext_url=f"/api/shares/{share_id}/ciphertext",
    )


# ── List shares sent ──────────────────────────────────────────────────────────

@router.get("/shares/sent", response_model=list[ShareSummary])
async def list_sent_shares(current_user: CurrentUser = Depends(get_current_user)):
    async with DB() as conn:
        rows = await conn.fetch(
            """
            SELECT s.share_id, s.short_code, s.filename, s.mime_type, s.size_bytes,
                   u1.username as owner_username, u2.username as grantee_username,
                   s.created_at, s.expires_at, s.delete_on_download,
                   s.status, s.permission_level
            FROM active_shares s
            JOIN users u1 ON s.owner_user_id_hex = u1.user_id_hex
            JOIN users u2 ON s.grantee_user_id_hex = u2.user_id_hex
            WHERE s.owner_user_id_hex = $1
            ORDER BY s.created_at DESC
            LIMIT 100
            """,
            current_user.user_id_hex,
        )
    return [ShareSummary(**dict(r), share_id=str(r["share_id"])) for r in rows]


# ── List shares received ──────────────────────────────────────────────────────

@router.get("/shares/received", response_model=list[ShareSummary])
async def list_received_shares(current_user: CurrentUser = Depends(get_current_user)):
    async with DB() as conn:
        rows = await conn.fetch(
            """
            SELECT s.share_id, s.short_code, s.filename, s.mime_type, s.size_bytes,
                   u1.username as owner_username, u2.username as grantee_username,
                   s.created_at, s.expires_at, s.delete_on_download,
                   s.status, s.permission_level
            FROM active_shares s
            JOIN users u1 ON s.owner_user_id_hex = u1.user_id_hex
            JOIN users u2 ON s.grantee_user_id_hex = u2.user_id_hex
            WHERE s.grantee_user_id_hex = $1 AND s.status = 'active'
            ORDER BY s.created_at DESC
            LIMIT 100
            """,
            current_user.user_id_hex,
        )
    return [ShareSummary(**dict(r), share_id=str(r["share_id"])) for r in rows]


# ── Get share detail ──────────────────────────────────────────────────────────

@router.get("/shares/{share_id}", response_model=ShareDetail)
async def get_share(
    share_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        row = await conn.fetchrow(
            """
            SELECT s.share_id, s.short_code, s.filename, s.mime_type, s.size_bytes,
                   u1.username as owner_username, u2.username as grantee_username,
                   s.created_at, s.expires_at, s.delete_on_download,
                   s.status, s.permission_level,
                   s.dek_bundle, s.nonce, s.signature
            FROM active_shares s
            JOIN users u1 ON s.owner_user_id_hex = u1.user_id_hex
            JOIN users u2 ON s.grantee_user_id_hex = u2.user_id_hex
            WHERE s.share_id = $1::uuid
              AND (s.owner_user_id_hex = $2 OR s.grantee_user_id_hex = $2)
            """,
            share_id, current_user.user_id_hex,
        )
    if not row:
        raise HTTPException(404, "Share not found")
    if row["status"] not in ("active",):
        raise HTTPException(410, f"Share is {row['status']}")

    return ShareDetail(
        **{k: v for k, v in dict(row).items() if k != "share_id"},
        share_id=str(row["share_id"]),
        ciphertext_url=f"/api/shares/{share_id}/ciphertext",
    )


# ── Stream ciphertext ─────────────────────────────────────────────────────────

@router.get("/shares/{share_id}/ciphertext")
async def get_ciphertext(
    share_id: str,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        row = await conn.fetchrow(
            """
            SELECT s.ciphertext, s.filename, s.mime_type,
                   s.delete_on_download, s.status,
                   s.grantee_user_id_hex, s.owner_user_id_hex
            FROM active_shares s
            WHERE s.share_id = $1::uuid
              AND (s.owner_user_id_hex = $2 OR s.grantee_user_id_hex = $2)
            """,
            share_id, current_user.user_id_hex,
        )
    if not row:
        raise HTTPException(404, "Share not found")
    if row["status"] not in ("active",):
        raise HTTPException(410, f"Share is {row['status']}")

    ciphertext: bytes = row["ciphertext"]

    # Mark as retrieved for grantee downloads
    if row["grantee_user_id_hex"] == current_user.user_id_hex:
        async with DB() as conn:
            if row["delete_on_download"]:
                await conn.execute(
                    "UPDATE active_shares SET status = 'retrieved', retrieved_at = NOW() WHERE share_id = $1::uuid",
                    share_id,
                )
            else:
                await conn.execute(
                    "UPDATE active_shares SET retrieved_at = NOW() WHERE share_id = $1::uuid AND retrieved_at IS NULL",
                    share_id,
                )
            await conn.execute(
                """INSERT INTO audit_log (actor_user_id_hex, action, share_id, detail, ip_address)
                   VALUES ($1, 'share_retrieve', $2::uuid, '{}', $3)""",
                current_user.user_id_hex, share_id,
                request.client.host if request.client else None,
            )

    mime = row["mime_type"] or "application/octet-stream"
    filename = row["filename"]

    return StreamingResponse(
        io.BytesIO(ciphertext),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.enc"',
            "Content-Length": str(len(ciphertext)),
            "X-Mime-Type": mime,
        },
    )


# ── Revoke share ──────────────────────────────────────────────────────────────

@router.delete("/shares/{share_id}")
async def revoke_share(
    share_id: str,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        result = await conn.execute(
            """
            UPDATE active_shares
            SET status = 'revoked'
            WHERE share_id = $1::uuid AND owner_user_id_hex = $2 AND status = 'active'
            """,
            share_id, current_user.user_id_hex,
        )
        if result == "UPDATE 0":
            raise HTTPException(404, "Share not found or already revoked")

        await conn.execute(
            """INSERT INTO audit_log (actor_user_id_hex, action, share_id, detail, ip_address)
               VALUES ($1, 'share_revoke', $2::uuid, '{}', $3)""",
            current_user.user_id_hex, share_id,
            request.client.host if request.client else None,
        )
    return {"message": "Share revoked"}


# ── Resolve short code ────────────────────────────────────────────────────────

@router.get("/shares/code/{code}")
async def resolve_short_code(
    code: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    async with DB() as conn:
        row = await conn.fetchrow(
            "SELECT share_id FROM active_shares WHERE short_code = $1 AND status = 'active'",
            code,
        )
    if not row:
        raise HTTPException(404, "Share not found or expired")
    return {"share_id": str(row["share_id"])}


# ── Search users (for share recipient lookup) ─────────────────────────────────

@router.get("/users/search")
async def search_users(
    q: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    if len(q) < 2:
        raise HTTPException(400, "Query too short")
    async with DB() as conn:
        rows = await conn.fetch(
            """
            SELECT username, user_id_hex, signing_public_key, exchange_public_key
            FROM users
            WHERE lower(username) LIKE lower($1) || '%'
              AND is_active = TRUE AND account_deleted = FALSE
              AND user_id_hex != $2
            LIMIT 10
            """,
            q, current_user.user_id_hex,
        )
    return [dict(r) for r in rows]
