"""
routes/grants.py — Grant endpoints.

All protected — JWT required.

POST   /grants                      → create grant on a record
DELETE /grants/{grant_id}           → revoke grant
GET    /grants/{grant_id}           → get grant details (incl. DEK bundle)
GET    /grants/record/{record_id}   → list grants for a record
GET    /grants/my                   → list my grants (as grantor or grantee)
GET    /grants/check/{record_id}    → check if I have access to a record
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from database.exceptions import RecordNotFoundError
from models.schemas import (
    AccessCheckResponse, CreateGrantRequest,
    GrantDetailsResponse, GrantListResponse, GrantResponse, MessageResponse,
)
from services.grant_service import GrantService

from .deps import get_current_user, get_grant_service

log = logging.getLogger(__name__)
router = APIRouter(prefix="/grants", tags=["grants"])


def _grant_response(g: dict) -> GrantResponse:
    return GrantResponse(
        grant_id=g.get("grant_id", ""),
        record_id=g.get("record_id", ""),
        grantor_key_hash=g.get("grantor_key_hash"),
        grantee_key_hash=g.get("grantee_key_hash"),
        grantee_user_id_hex=g.get("grantee_user_id_hex"),
        permission_level=g.get("permission_level", "view_only"),
        time_start=str(g["time_start"]) if g.get("time_start") else None,
        time_end=str(g["time_end"]) if g.get("time_end") else None,
        revoked=bool(g.get("revoked")),
        created_at=str(g["created_at"]) if g.get("created_at") else None,
        retrieved_at=str(g["retrieved_at"]) if g.get("retrieved_at") else None,
    )


@router.post("", response_model=GrantResponse, status_code=201)
async def create_grant(
    body:     CreateGrantRequest,
    request:  Request,
    current_user: dict         = Depends(get_current_user),
    grant_svc:   GrantService  = Depends(get_grant_service),
):
    """Create a time-bounded access grant on a vault record."""
    try:
        time_start = datetime.fromisoformat(body.time_start).replace(tzinfo=timezone.utc)
        time_end   = datetime.fromisoformat(body.time_end).replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(400, "time_start and time_end must be ISO 8601 datetime strings.")

    try:
        grant = await grant_svc.create_grant(
            grantor_id_hex=current_user["user_id_hex"],
            grantee_id_hex=body.grantee_id_hex,
            record_id=body.record_id,
            permission_level=body.permission_level,
            time_start=time_start,
            time_end=time_end,
            dek_bundle_grantee=body.dek_bundle_grantee,
            signature_hex=body.signature_hex,
            ip_address=request.client.host if request.client else "",
        )
        return _grant_response(grant)
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("create_grant failed")
        raise HTTPException(500, "Internal server error")


@router.delete("/{grant_id}", response_model=MessageResponse)
async def revoke_grant(
    grant_id: str,
    request:  Request,
    current_user: dict         = Depends(get_current_user),
    grant_svc:   GrantService  = Depends(get_grant_service),
):
    """Revoke a grant. Only the grantor (record owner) may revoke."""
    try:
        await grant_svc.revoke_grant(
            grant_id=grant_id,
            revoker_id_hex=current_user["user_id_hex"],
            ip_address=request.client.host if request.client else "",
        )
        return MessageResponse(message="Grant revoked.")
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(403, str(exc))
    except Exception:
        log.exception("revoke_grant failed")
        raise HTTPException(500, "Internal server error")


@router.get("/my", response_model=GrantListResponse)
async def list_my_grants(
    as_grantor: bool         = Query(True, description="True = grants I created; False = grants I received"),
    current_user: dict       = Depends(get_current_user),
    grant_svc: GrantService  = Depends(get_grant_service),
):
    """List grants where the authenticated user is grantor or grantee."""
    try:
        grants = await grant_svc.list_my_grants(
            user_id_hex=current_user["user_id_hex"],
            as_grantor=as_grantor,
        )
        return GrantListResponse(grants=[_grant_response(g) for g in grants])
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except Exception:
        log.exception("list_my_grants failed")
        raise HTTPException(500, "Internal server error")


@router.get("/check/{record_id}", response_model=AccessCheckResponse)
async def check_access(
    record_id: str,
    current_user: dict       = Depends(get_current_user),
    grant_svc: GrantService  = Depends(get_grant_service),
):
    """Check whether the authenticated user has an active grant for a record."""
    try:
        result = await grant_svc.check_access(
            user_id_hex=current_user["user_id_hex"],
            record_id=record_id,
        )
        return AccessCheckResponse(
            has_access=result["has_access"],
            grant=_grant_response(result["grant"]) if result.get("grant") else None,
            permission_level=result.get("permission_level"),
        )
    except Exception:
        log.exception("check_access failed")
        raise HTTPException(500, "Internal server error")


@router.get("/record/{record_id}", response_model=GrantListResponse)
async def list_grants_for_record(
    record_id: str,
    current_user: dict       = Depends(get_current_user),
    grant_svc: GrantService  = Depends(get_grant_service),
):
    """List all grants on a record. Only callable by the record owner."""
    try:
        grants = await grant_svc.list_grants_for_record(
            record_id=record_id,
            owner_id_hex=current_user["user_id_hex"],
        )
        return GrantListResponse(grants=[_grant_response(g) for g in grants])
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(403, str(exc))
    except Exception:
        log.exception("list_grants_for_record failed")
        raise HTTPException(500, "Internal server error")


@router.get("/{grant_id}", response_model=GrantDetailsResponse)
async def get_grant_details(
    grant_id: str,
    current_user: dict       = Depends(get_current_user),
    grant_svc: GrantService  = Depends(get_grant_service),
):
    """
    Get full grant details including the DEK bundle.
    Only accessible by the grantor or grantee.
    """
    try:
        grant = await grant_svc.get_grant_details(
            grant_id=grant_id,
            user_id_hex=current_user["user_id_hex"],
        )
        base = _grant_response(grant)
        return GrantDetailsResponse(
            **base.model_dump(),
            dek_bundle_grantee=grant.get("dek_bundle_grantee"),
        )
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(403, str(exc))
    except Exception:
        log.exception("get_grant_details failed")
        raise HTTPException(500, "Internal server error")
