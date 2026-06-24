"""
routes/keys.py — Public key endpoints.

All protected — JWT required.

GET  /keys/my                      → own public keys
GET  /keys/{user_id_hex}           → both keys for a user
GET  /keys/{user_id_hex}/exchange  → X25519 exchange key
GET  /keys/{user_id_hex}/signing   → Ed25519 signing key
PUT  /keys/update                  → update own keys
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from database.exceptions import RecordNotFoundError
from models.schemas import (
    ExchangeKeyResponse, PublicKeysResponse,
    SigningKeyResponse, UpdateKeysRequest, MessageResponse,
)
from services.key_service import KeyService

from .deps import get_current_user, get_key_service

log = logging.getLogger(__name__)
router = APIRouter(prefix="/keys", tags=["keys"])


@router.get("/my", response_model=PublicKeysResponse)
async def get_my_keys(
    current_user: dict    = Depends(get_current_user),
    key_svc:     KeyService = Depends(get_key_service),
):
    """Return own public keys. No audit event — not a sensitive lookup."""
    try:
        result = await key_svc.get_my_keys(current_user["user_id_hex"])
        return PublicKeysResponse(**result)
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except Exception:
        log.exception("get_my_keys failed")
        raise HTTPException(500, "Internal server error")


@router.get("/{user_id_hex}", response_model=PublicKeysResponse)
async def get_public_keys(
    user_id_hex: str,
    request:     Request,
    current_user: dict    = Depends(get_current_user),
    key_svc:     KeyService = Depends(get_key_service),
):
    """Get both public keys for another user. Logged as a key access event."""
    try:
        result = await key_svc.get_public_keys(
            user_id_hex=user_id_hex,
            requester_id_hex=current_user["user_id_hex"],
            ip_address=request.client.host if request.client else "",
        )
        return PublicKeysResponse(**result)
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except Exception:
        log.exception("get_public_keys failed")
        raise HTTPException(500, "Internal server error")


@router.get("/{user_id_hex}/exchange", response_model=ExchangeKeyResponse)
async def get_exchange_key(
    user_id_hex: str,
    request:     Request,
    current_user: dict    = Depends(get_current_user),
    key_svc:     KeyService = Depends(get_key_service),
):
    """Get the X25519 exchange key for a user (to encrypt data for them)."""
    try:
        result = await key_svc.get_exchange_key(
            user_id_hex=user_id_hex,
            requester_id_hex=current_user["user_id_hex"],
            ip_address=request.client.host if request.client else "",
        )
        return ExchangeKeyResponse(**result)
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except Exception:
        log.exception("get_exchange_key failed")
        raise HTTPException(500, "Internal server error")


@router.get("/{user_id_hex}/signing", response_model=SigningKeyResponse)
async def get_signing_key(
    user_id_hex: str,
    request:     Request,
    current_user: dict    = Depends(get_current_user),
    key_svc:     KeyService = Depends(get_key_service),
):
    """Get the Ed25519 signing key for a user (to verify their signatures)."""
    try:
        result = await key_svc.get_signing_key(
            user_id_hex=user_id_hex,
            requester_id_hex=current_user["user_id_hex"],
            ip_address=request.client.host if request.client else "",
        )
        return SigningKeyResponse(**result)
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except Exception:
        log.exception("get_signing_key failed")
        raise HTTPException(500, "Internal server error")


@router.put("/update", response_model=MessageResponse)
async def update_keys(
    body:    UpdateKeysRequest,
    request: Request,
    current_user: dict    = Depends(get_current_user),
    key_svc:     KeyService = Depends(get_key_service),
):
    """Update own signing and/or exchange public keys."""
    try:
        await key_svc.update_keys(
            user_id_hex=current_user["user_id_hex"],
            ip_address=request.client.host if request.client else "",
            signing_public_key=body.signing_public_key,
            exchange_public_key=body.exchange_public_key,
        )
        return MessageResponse(message="Public keys updated.")
    except RecordNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        log.exception("update_keys failed")
        raise HTTPException(500, "Internal server error")
