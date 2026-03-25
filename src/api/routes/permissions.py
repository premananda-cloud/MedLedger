"""
Permission Routes - FastAPI endpoints for access control
Location: src/api/routes/permissions.py

Security model (no private key ever sent to server):
  - The patient signs the permission payload CLIENT-SIDE (SubtleCrypto / local tool).
  - Only the resulting signature + the doctor_encrypted_dek are sent here.
  - The server stores the signature and verifies it on every doctor access.

Endpoints:
  POST /permissions/grant   – Patient grants access (JWT required)
  POST /permissions/verify  – Doctor verifies they can access (JWT required)
  POST /permissions/revoke  – Patient revokes access (JWT required)
  GET  /permissions/patient/{patient_id} – List permissions (JWT required)
  GET  /permissions/audit   – Audit log (JWT required)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List, Dict, Optional
import uuid

from src.services.permission_service import PermissionService, PermissionError
from src.api.routes.auth import get_current_user_id
from src.database.connection import get_db          # shared session — not a local one
from src.database.models import AccessPermission, AuditLog, User, UserRole
from pydantic import BaseModel, Field

# ──────────────────────────── Pydantic Schemas ────────────────────────────────

class GrantPermissionRequest(BaseModel):
    """
    Patient grants access to a doctor for a specific record.

    The private key NEVER leaves the patient's device.
    The frontend must:
      1. Build the canonical permission payload (same dict the server reconstructs).
      2. Sign it with SubtleCrypto / local key tool → signature_hex.
      3. ECIES-decrypt the record DEK with the patient's private key.
      4. ECIES-encrypt the DEK with the doctor's public key → doctor_encrypted_dek.
      5. POST this request.
    """
    doctor_id: str = Field(..., description="Integer user-id of the doctor (as string)")
    record_id: str = Field(..., description="Record ID being shared")
    time_window_hours: int = Field(2, ge=1, le=168, description="Access window in hours (1–168)")
    permission_level: str = Field("view_only", description="'view_only' or 'view_download'")
    # Client-signed timestamps — MUST match what was signed.  ISO-8601, no timezone suffix.
    valid_from: Optional[str] = Field(
        None,
        description="ISO-8601 UTC timestamp the patient signed as valid_from (no tz suffix). "
                    "If omitted the server falls back to utcnow().",
    )
    valid_until: Optional[str] = Field(
        None,
        description="ISO-8601 UTC timestamp the patient signed as valid_until (no tz suffix). "
                    "If omitted the server derives it from time_window_hours.",
    )
    # Client-side ECDSA signature over the canonical permission payload
    signature_hex: str = Field(
        ...,
        description=(
            "Hex-encoded ECDSA-P256 signature produced CLIENT-SIDE over the JSON payload:\n"
            '{"patient_id":"<id>","grantee_public_key_hash":"<hash>","record_id":"<id>",'
            '"valid_from":"<iso>","valid_until":"<iso>","permission_level":"<level>"}\n'
            "(keys sorted, no spaces)"
        ),
    )
    # DEK re-encrypted for the doctor (ECIES bundle, JSON-serialised)
    doctor_encrypted_dek: str = Field(
        ...,
        description=(
            "ECIES bundle: patient decrypts record DEK with their private key, "
            "then re-encrypts it with the doctor's public key. "
            "JSON string: {epk, iv, ct, tag}."
        ),
    )

    class Config:
        json_schema_extra = {
            "example": {
                "doctor_id": "5",
                "record_id": "a1b2c3d4e5f6...",
                "time_window_hours": 2,
                "permission_level": "view_only",
                "signature_hex": "3045022100abcdef...",
                "doctor_encrypted_dek": '{"epk":"04...","iv":"...","ct":"...","tag":"..."}',
            }
        }


class VerifyPermissionRequest(BaseModel):
    """Doctor checks whether they currently hold valid access to a record."""
    record_id: str
    patient_public_key_hex: str = Field(
        ..., description="Patient's uncompressed public key hex (from GET /users/{id}/public-key)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "record_id": "a1b2c3d4e5f6...",
                "patient_public_key_hex": "04abc123def456...",
            }
        }


class RevokePermissionRequest(BaseModel):
    """Patient revokes a specific permission by its UUID."""
    permission_id: str = Field(..., description="UUID of the permission to revoke")

    class Config:
        json_schema_extra = {"example": {"permission_id": "550e8400-e29b-41d4-a716-446655440000"}}


class GrantPermissionResponse(BaseModel):
    permission_id: str
    signature: str
    patient_id: str
    doctor_id: str
    record_id: str
    time_window: Dict[str, str]
    permission_level: str
    status: str


class VerifyPermissionResponse(BaseModel):
    allowed: bool
    doctor_id: str
    record_id: str
    reason: str
    permission_id: Optional[str] = None
    timestamp: Optional[str] = None


class RevokePermissionResponse(BaseModel):
    status: str
    permission_id: str
    timestamp: str


# ──────────────────────────── Router ──────────────────────────────────────────

router = APIRouter(
    prefix="/permissions",
    tags=["permissions"],
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)


# ──────────────────────────── Endpoints ───────────────────────────────────────

@router.post("/grant", response_model=GrantPermissionResponse, status_code=status.HTTP_201_CREATED)
async def grant_permission(
    request: GrantPermissionRequest,
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Patient grants a doctor time-limited access to one of their records.

    **The patient's private key never leaves the client.**
    The frontend signs the permission payload locally and sends only the signature.

    Authorization: JWT required — caller must be a PATIENT.
    """
    # Enforce caller is a patient
    caller = db.query(User).filter(User.id == current_user_id).first()
    if not caller or caller.role != UserRole.PATIENT:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only patients can grant permissions",
        )

    try:
        service = PermissionService(db)
        result = service.grant_permission(
            patient_id=str(current_user_id),   # use JWT identity — not body
            doctor_id=request.doctor_id,
            record_id=request.record_id,
            time_window_hours=request.time_window_hours,
            permission_level=request.permission_level,
            signature_hex=request.signature_hex,          # client-produced signature
            doctor_encrypted_dek=request.doctor_encrypted_dek,
            valid_from=request.valid_from,                # use client timestamps so signature matches
            valid_until=request.valid_until,
        )
        return GrantPermissionResponse(**result)

    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/verify", response_model=VerifyPermissionResponse)
async def verify_permission(
    request: VerifyPermissionRequest,
    current_user_id: int = Depends(get_current_user_id),  # auth required
    db: Session = Depends(get_db),
):
    """
    Doctor checks whether they currently have valid, non-revoked access to a record.

    Authorization: JWT required — caller must be a DOCTOR.
    """
    caller = db.query(User).filter(User.id == current_user_id).first()
    if not caller or caller.role != UserRole.DOCTOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only doctors can verify permissions",
        )

    try:
        service = PermissionService(db)
        allowed, result = service.verify_permission(
            doctor_id=str(current_user_id),          # use JWT identity
            record_id=request.record_id,
            patient_public_key_hex=request.patient_public_key_hex,
        )

        return VerifyPermissionResponse(
            allowed=allowed,
            doctor_id=str(current_user_id),
            record_id=request.record_id,
            reason=result.get("reason", ""),
            permission_id=result.get("permission_id"),
            timestamp=result.get("timestamp", datetime.utcnow().isoformat()),
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error verifying permission: {str(e)}",
        )


@router.post("/revoke", response_model=RevokePermissionResponse)
async def revoke_permission(
    request: RevokePermissionRequest,
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Patient immediately revokes a permission.

    Authorization: JWT required — service layer enforces that only the granting
    patient can revoke their own permission.
    """
    try:
        service = PermissionService(db)
        result = service.revoke_permission(
            permission_id=request.permission_id,
            patient_id=str(current_user_id),   # use JWT identity — never trust body
        )
        return RevokePermissionResponse(**result)

    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.get("/patient/{patient_id}", response_model=List[Dict])
async def get_patient_permissions(
    patient_id: str,
    current_user_id: int = Depends(get_current_user_id),   # auth required
    db: Session = Depends(get_db),
):
    """
    List all permissions granted by a patient.

    Authorization: JWT required.
    - Patients may only view their own permissions.
    - Doctors/admins are blocked (return 403).
    """
    caller = db.query(User).filter(User.id == current_user_id).first()
    if not caller:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Only the patient themselves can list their permissions
    if caller.role != UserRole.PATIENT or current_user_id != int(patient_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own permissions",
        )

    try:
        service = PermissionService(db)
        return service.get_patient_permissions(patient_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving permissions: {str(e)}",
        )


@router.get("/audit", response_model=List[Dict])
async def get_audit_log(
    record_id: Optional[str] = None,
    doctor_id: Optional[str] = None,
    patient_id: Optional[str] = None,
    limit: int = 100,
    current_user_id: int = Depends(get_current_user_id),   # auth required
    db: Session = Depends(get_db),
):
    """
    Get audit log entries.

    Authorization: JWT required.
    Patients see only entries related to themselves.
    (Future: admin role gets full access.)
    """
    try:
        query = db.query(AuditLog)

        if record_id:
            query = query.filter(AuditLog.record_id == record_id)
        if doctor_id:
            query = query.filter(AuditLog.user_id == int(doctor_id))
        if patient_id:
            query = query.filter(AuditLog.related_user_id == int(patient_id))

        logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()

        return [
            {
                "timestamp": log.timestamp.isoformat(),
                "action": log.action.value,
                "user_id": log.user_id,
                "related_user_id": log.related_user_id,
                "record_id": log.record_id,
                "description": log.description,
            }
            for log in logs
        ]

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving audit log: {str(e)}",
        )


# ──────────────────────────── Audit chain verify ──────────────────────────────

class ChainVerifyResponse(BaseModel):
    intact: bool
    broken_at_id: Optional[int] = None
    message: str
    total_entries: int


@router.get(
    "/audit/verify-chain",
    response_model=ChainVerifyResponse,
    summary="Verify audit log hash chain integrity (admin / forensic use)",
)
async def verify_audit_chain(
    current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    """
    Walk the entire audit log and verify every hash-chain link.

    Returns whether the chain is intact and, if not, the id of the first
    broken entry.  Only ADMIN-role users may call this endpoint.
    """
    caller = db.query(User).filter(User.id == current_user_id).first()
    if not caller or caller.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit chain verification requires ADMIN role",
        )

    from src.services import audit_service
    total = db.query(AuditLog).count()
    intact, broken_at, message = audit_service.verify_chain(db)

    return ChainVerifyResponse(
        intact=intact,
        broken_at_id=broken_at,
        message=message,
        total_entries=total,
    )
