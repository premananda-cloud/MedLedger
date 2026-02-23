"""
Record Routes - Upload & View Medical Records
Location: src/api/routes/records.py

What changed from Phase 1
─────────────────────────
GET  /records/{record_id}
  Now returns the encrypted blob as binary + two headers:
    X-DEK-Bundle   : ECIES bundle JSON (patient decrypts client-side)
    X-Content-Type : original MIME type (so frontend knows how to render)
  (FileResponse is replaced with a raw binary Response)

POST /records/{record_id}/doctor-view
  Same encrypted blob + X-DEK-Bundle (doctor's ECIES bundle from permission row).
  The DoctorViewRequest body is unchanged (still carries patient_public_key_hex).

Everything else (upload, /my, /meta, /users/{id}/public-key) is unchanged.
"""

from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter, Depends, File, Form, HTTPException,
    Request, UploadFile, status, Response,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from src.api.routes.auth import get_current_user_id
from src.database.connection import get_db
from src.database.models import MedicalRecordBlock, User, UserRole
from src.schemas.records import (
    DoctorViewRequest, RecordListResponse,
    RecordMetaResponse, UploadResponse,
)
from src.services.record_service import (
    AccessDeniedError, NotAPatientError,
    RecordError, RecordNotFoundError, RecordService,
)

router = APIRouter(
    prefix="/records",
    tags=["records"],
    responses={
        401: {"description": "Unauthorised"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)

MAX_UPLOAD_BYTES = 20 * 1024 * 1024   # 20 MB


def _record_to_meta(record: MedicalRecordBlock, **extra) -> RecordMetaResponse:
    return RecordMetaResponse(
        record_id=record.record_id,
        patient_id=record.patient_id,
        filename=Path(record.storage_cid).name,
        content_type=record.content_type or "application/octet-stream",
        content_hash=record.content_hash,
        storage_path=record.storage_cid,
        created_at=record.created_at,
        **extra,
    )


def _get_service(db: Session = Depends(get_db)) -> RecordService:
    return RecordService(db)


def _require_role(required: UserRole, db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if user.role != required:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This endpoint requires role: {required.value}",
        )
    return user


# ═════════════════════════════════════════════════════════════════════════════
# POST /records/upload
# ═════════════════════════════════════════════════════════════════════════════

@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload and encrypt a medical record file",
)
async def upload_record(
    file: UploadFile = File(...),
    patient_id: Optional[int] = Form(default=None),
    encrypted_dek: Optional[str] = Form(default=None),   # ECIES bundle JSON from client
    content_hash: Optional[str] = Form(default=None),    # for audit/verification
    signature: Optional[str] = Form(default=None),       # ECDSA sig over content_hash
    current_user_id: int = Depends(get_current_user_id),
    service: RecordService = Depends(_get_service),
):
    file_bytes = await file.read()
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit",
        )

    content_type      = file.content_type or "application/octet-stream"
    original_filename = file.filename or "record"

    try:
        record, already_existed = service.upload_record(
            uploader_id=current_user_id,
            file_bytes=file_bytes,
            original_filename=original_filename,
            content_type=content_type,
            patient_id=patient_id,
            encrypted_dek=encrypted_dek,
        )
    except NotAPatientError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except RecordError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    return UploadResponse(
        record_id=record.record_id,
        already_existed=already_existed,
        patient_id=record.patient_id,
        filename=original_filename,
        content_type=record.content_type or content_type,
        content_hash=record.content_hash,
        storage_path=record.storage_cid,
        created_at=record.created_at,
    )


# ═════════════════════════════════════════════════════════════════════════════
# GET /records/my
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/my", response_model=RecordListResponse, status_code=status.HTTP_200_OK)
async def list_my_records(
    current_user_id: int = Depends(get_current_user_id),
    service: RecordService = Depends(_get_service),
    db: Session = Depends(get_db),
):
    _require_role(UserRole.PATIENT, db, current_user_id)
    records = service.list_patient_records(current_user_id)
    return RecordListResponse(
        total=len(records),
        records=[_record_to_meta(r) for r in records],
    )


# ═════════════════════════════════════════════════════════════════════════════
# GET /records/{record_id}/meta
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/{record_id}/meta", response_model=RecordMetaResponse, status_code=status.HTTP_200_OK)
async def get_record_meta(
    record_id: str,
    current_user_id: int = Depends(get_current_user_id),
    service: RecordService = Depends(_get_service),
    db: Session = Depends(get_db),
):
    _require_role(UserRole.PATIENT, db, current_user_id)
    try:
        record, _, _dek = service.get_record_as_patient(current_user_id, record_id)
    except RecordNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except RecordError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
    return _record_to_meta(record)


# ═════════════════════════════════════════════════════════════════════════════
# GET /records/{record_id}   — patient downloads their own encrypted blob
#
# CHANGED FROM PHASE 1
# Returns:  binary body = encrypted blob (IV + AES-GCM ciphertext+tag)
#           X-DEK-Bundle header = ECIES JSON the client decrypts with private key
#           X-Content-Type header = original MIME type
#
# Frontend responsibility:
#   1. Receive binary body (encrypted blob)
#   2. Parse X-DEK-Bundle JSON
#   3. ECIES-decrypt the bundle with patient's private key → DEK
#   4. Split blob: first 12 bytes = IV, rest = ciphertext+tag
#   5. AES-256-GCM decrypt ciphertext with DEK and IV
#   6. Set MIME type from X-Content-Type and render/download
# ═════════════════════════════════════════════════════════════════════════════

@router.get(
    "/{record_id}",
    summary="Download encrypted record blob (patient only) — decrypt client-side",
)
async def get_own_record(
    record_id: str,
    current_user_id: int = Depends(get_current_user_id),
    service: RecordService = Depends(_get_service),
    db: Session = Depends(get_db),
):
    _require_role(UserRole.PATIENT, db, current_user_id)

    try:
        record, abs_path, patient_dek_bundle = service.get_record_as_patient(
            current_user_id, record_id
        )
    except RecordNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except RecordError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    encrypted_blob = abs_path.read_bytes()

    return Response(
        content=encrypted_blob,
        media_type="application/octet-stream",
        headers={
            "X-Record-Id":     record_id,
            "X-Content-Hash":  record.content_hash,
            "X-DEK-Bundle":    patient_dek_bundle,
            "X-Content-Type":  record.content_type or "application/octet-stream",
            # Expose headers to browser JS (CORS)
            "Access-Control-Expose-Headers": "X-DEK-Bundle,X-Content-Type,X-Record-Id,X-Content-Hash",
        },
    )


# ═════════════════════════════════════════════════════════════════════════════
# POST /records/{record_id}/doctor-view
#
# CHANGED FROM PHASE 1
# Returns:  binary body = encrypted blob (same as patient endpoint)
#           X-DEK-Bundle header = DOCTOR's ECIES bundle from the permission row
#
# Frontend responsibility (same steps as patient, but using doctor's private key):
#   1. Receive binary body
#   2. Parse X-DEK-Bundle
#   3. ECIES-decrypt with DOCTOR's private key → DEK
#   4. AES-256-GCM decrypt blob → plaintext
#   5. Render with X-Content-Type
# ═════════════════════════════════════════════════════════════════════════════

@router.post(
    "/{record_id}/doctor-view",
    summary="Doctor downloads encrypted record blob — decrypt client-side with doctor's private key",
)
async def doctor_view_record(
    record_id: str,
    body: DoctorViewRequest,
    current_user_id: int = Depends(get_current_user_id),
    service: RecordService = Depends(_get_service),
    db: Session = Depends(get_db),
):
    _require_role(UserRole.DOCTOR, db, current_user_id)

    try:
        record, abs_path, perm_detail, doctor_dek_bundle = service.get_record_as_doctor(
            doctor_id=current_user_id,
            record_id=record_id,
            patient_public_key_hex=body.patient_public_key_hex,
        )
    except AccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except RecordNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except RecordError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

    encrypted_blob = abs_path.read_bytes()

    return Response(
        content=encrypted_blob,
        media_type="application/octet-stream",
        headers={
            "X-Record-Id":      record_id,
            "X-Content-Hash":   record.content_hash,
            "X-DEK-Bundle":     doctor_dek_bundle,
            "X-Content-Type":   record.content_type or "application/octet-stream",
            "X-Permission-Id":  perm_detail.get("permission_id", ""),
            "X-Access-Expires": perm_detail.get("valid_until", ""),
            "Access-Control-Expose-Headers": (
                "X-DEK-Bundle,X-Content-Type,X-Record-Id,"
                "X-Content-Hash,X-Permission-Id,X-Access-Expires"
            ),
        },
    )


# ═════════════════════════════════════════════════════════════════════════════
# GET /users/{target_user_id}/public-key
# ═════════════════════════════════════════════════════════════════════════════

public_key_router = APIRouter(prefix="/users", tags=["users"])


@public_key_router.get("/{target_user_id}/public-key", status_code=status.HTTP_200_OK)
async def get_user_public_key(
    target_user_id: int,
    _current_user_id: int = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == target_user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return {
        "user_id":              user.id,
        "username":             user.username,
        "role":                 user.role.value,
        "public_key_hex":       user.public_key_hex,
        "public_key_compressed": user.public_key_compressed,
        "public_key_hash":      user.public_key_hash,
        "algorithm":            "ECDSA-P256",
    }
