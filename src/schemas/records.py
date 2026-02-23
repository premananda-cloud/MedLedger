"""
Record Schemas - Request/Response validation for medical record endpoints
Location: src/schemas/records.py

Covers:
- UploadResponse: returned after a successful (or duplicate) upload
- RecordMetaResponse: record metadata visible to patient and authorised doctor
- RecordListResponse: list of a patient's records (metadata only, no file bytes)
- DoctorViewRequest: body sent by doctor to view a record (carries patient pub-key)
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ─────────────────────────── Upload ───────────────────────────

class UploadResponse(BaseModel):
    """Returned by POST /records/upload"""
    record_id: str = Field(..., description="Stable SHA-256 record identifier")
    already_existed: bool = Field(
        ...,
        description="True when the exact file was already on record (de-dup hit)"
    )
    patient_id: int
    filename: str
    content_type: str
    content_hash: str = Field(..., description="SHA-256 hex of the raw file bytes")
    storage_path: str = Field(..., description="Server-side relative storage path")
    created_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "record_id": "a1b2c3d4e5f6...",
                "already_existed": False,
                "patient_id": 7,
                "filename": "blood_test_2025.pdf",
                "content_type": "application/pdf",
                "content_hash": "7f2a3b4c...",
                "storage_path": "uploads/7/a1b2c3d4.pdf",
                "created_at": "2025-02-15T10:30:00Z",
            }
        }


# ─────────────────────────── View / List ───────────────────────────

class RecordMetaResponse(BaseModel):
    """
    Record metadata returned to the requester.
    File bytes are streamed separately via FileResponse.
    """
    record_id: str
    patient_id: int
    filename: str
    content_type: str
    content_hash: str
    storage_path: str
    created_at: datetime
    # If the caller is a doctor these extra fields are populated
    accessed_by_doctor_id: Optional[int] = None
    access_expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "record_id": "a1b2c3d4e5f6...",
                "patient_id": 7,
                "filename": "blood_test_2025.pdf",
                "content_type": "application/pdf",
                "content_hash": "7f2a3b4c...",
                "storage_path": "uploads/7/a1b2c3d4.pdf",
                "created_at": "2025-02-15T10:30:00Z",
                "accessed_by_doctor_id": 12,
                "access_expires_at": "2025-02-15T12:30:00Z",
            }
        }


class RecordListResponse(BaseModel):
    """Returned by GET /records/my — patient's own record index"""
    total: int
    records: list[RecordMetaResponse]


# ─────────────────────────── Doctor-view helper ───────────────────────────

class DoctorViewRequest(BaseModel):
    """
    Body sent by a doctor to view a specific record.

    The doctor must supply the *patient's* public key so the server can verify
    the ECDSA permission signature without storing it.  In practice the doctor
    obtains this from the patient or via GET /users/{patient_id}/public-key.
    """
    patient_public_key_hex: str = Field(
        ...,
        description="Patient's uncompressed public key hex (obtained at grant time)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "patient_public_key_hex": "04abc123def456..."
            }
        }
