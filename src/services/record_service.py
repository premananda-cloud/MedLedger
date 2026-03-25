"""
Record Service - Business Logic for Medical Record Upload & Retrieval
Location: src/services/record_service.py

Responsibilities:
- Upload a file for a patient, with SHA-256 deduplication
- Retrieve a record path for the owning patient (no permission check needed)
- Retrieve a record path for a doctor AFTER verifying the permission signature
  via the existing PermissionService (no logic duplication)
- Audit every access attempt

Storage layout (local, Phase-1):
    UPLOAD_ROOT/
        <patient_id>/
            <record_id>_<original_filename>

UPLOAD_ROOT defaults to "./medledger_uploads" and is configurable via the
MEDLEDGER_UPLOAD_DIR environment variable.
"""

import os
import hashlib
import uuid
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict

from sqlalchemy.orm import Session

from src.database.models import (
    MedicalRecordBlock, User, UserRole, AuditLog, AuditAction
)
from src.services.permission_service import PermissionService, PermissionError

# ─────────────────────── Config ───────────────────────────────────────────────
UPLOAD_ROOT = Path(os.getenv("MEDLEDGER_UPLOAD_DIR", "./medledger_uploads"))


# ─────────────────────── Exceptions ───────────────────────────────────────────

class RecordError(Exception):
    """Base exception for record operations"""
    pass


class RecordNotFoundError(RecordError):
    pass


class DuplicateRecordError(RecordError):
    """Raised when the exact file already exists for this patient"""
    def __init__(self, existing_record: MedicalRecordBlock):
        self.existing_record = existing_record
        super().__init__(f"Record already exists: {existing_record.record_id}")


class AccessDeniedError(RecordError):
    pass


class NotAPatientError(RecordError):
    pass


# ─────────────────────── Service ──────────────────────────────────────────────

class RecordService:
    """
    Handles the full lifecycle of a medical record:
      upload → dedup → store → patient view → doctor view (permission-gated)
    """

    def __init__(self, db: Session):
        self.db = db
        self.perm_service = PermissionService(db)

    # ══════════════════════════════════════════════════════════════════════════
    # 1.  UPLOAD
    # ══════════════════════════════════════════════════════════════════════════

    def upload_record(
        self,
        uploader_id: int,
        file_bytes: bytes,
        original_filename: str,
        content_type: str,
        patient_id: Optional[int] = None,
        encrypted_dek: Optional[str] = None,   # ECIES bundle JSON string from client — REQUIRED for new records
    ) -> Tuple[MedicalRecordBlock, bool]:
        """
        Store a medical record file for a patient.

        Returns:
            (record, already_existed)
            already_existed = True  → identical file was already on record
            already_existed = False → new record created

        Raises:
            NotAPatientError  – target patient does not exist / wrong role
            RecordError       – any other storage failure
        """
        # ── Resolve the actual patient ────────────────────────────────────────
        uploader = self._get_user_or_raise(uploader_id)

        if patient_id is None:
            # Uploading for yourself — only patients may do this
            if uploader.role != UserRole.PATIENT:
                raise NotAPatientError(
                    "Doctors must specify patient_id when uploading a record"
                )
            target_patient_id = uploader_id
        else:
            # Doctor uploading on behalf of a patient
            target_patient = self._get_user_or_raise(patient_id)
            if target_patient.role != UserRole.PATIENT:
                raise NotAPatientError(
                    f"User {patient_id} is not a patient"
                )
            target_patient_id = patient_id

        # ── Compute content hash (dedup key) ──────────────────────────────────
        content_hash = hashlib.sha256(file_bytes).hexdigest()

        # ── Deduplication check ───────────────────────────────────────────────
        existing = (
            self.db.query(MedicalRecordBlock)
            .filter(
                MedicalRecordBlock.patient_id == target_patient_id,
                MedicalRecordBlock.content_hash == content_hash,
            )
            .first()
        )
        if existing:
            # Same bytes already stored — return the existing record
            self._log(
                action=AuditAction.RECORD_ACCESSED,
                user_id=uploader_id,
                related_user_id=target_patient_id,
                record_id=existing.record_id,
                description=f"Duplicate upload detected — existing record returned",
            )
            return existing, True

        # ── Build unique record_id: patient + content_hash + random salt ────
        # uuid4 salt ensures two patients uploading the exact same file bytes
        # never produce the same record_id and hit the UniqueConstraint.
        record_id = hashlib.sha256(
            f"{target_patient_id}:{content_hash}:{uuid.uuid4()}".encode()
        ).hexdigest()

        # ── Persist file to disk ──────────────────────────────────────────────
        patient_dir = UPLOAD_ROOT / str(target_patient_id)
        patient_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize extension: allow only alphanumeric chars to prevent path traversal
        # e.g. "../../evil.sh" → suffix="" → stored as just the record_id prefix
        raw_suffix = Path(original_filename).suffix  # e.g. ".pdf", ".jpg"
        if raw_suffix and raw_suffix[1:].isalnum() and len(raw_suffix) <= 6:
            suffix = raw_suffix.lower()
        else:
            suffix = ""

        stored_filename = f"{record_id[:16]}{suffix}"
        file_path = patient_dir / stored_filename

        # Resolve to absolute path and confirm it is strictly inside patient_dir.
        # This blocks any remaining path traversal (e.g. symlink attacks).
        resolved = file_path.resolve()
        resolved_root = patient_dir.resolve()
        if not str(resolved).startswith(str(resolved_root) + "/"):
            raise RecordError("Rejected: computed storage path escapes upload root")

        try:
            file_path.write_bytes(file_bytes)
        except OSError as exc:
            raise RecordError(f"Failed to write file: {exc}") from exc

        storage_path = str(file_path.relative_to(Path(".")))

        # Reject uploads that arrive without an encrypted DEK.
        # A missing DEK means the record would be stored with no key protection —
        # silently accepting it would violate the core security guarantee.
        if not encrypted_dek:
            raise RecordError(
                "encrypted_dek is required. Encrypt the file DEK with the patient's "
                "public key (ECIES) before uploading."
            )

        # Basic structure check — must be valid JSON with the four ECIES fields
        import json as _json
        try:
            _bundle = _json.loads(encrypted_dek)
            if not all(k in _bundle for k in ("epk", "iv", "ct", "tag")):
                raise ValueError("missing required ECIES fields")
        except (ValueError, TypeError) as exc:
            raise RecordError(f"encrypted_dek is not a valid ECIES bundle: {exc}") from exc

        dek_to_store = encrypted_dek

        # ── Create DB record ──────────────────────────────────────────────────
        record = MedicalRecordBlock(
            record_id=record_id,
            patient_id=target_patient_id,
            provider_id=uploader_id,
            content_hash=content_hash,
            content_type=content_type,
            storage_protocol="LOCAL",
            storage_cid=storage_path,
            encrypted_dek_hex=dek_to_store,
            is_immutable=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)

        # ── Audit ──────────────────────────────────────────────────────────────
        self._log(
            action=AuditAction.RECORD_CREATED,
            user_id=uploader_id,
            related_user_id=target_patient_id,
            record_id=record_id,
            description=f"Record uploaded: {original_filename} ({len(file_bytes)} bytes)",
        )

        return record, False

    # ══════════════════════════════════════════════════════════════════════════
    # 2.  PATIENT RETRIEVES OWN RECORD
    # ══════════════════════════════════════════════════════════════════════════

    def get_record_as_patient(
        self, patient_id: int, record_id: str
    ) -> Tuple[MedicalRecordBlock, Path, str]:
        """
        Returns (record_meta, absolute_file_path, patient_dek_bundle).
        No permission check needed — it's their own file.

        patient_dek_bundle is the ECIES JSON bundle (always present — uploads without a DEK are rejected)
        stored at upload time. The client uses it to decrypt the file with
        their private key.

        Raises:
            RecordNotFoundError – record_id not found or doesn't belong to patient
        """
        record = self._fetch_record(record_id)
        if record.patient_id != patient_id:
            raise RecordNotFoundError(
                f"Record {record_id} not found for patient {patient_id}"
            )

        abs_path = self._resolve_path(record)

        self._log(
            action=AuditAction.RECORD_ACCESSED,
            user_id=patient_id,
            related_user_id=None,
            record_id=record_id,
            description="Patient accessed own record",
        )
        # Return the DEK bundle stored at upload time (always a valid ECIES JSON bundle)
        return record, abs_path, record.encrypted_dek_hex

    # ══════════════════════════════════════════════════════════════════════════
    # 3.  DOCTOR RETRIEVES A PATIENT'S RECORD (permission-gated)
    # ══════════════════════════════════════════════════════════════════════════

    def get_record_as_doctor(
        self,
        doctor_id: int,
        record_id: str,
        patient_public_key_hex: str,
    ) -> Tuple[MedicalRecordBlock, Path, Dict, str]:
        """
        Returns (record_meta, absolute_file_path, permission_detail) if and only
        if the doctor holds a valid, non-revoked, in-window permission.

        The permission is verified via PermissionService.verify_permission(),
        which checks:
          1. A non-revoked AccessPermission row exists for (doctor, record)
          2. Current time is inside the valid_from … valid_until window
          3. Patient's ECDSA signature over the grant payload is valid

        Raises:
            AccessDeniedError   – any of the three checks fail
            RecordNotFoundError – record_id not in DB
        """
        record = self._fetch_record(record_id)

        # Delegate ALL permission logic to PermissionService — no duplication
        allowed, detail = self.perm_service.verify_permission(
            doctor_id=str(doctor_id),
            record_id=record_id,
            patient_public_key_hex=patient_public_key_hex,
        )

        if not allowed:
            reason = detail.get("reason", "Access denied")
            # PermissionService already logs the attempt; we don't double-log
            raise AccessDeniedError(reason)

        abs_path = self._resolve_path(record)

        # Extra audit entry from the record-access layer
        self._log(
            action=AuditAction.RECORD_ACCESSED,
            user_id=doctor_id,
            related_user_id=record.patient_id,
            record_id=record_id,
            description=f"Doctor viewed record (permission: {detail.get('permission_id')})",
        )

                # Fetch the doctor's DEK bundle from the permission row for the route header.
        from src.database.models import AccessPermission as _AP
        perm_row = (
            self.db.query(_AP)
            .filter(_AP.permission_id == detail.get('permission_id'))
            .first()
        )
        doctor_dek_bundle = perm_row.doctor_encrypted_dek if perm_row else ""

        return record, abs_path, detail, doctor_dek_bundle

    # ══════════════════════════════════════════════════════════════════════════
    # 4.  LIST PATIENT'S OWN RECORDS (metadata only)
    # ══════════════════════════════════════════════════════════════════════════

    def list_patient_records(self, patient_id: int):
        """Return all MedicalRecordBlock rows belonging to patient_id."""
        return (
            self.db.query(MedicalRecordBlock)
            .filter(MedicalRecordBlock.patient_id == patient_id)
            .order_by(MedicalRecordBlock.created_at.desc())
            .all()
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Internal helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _get_user_or_raise(self, user_id: int) -> User:
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise RecordError(f"User {user_id} not found")
        return user

    def _fetch_record(self, record_id: str) -> MedicalRecordBlock:
        record = (
            self.db.query(MedicalRecordBlock)
            .filter(MedicalRecordBlock.record_id == record_id)
            .first()
        )
        if not record:
            raise RecordNotFoundError(f"Record {record_id} not found")
        return record

    def _resolve_path(self, record: MedicalRecordBlock) -> Path:
        """Turn the stored storage_cid into an absolute Path and verify it exists.

        Guards against a tampered storage_cid in the DB escaping UPLOAD_ROOT.
        """
        path = Path(record.storage_cid)
        if not path.is_absolute():
            path = UPLOAD_ROOT.resolve() / path
        resolved = path.resolve()

        # Enforce that the resolved path is strictly inside UPLOAD_ROOT
        upload_root_resolved = UPLOAD_ROOT.resolve()
        if not str(resolved).startswith(str(upload_root_resolved) + "/"):
            raise RecordError(
                f"Security: storage_cid for record {record.record_id} resolves outside UPLOAD_ROOT"
            )

        if not resolved.exists():
            raise RecordError(
                f"File missing on disk for record {record.record_id}: {resolved}"
            )
        return resolved

    def _log(
        self,
        action: AuditAction,
        user_id: int,
        related_user_id: Optional[int],
        record_id: Optional[str],
        description: str,
    ):
        """Append to the immutable audit trail via the shared AuditService."""
        from src.services import audit_service
        audit_service.append(
            self.db,
            action=action,
            user_id=user_id,
            related_user_id=related_user_id,
            record_id=record_id,
            description=description,
        )
