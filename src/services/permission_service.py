"""
Permission Service - Business Logic for Access Control
Location: src/services/permission_service.py

Handles:
- Creating permission grants (patient signs, doctor gets access window)
- Verifying permissions (checking if doctor can access now)
- Revoking permissions (instant revocation by patient)
- Audit logging (tracking all permission changes)

FIX LOG (aligned service to actual AccessPermission/AuditLog model):
  - AccessPermission uses permission_id (str UUID), grantee_public_key_hash,
    valid_from/valid_until, patient_signature, conditions (JSON)
  - AuditLog uses user_id (int), related_user_id (int), description, record_id
  - AuditAction has no ACCESS_ATTEMPT → use RECORD_ACCESSED instead
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, List
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import uuid

from src.crypto.signature_verifier import SignatureVerifier
from src.database.models import User, AccessPermission, AuditLog, AuditAction


class PermissionError(Exception):
    """Base exception for permission errors"""
    pass


class InvalidPermissionError(PermissionError):
    """Permission signature is invalid"""
    pass


class AccessDeniedError(PermissionError):
    """Access denied (expired, revoked, or invalid signature)"""
    pass


class PermissionService:
    """
    Service for managing patient-controlled access permissions.

    Security model:
    - Patient signs each permission grant with their private key
    - Grantee is identified by their public_key_hash (not a mutable username)
    - Time-limited access enforced on every verification
    - Instant revocation via is_revoked flag
    - Immutable audit trail
    """

    def __init__(self, db: Session):
        self.db = db
        self.verifier = SignatureVerifier()

    # ==================== Grant Permission ====================

    def grant_permission(
        self,
        patient_id: str,
        doctor_id: str,
        record_id: str,
        time_window_hours: int,
        permission_level: str,
        signature_hex: str,          # ECDSA signature produced CLIENT-SIDE by the patient
        doctor_encrypted_dek: str,   # ECIES bundle: DEK re-encrypted for the doctor
    ) -> Dict:
        """
        Record a patient's access grant for a doctor on a specific record.

        The private key NEVER reaches the server.  The patient signs the canonical
        permission payload on their own device (SubtleCrypto / local tool) and sends
        only the hex-encoded ECDSA signature here.

        The server:
          1. Builds the same canonical payload (deterministic JSON, sorted keys).
          2. Verifies the submitted signature against the patient's stored public key.
          3. Persists the permission row only if verification passes.

        Returns:
            Dict: permission_id, signature, time_window, status
        Raises:
            PermissionError:        patient/doctor not found, DB error
            InvalidPermissionError: signature verification failed
        """
        try:
            # 1. Validate patient exists
            patient = self.db.query(User).filter(User.id == int(patient_id)).first()
            if not patient:
                raise PermissionError(f"Patient {patient_id} not found")

            # 2. Validate doctor exists and get their public_key_hash
            doctor = self.db.query(User).filter(User.id == int(doctor_id)).first()
            if not doctor:
                raise PermissionError(f"Doctor {doctor_id} not found")

            # 3. Build the canonical payload the patient should have signed.
            #    This MUST match the exact JSON the client serialised before signing.
            valid_from  = datetime.utcnow()
            valid_until = valid_from + timedelta(hours=time_window_hours)

            permission_payload = {
                "patient_id": patient_id,
                "grantee_public_key_hash": doctor.public_key_hash,
                "record_id": record_id,
                "valid_from":  valid_from.isoformat(),
                "valid_until": valid_until.isoformat(),
                "permission_level": permission_level,
            }
            permission_data_str = json.dumps(permission_payload, sort_keys=True)

            # 4. Verify the client-produced signature against the patient's stored public key.
            #    This proves the patient (who holds the private key) authorised this grant.
            is_valid, sig_reason = self.verifier.verify_signature(
                patient.public_key_hex,
                signature_hex,
                permission_payload,          # verifier re-serialises internally
            )
            if not is_valid:
                raise InvalidPermissionError(
                    f"Permission signature verification failed: {sig_reason}"
                )

            # 5. Persist the permission row
            perm_uuid = str(uuid.uuid4())
            can_write  = permission_level == "view_download"

            perm = AccessPermission(
                permission_id=perm_uuid,
                patient_id=int(patient_id),
                grantee_public_key_hash=doctor.public_key_hash,
                record_id=record_id,
                can_read=True,
                can_write=can_write,
                can_audit=False,
                can_delegate=False,
                valid_from=valid_from,
                valid_until=valid_until,
                conditions=permission_data_str,
                patient_signature=signature_hex,
                signature_timestamp=datetime.utcnow(),
                doctor_encrypted_dek=doctor_encrypted_dek,
                is_active=True,
                is_revoked=False,
                created_at=datetime.utcnow(),
            )
            self.db.add(perm)
            self.db.commit()

            # 6. Audit log
            self._log_audit(
                action=AuditAction.PERMISSION_GRANTED,
                user_id=int(patient_id),
                related_user_id=int(doctor_id),
                record_id=record_id,
                description=f"Permission granted for {time_window_hours}h ({permission_level})",
            )

            return {
                "permission_id": perm_uuid,
                "signature": signature_hex,
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "grantee_public_key_hash": doctor.public_key_hash,
                "record_id": record_id,
                "time_window": {
                    "start": valid_from.isoformat(),
                    "end":   valid_until.isoformat(),
                },
                "permission_level": permission_level,
                "status": "granted",
            }

        except PermissionError:
            raise
        except IntegrityError as e:
            self.db.rollback()
            raise PermissionError(f"Database integrity error: {e}")
        except Exception as e:
            self.db.rollback()
            raise PermissionError(f"Failed to grant permission: {e}")

    # ==================== Verify Permission ====================

    def verify_permission(
        self,
        doctor_id: str,
        record_id: str,
        patient_public_key_hex: str      # Patient's full public key hex for sig verification
    ) -> Tuple[bool, Dict]:
        """
        Check if a doctor currently has valid access to a record.

        Returns:
            (True, detail_dict)  if access granted
            (False, detail_dict) if denied, with reason
        """
        result: Dict = {
            "allowed": False,
            "timestamp": datetime.utcnow().isoformat(),
            "doctor_id": doctor_id,
            "record_id": record_id,
            "reason": "",
        }

        try:
            # Look up doctor by ID to get their public_key_hash
            doctor = self.db.query(User).filter(User.id == int(doctor_id)).first()
            if not doctor:
                result["reason"] = f"Doctor {doctor_id} not found"
                return False, result

            # Find most recent non-revoked permission for (grantee, record)
            perm = (
                self.db.query(AccessPermission)
                .filter(
                    AccessPermission.grantee_public_key_hash == doctor.public_key_hash,
                    AccessPermission.record_id == record_id,
                    AccessPermission.is_revoked == False,
                    AccessPermission.is_active  == True,
                )
                .order_by(AccessPermission.created_at.desc())
                .first()
            )

            if not perm:
                result["reason"] = "No active permission found"
                self._log_access_attempt(int(doctor_id), record_id, False, "No permission")
                return False, result

            # Check time window
            now = datetime.utcnow()
            if now < perm.valid_from:
                result["reason"] = "Permission not yet valid"
                self._log_access_attempt(int(doctor_id), record_id, False, "Not yet valid")
                return False, result

            if now > perm.valid_until:
                result["reason"] = "Permission has expired"
                self._log_access_attempt(int(doctor_id), record_id, False, "Expired")
                return False, result

            # Verify the patient's signature over the stored conditions payload.
            # FIX BUG 1: perm.conditions is stored as a JSON *string*. verify_signature
            # expects a dict and re-serialises it internally. Passing the raw string
            # would cause json.dumps(string) → a double-encoded string that never
            # matches what was originally signed. Parse it back to dict first.
            try:
                conditions_dict = json.loads(perm.conditions)
                is_sig_valid, sig_reason = self.verifier.verify_signature(
                    patient_public_key_hex,
                    perm.patient_signature,
                    conditions_dict
                )
            except Exception as e:
                is_sig_valid = False
                sig_reason = str(e)

            if not is_sig_valid:
                result["reason"] = f"Signature invalid: {sig_reason}"
                self._log_access_attempt(
                    int(doctor_id), record_id, False, "Invalid signature"
                )
                return False, result

            # All checks passed
            result["allowed"] = True
            result["permission_id"] = perm.permission_id
            result["valid_until"] = perm.valid_until.isoformat()
            result["reason"] = "Access granted"

            self._log_access_attempt(int(doctor_id), record_id, True, "Granted")
            return True, result

        except Exception as e:
            result["reason"] = f"Verification error: {e}"
            return False, result

    # ==================== Revoke Permission ====================

    def revoke_permission(self, permission_id: str, patient_id: str) -> Dict:
        """
        Patient immediately revokes an access permission.

        Args:
            permission_id: The UUID string (permission_id field, not pk id)
            patient_id: Integer ID of the revoking patient (as string)
        Returns:
            Dict: status, permission_id, timestamp
        Raises:
            PermissionError: not found or unauthorized
        """
        try:
            # Query by permission_id (UUID string), NOT by integer pk
            perm = (
                self.db.query(AccessPermission)
                .filter(AccessPermission.permission_id == permission_id)
                .first()
            )

            if not perm:
                raise PermissionError(f"Permission '{permission_id}' not found")

            if perm.patient_id != int(patient_id):
                raise PermissionError("Only the granting patient can revoke this permission")

            perm.is_revoked = True
            perm.is_active  = False
            perm.revoked_at = datetime.utcnow()
            perm.doctor_encrypted_dek = None   # doctor can no longer derive the DEK
            self.db.commit()

            self._log_audit(
                action=AuditAction.PERMISSION_REVOKED,
                user_id=int(patient_id),
                related_user_id=None,
                record_id=perm.record_id,
                description=f"Permission {permission_id} revoked"
            )

            return {
                "status": "revoked",
                "permission_id": permission_id,
                "timestamp": datetime.utcnow().isoformat(),
            }

        except PermissionError:
            raise
        except Exception as e:
            self.db.rollback()
            raise PermissionError(f"Failed to revoke permission: {e}")

    # ==================== Queries ====================

    def get_patient_permissions(self, patient_id: str) -> List[Dict]:
        """Return all permissions ever granted by this patient."""
        perms = (
            self.db.query(AccessPermission)
            .filter(AccessPermission.patient_id == int(patient_id))
            .order_by(AccessPermission.created_at.desc())
            .all()
        )
        return [
            {
                "permission_id": p.permission_id,
                "grantee_public_key_hash": p.grantee_public_key_hash,
                "record_id": p.record_id,
                "valid_from":  p.valid_from.isoformat() if p.valid_from else None,
                "valid_until": p.valid_until.isoformat() if p.valid_until else None,
                "is_active":  p.is_active,
                "is_revoked": p.is_revoked,
            }
            for p in perms
        ]

    def get_active_permissions_for_record(self, record_id: str) -> List[AccessPermission]:
        """Return all currently-valid permissions for a record."""
        return (
            self.db.query(AccessPermission)
            .filter(
                AccessPermission.record_id == record_id,
                AccessPermission.is_revoked == False,
                AccessPermission.valid_until > datetime.utcnow()  # FIX: was time_end
            )
            .all()
        )

    # ==================== Internal Audit Logging ====================

    def _log_audit(
        self,
        action: AuditAction,
        user_id: int,
        related_user_id: Optional[int],
        record_id: Optional[str],
        description: str
    ):
        """Append to the immutable audit trail."""
        try:
            # Build a deterministic hash for chain integrity
            raw = f"{action}{user_id}{related_user_id}{record_id}{description}{datetime.utcnow().isoformat()}"
            event_hash = hashlib.sha256(raw.encode()).hexdigest()

            log = AuditLog(
                user_id=user_id,
                action=action,
                record_id=record_id,
                related_user_id=related_user_id,
                description=description,
                event_hash=event_hash,
                timestamp=datetime.utcnow(),
            )
            self.db.add(log)
            self.db.commit()
        except Exception as e:
            # Audit failures should never break the main flow
            print(f"⚠ Audit log warning: {e}")

    def _log_access_attempt(
        self,
        doctor_id: int,
        record_id: str,
        success: bool,
        reason: str
    ):
        """Log an access verification attempt."""
        self._log_audit(
            action=AuditAction.RECORD_ACCESSED,   # FIX: ACCESS_ATTEMPT doesn't exist
            user_id=doctor_id,
            related_user_id=None,
            record_id=record_id,
            description=f"{'GRANTED' if success else 'DENIED'}: {reason}"
        )
