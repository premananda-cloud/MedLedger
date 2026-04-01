"""
CypherAegis Transceiver
Location: src/services/transceiver.py

Wires the full crypto layer to the VaultStore persistence layer.
All vault I/O goes through VaultStore — no raw JSON reads/writes here.

Operations
──────────
  upload      Encrypt a file and store it. Returns a record_id.
  download    Decrypt a file you own or have a valid grant for.
  grant       Patient signs a permission and re-encrypts the DEK for a grantee.
  revoke      Invalidate a grant (checked on every access).
  rotate_key  Replace the user's keypair; re-encrypts all owned DEKs atomically.
  change_key  Alias for rotate_key with an explicit new keypair supplied by caller.
  permissions List all grants the caller owns (as patient) or has received (as grantee).
  inbox       Permissions granted TO the caller — their receivable access.

Data model is owned by VaultStore / schemas:
  VaultRecord      — file metadata (no ciphertext)
  CiphertextRecord — encrypted bytes + owner DEK bundle
  Grant            — cryptographically signed access permission
  VaultAuditEntry  — immutable audit trail
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from src.crypto.ecies import ecies_encrypt, ecies_decrypt, aes_gcm_encrypt, aes_gcm_decrypt
from src.crypto.key_manager import KeyManager
from src.crypto.signature_verifier import SignatureVerifier
from src.database.vault_store import VaultStore
from src.schemas import VaultRecord, CiphertextRecord, Grant

_km  = KeyManager()
_sv  = SignatureVerifier()
_now = lambda: datetime.now(timezone.utc).isoformat()


# ── Exceptions ────────────────────────────────────────────────────────────────

class VaultError(Exception):       pass
class AccessDenied(VaultError):    pass
class RecordNotFound(VaultError):  pass
class GrantNotFound(VaultError):   pass
class RevokedGrant(VaultError):    pass
class ExpiredGrant(VaultError):    pass


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class UploadResult:
    record_id:  str
    filename:   str
    size_bytes: int
    created_at: str

    def to_dict(self) -> dict: return asdict(self)


@dataclass
class DownloadResult:
    record_id:  str
    filename:   str
    mime_type:  str
    size_bytes: int
    plaintext:  bytes

    def to_dict(self) -> dict:
        d = asdict(self)
        d["plaintext"] = f"<{self.size_bytes} bytes>"
        return d


@dataclass
class GrantResult:
    grant_id:         str
    record_id:        str
    grantee_key_hash: str
    permission_level: str
    time_start:       str
    time_end:         str
    created_at:       str

    def to_dict(self) -> dict: return asdict(self)


@dataclass
class PermissionView:
    grant_id:         str
    record_id:        str
    filename:         str
    grantor_key_hash: str
    grantee_key_hash: str
    permission_level: str
    time_start:       str
    time_end:         str
    revoked:          bool
    revoked_at:       Optional[str]
    signature_valid:  bool
    time_valid:       bool
    created_at:       str

    def to_dict(self) -> dict: return asdict(self)


# ── Transceiver ───────────────────────────────────────────────────────────────

class Transceiver:
    """
    The CypherAegis file transceiver.

    Every method takes a caller_private_key_pem so the transceiver can
    derive the caller's public key hash on the fly — no session state needed.

    vault_path: path to the vault JSON ledger (passed to VaultStore).
    """

    def __init__(self, vault_path: Path):
        self._store = VaultStore(vault_path)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _caller_keys(self, private_key_pem: str) -> tuple[str, str]:
        """Return (public_key_hex, public_key_hash) for caller."""
        info = _km.get_public_key_from_private(private_key_pem)
        return info["public_key_hex"], info["public_key_hash"]

    def _decrypt_dek(self, private_key_pem: str, dek_bundle: dict) -> bytes:
        return ecies_decrypt(private_key_pem, dek_bundle)

    def _get_record(self, record_id: str) -> VaultRecord:
        rec = self._store.get_record(record_id)
        if not rec:
            raise RecordNotFound(f"Record {record_id} not found")
        return rec

    def _assert_owns(self, rec: VaultRecord, caller_key_hash: str):
        if rec.owner_key_hash != caller_key_hash:
            raise AccessDenied("You do not own this record")

    # ── upload ────────────────────────────────────────────────────────────────

    def upload(
        self,
        caller_private_key_pem: str,
        plaintext: bytes,
        filename: str,
        tags: list[str] | None = None,
    ) -> UploadResult:
        """
        Encrypt *plaintext* and store it in the vault.

        Flow:
          1. Derive caller's public key from their private key.
          2. Generate a fresh 256-bit DEK.
          3. AES-256-GCM encrypt the file with the DEK.
          4. ECIES-wrap the DEK under the caller's public key.
          5. Write VaultRecord + CiphertextRecord. DEK is discarded.
        """
        pub_hex, pub_hash = self._caller_keys(caller_private_key_pem)

        dek        = os.urandom(32)
        iv, ct     = aes_gcm_encrypt(dek, plaintext)
        dek_bundle = ecies_encrypt(pub_hex, dek)
        dek        = b"\x00" * 32

        mime, _ = mimetypes.guess_type(filename)
        record_id = str(uuid.uuid4())
        now       = _now()

        rec = VaultRecord(
            record_id=record_id,
            owner_key_hash=pub_hash,
            owner_public_key_hex=pub_hex,
            filename=filename,
            mime_type=mime or "application/octet-stream",
            size_bytes=len(plaintext),
            iv_hex=iv.hex(),
            created_at=now,
            tags=tags or [],
        )
        ct_rec = CiphertextRecord(
            record_id=record_id,
            ciphertext=ct,
            dek_bundle=dek_bundle,
        )

        self._store.save_record(rec, ct_rec)
        self._store.append_audit(
            action="UPLOAD",
            actor_key_hash=pub_hash,
            record_id=record_id,
            detail=f"filename={filename} size={len(plaintext)}",
        )

        return UploadResult(
            record_id=record_id,
            filename=filename,
            size_bytes=len(plaintext),
            created_at=now,
        )

    # ── download ──────────────────────────────────────────────────────────────

    def download(
        self,
        caller_private_key_pem: str,
        record_id: str,
    ) -> DownloadResult:
        """
        Decrypt and return a file the caller owns or has a valid grant for.

        Access path:
          - Owner   → decrypt DEK from CiphertextRecord.dek_bundle
          - Grantee → find a non-revoked, time-valid grant; decrypt DEK from
                      grant.dek_bundle_grantee; verify owner's ECDSA signature
        """
        pub_hex, pub_hash = self._caller_keys(caller_private_key_pem)
        rec = self._get_record(record_id)

        ct_rec = self._store.get_ciphertext(record_id)
        if not ct_rec:
            raise RecordNotFound(f"Ciphertext for record {record_id} not found")

        if rec.owner_key_hash == pub_hash:
            dek_bundle = ct_rec.dek_bundle
            self._store.append_audit(
                action="DOWNLOAD_OWNER",
                actor_key_hash=pub_hash,
                record_id=record_id,
            )
        else:
            grant = self._find_valid_grant(record_id, pub_hash, rec)
            dek_bundle = grant.dek_bundle_grantee
            self._store.append_audit(
                action="DOWNLOAD_GRANT",
                actor_key_hash=pub_hash,
                record_id=record_id,
                detail=f"grant_id={grant.grant_id}",
            )

        dek       = self._decrypt_dek(caller_private_key_pem, dek_bundle)
        plaintext = aes_gcm_decrypt(
            dek,
            bytes.fromhex(rec.iv_hex),
            ct_rec.ciphertext,
        )
        dek = b"\x00" * 32

        return DownloadResult(
            record_id=record_id,
            filename=rec.filename,
            mime_type=rec.mime_type,
            size_bytes=len(plaintext),
            plaintext=plaintext,
        )

    def _find_valid_grant(
        self, record_id: str, grantee_key_hash: str, rec: VaultRecord
    ) -> Grant:
        """Find the best active, signature-valid, time-valid grant."""
        now        = datetime.now(timezone.utc)
        candidates = self._store.list_active_grants_for_record(record_id, grantee_key_hash)

        if not candidates:
            raise AccessDenied("No active grant found for this record")

        for g in candidates:
            perm = _sv.create_permission_data(
                patient_id=g.grantor_key_hash,
                doctor_id=g.grantee_key_hash,
                record_id=g.record_id,
                time_start=datetime.fromisoformat(g.time_start),
                time_end=datetime.fromisoformat(g.time_end),
                permission_level=g.permission_level,
            )
            valid_sig, _ = _sv.verify_signature(
                rec.owner_public_key_hex, g.signature_hex, perm
            )
            if not valid_sig:
                continue

            time_valid, reason = _sv.is_permission_valid(perm, now)
            if not time_valid:
                if "expired" in reason.lower():
                    raise ExpiredGrant(reason)
                continue

            return g

        raise AccessDenied("No valid (signature + time) grant found")

    # ── grant ─────────────────────────────────────────────────────────────────

    def grant(
        self,
        owner_private_key_pem: str,
        record_id: str,
        grantee_public_key_hex: str,
        permission_level: str = "view_only",
        duration_hours: float = 24.0,
    ) -> GrantResult:
        """
        Grant a grantee access to a record.

        Flow:
          1. Verify caller owns the record.
          2. Decrypt the record's DEK using owner's private key.
          3. Re-encrypt DEK under the grantee's public key.
          4. Sign the permission payload with owner's private key.
          5. Persist the Grant. DEK is discarded.
        """
        if permission_level not in ("view_only", "view_download"):
            raise VaultError("permission_level must be 'view_only' or 'view_download'")

        owner_pub_hex, owner_key_hash = self._caller_keys(owner_private_key_pem)
        grantee_key_hash = hashlib.sha256(
            bytes.fromhex(grantee_public_key_hex)
        ).hexdigest()

        now        = datetime.now(timezone.utc)
        time_start = now
        time_end   = now + timedelta(hours=duration_hours)

        rec = self._get_record(record_id)
        self._assert_owns(rec, owner_key_hash)

        ct_rec = self._store.get_ciphertext(record_id)
        if not ct_rec:
            raise RecordNotFound(f"Ciphertext for record {record_id} not found")

        dek = self._decrypt_dek(owner_private_key_pem, ct_rec.dek_bundle)
        dek_bundle_grantee = ecies_encrypt(grantee_public_key_hex, dek)
        dek = b"\x00" * 32

        perm = _sv.create_permission_data(
            patient_id=owner_key_hash,
            doctor_id=grantee_key_hash,
            record_id=record_id,
            time_start=time_start,
            time_end=time_end,
            permission_level=permission_level,
        )
        sig_hex = _sv.sign_permission(owner_private_key_pem, perm)

        g = Grant(
            grant_id=str(uuid.uuid4()),
            record_id=record_id,
            grantor_key_hash=owner_key_hash,
            grantee_key_hash=grantee_key_hash,
            grantee_public_key_hex=grantee_public_key_hex,
            permission_level=permission_level,
            time_start=time_start.isoformat(),
            time_end=time_end.isoformat(),
            dek_bundle_grantee=dek_bundle_grantee,
            signature_hex=sig_hex,
            created_at=_now(),
        )
        self._store.save_grant(g)
        self._store.append_audit(
            action="GRANT_CREATED",
            actor_key_hash=owner_key_hash,
            record_id=record_id,
            detail=f"grant_id={g.grant_id} grantee={grantee_key_hash[:12]} level={permission_level}",
        )

        return GrantResult(
            grant_id=g.grant_id,
            record_id=record_id,
            grantee_key_hash=grantee_key_hash,
            permission_level=permission_level,
            time_start=time_start.isoformat(),
            time_end=time_end.isoformat(),
            created_at=g.created_at,
        )

    # ── revoke ────────────────────────────────────────────────────────────────

    def revoke(
        self,
        owner_private_key_pem: str,
        grant_id: str,
    ) -> dict:
        """
        Immediately revoke a grant. Only the record owner can revoke.
        The grant row is kept for audit with revoked=True.
        """
        _, owner_key_hash = self._caller_keys(owner_private_key_pem)

        g = self._store.get_grant(grant_id)
        if not g:
            raise GrantNotFound(f"Grant {grant_id} not found")
        if g.grantor_key_hash != owner_key_hash:
            raise AccessDenied("Only the record owner can revoke a grant")
        if g.revoked:
            return {"grant_id": grant_id, "status": "already_revoked"}

        revoked_at = _now()
        self._store.revoke_grant(grant_id, revoked_at)
        self._store.append_audit(
            action="GRANT_REVOKED",
            actor_key_hash=owner_key_hash,
            record_id=g.record_id,
            detail=f"grant_id={grant_id} grantee={g.grantee_key_hash[:12]}",
        )

        return {"grant_id": grant_id, "status": "revoked", "revoked_at": revoked_at}

    # ── rotate_key ────────────────────────────────────────────────────────────

    def rotate_key(
        self,
        old_private_key_pem: str,
        new_public_key_hex: str,
        new_private_key_pem: str,
    ) -> dict:
        """
        Replace the caller's keypair and re-wrap all owned DEKs under the new key.

        Atomic:
          1. Decrypt every owned record's DEK with the old private key.
          2. Re-encrypt each DEK under the new public key.
          3. Batch-update all records in one write.
          4. Revoke all outstanding grants (grantees must re-request).
        """
        _, old_key_hash = self._caller_keys(old_private_key_pem)
        _, new_key_hash = self._caller_keys(new_private_key_pem)

        records = self._store.list_records_by_owner(old_key_hash)
        if not records:
            return {"rotated_records": 0, "revoked_grants": 0, "new_key_hash": new_key_hash}

        new_dek_bundles: dict[str, dict] = {}
        for rec in records:
            ct_rec = self._store.get_ciphertext(rec.record_id)
            if not ct_rec:
                continue
            dek = ecies_decrypt(old_private_key_pem, ct_rec.dek_bundle)
            new_dek_bundles[rec.record_id] = ecies_encrypt(new_public_key_hex, dek)
            dek = b"\x00" * 32

        updated = self._store.batch_rotate_owner(
            old_owner_key_hash=old_key_hash,
            new_owner_key_hash=new_key_hash,
            new_owner_public_key_hex=new_public_key_hex,
            new_dek_bundles=new_dek_bundles,
        )

        record_ids = {r.record_id for r in records}
        revoked_at = _now()
        revoked    = self._store.revoke_all_grants_for_records(record_ids, revoked_at)

        self._store.append_audit(
            action="KEY_ROTATED",
            actor_key_hash=old_key_hash,
            detail=f"records={updated} grants_revoked={revoked} new_hash={new_key_hash[:12]}",
        )

        return {
            "rotated_records": updated,
            "revoked_grants":  revoked,
            "old_key_hash":    old_key_hash,
            "new_key_hash":    new_key_hash,
        }

    def change_key(
        self,
        old_private_key_pem: str,
        new_public_key_hex: str,
        new_private_key_pem: str,
    ) -> dict:
        """Alias for rotate_key — same operation, explicit name."""
        return self.rotate_key(old_private_key_pem, new_public_key_hex, new_private_key_pem)

    # ── permissions / inbox ───────────────────────────────────────────────────

    def permissions(
        self,
        caller_private_key_pem: str,
        as_owner: bool = True,
    ) -> list[PermissionView]:
        """
        List grants.
        as_owner=True  → grants the caller issued (outbox).
        as_owner=False → grants the caller received (inbox).
        """
        _, caller_key_hash = self._caller_keys(caller_private_key_pem)
        now    = datetime.now(timezone.utc)
        grants = (
            self._store.list_grants_by_grantor(caller_key_hash) if as_owner
            else self._store.list_grants_by_grantee(caller_key_hash)
        )

        results = []
        for g in grants:
            rec      = self._store.get_record(g.record_id)
            filename = rec.filename if rec else "<deleted>"

            perm = _sv.create_permission_data(
                patient_id=g.grantor_key_hash,
                doctor_id=g.grantee_key_hash,
                record_id=g.record_id,
                time_start=datetime.fromisoformat(g.time_start),
                time_end=datetime.fromisoformat(g.time_end),
                permission_level=g.permission_level,
            )

            if as_owner:
                sig_valid = True   # we are the signer
            else:
                try:
                    sig_valid, _ = _sv.verify_signature(
                        rec.owner_public_key_hex if rec else "", g.signature_hex, perm
                    )
                except Exception:
                    sig_valid = False

            time_valid, _ = _sv.is_permission_valid(perm, now)

            results.append(PermissionView(
                grant_id=g.grant_id,
                record_id=g.record_id,
                filename=filename,
                grantor_key_hash=g.grantor_key_hash,
                grantee_key_hash=g.grantee_key_hash,
                permission_level=g.permission_level,
                time_start=g.time_start,
                time_end=g.time_end,
                revoked=g.revoked,
                revoked_at=g.revoked_at,
                signature_valid=sig_valid,
                time_valid=time_valid,
                created_at=g.created_at,
            ))

        def _sort_key(p: PermissionView):
            if p.revoked:        return 2
            if not p.time_valid: return 1
            return 0

        results.sort(key=_sort_key)
        return results

    def inbox(self, caller_private_key_pem: str) -> list[PermissionView]:
        """Permissions granted TO the caller. Shorthand for permissions(as_owner=False)."""
        return self.permissions(caller_private_key_pem, as_owner=False)
