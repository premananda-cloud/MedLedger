"""
core/orchestrator.py - Central application logic.

Simplified flow:
  Register  → generate private key hex → save to local SQLite DB → send public key to server
  Login     → look up user in local DB by email → verify password with server (or offline) → load key
  Upload    → encrypt with private key hex → send to server (or queue offline)
  Download  → fetch from server → decrypt with private key hex

No passphrase.  No PEM.  No encrypted key files.
The private key hex lives in the local SQLite DB (medledger.db).
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Callable

from config import OFFLINE_DIR
from core.crypto import (
    generate_private_key_hex,
    derive_public_key_hex,
    derive_public_key_compressed,
    derive_public_key_hash,
    encrypt_document,
    decrypt_document,
    rewrap_dek_for_doctor,
    sha256_file,
    sign_permission_payload,
)
from core.keystore import (
    save_user, load_user, find_user_by_email, update_token,
    load_private_key_hex, key_exists,
    set_active_session, get_active_session, clear_session, load_session,
)
from client.api_client import APIClient
from client.offline_client import OfflineClient


class Orchestrator:
    """
    Single instance shared across the whole app.
    Holds current session state and routes calls to API or offline.
    """

    def __init__(self):
        self.api     = APIClient()
        self.offline = OfflineClient()

        # Current session (populated after login/register)
        self.user_id:         Optional[str]  = None
        self.token:           Optional[str]  = None
        self.role:            Optional[str]  = None
        self.username:        Optional[str]  = None
        self.full_name:       Optional[str]  = None
        self.email:           Optional[str]  = None
        self.public_key_hex:  Optional[str]  = None
        self.public_key_hash: Optional[str]  = None
        self.is_online:       bool           = False

        # Private key hex in memory (cleared on logout)
        self._private_key_hex: Optional[str] = None

        # Restore last active session on startup
        self._restore_session()

    # ── Internal ─────────────────────────────────────────────────────────────

    def _check_online(self) -> bool:
        self.is_online = self.api.is_server_available()
        return self.is_online

    def _restore_session(self):
        """Re-hydrate state from the local DB without loading the private key."""
        row = load_session()
        if not row:
            return
        self.user_id         = row.get("user_id")
        self.token           = row.get("token")
        self.role            = (row.get("role") or "").lower() or None
        self.username        = row.get("username")
        self.full_name       = row.get("full_name")
        self.email           = row.get("email")
        self.public_key_hex  = row.get("public_key_hex")
        self.public_key_hash = row.get("public_key_hash")
        if self.token:
            self.api.set_token(self.token)

    def _load_private_key(self, password: str):
        """Decrypt and load private key hex from DB into memory."""
        if not self.user_id:
            raise RuntimeError("Not logged in.")
        self._private_key_hex = load_private_key_hex(self.user_id, password)

    def _get_private_key(self) -> str:
        if not self._private_key_hex:
            raise RuntimeError(
                "Private key not loaded. Please log in again."
            )
        return self._private_key_hex

    @property
    def is_logged_in(self) -> bool:
        return (
            self.user_id is not None
            and self._private_key_hex is not None
        )

    @property
    def is_patient(self) -> bool:
        return self.role == "patient"

    @property
    def is_doctor(self) -> bool:
        return self.role == "doctor"

    # ══════════════════════════════════════════════════════════════════════════
    # 1. REGISTER
    # ══════════════════════════════════════════════════════════════════════════

    def register(
        self,
        username: str,
        email: str,
        full_name: str,
        role: str,
        password: str,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> dict:
        """
        Generate private key hex locally, save to SQLite, register with server.
        """
        def progress(msg):
            if on_progress:
                on_progress(msg)

        progress("Generating encryption keypair…")
        priv_hex   = generate_private_key_hex()
        pub_hex    = derive_public_key_hex(priv_hex)
        pub_comp   = derive_public_key_compressed(priv_hex)
        pub_hash   = derive_public_key_hash(priv_hex)

        if self._check_online():
            progress("Sending registration to server…")
            try:
                result = self.api.register(
                    username=username,
                    email=email,
                    full_name=full_name,
                    role=role,
                    password=password,
                    public_key_hex=pub_hex,
                    public_key_compressed=pub_comp,
                    public_key_hash=pub_hash,
                )
                user_id = str(result["user_id"])
                token   = result.get("access_token")

                progress("Saving private key to local database…")
                save_user(
                    user_id=user_id,
                    username=username,
                    email=email,
                    full_name=full_name,
                    role=role.lower(),
                    private_key_hex=priv_hex,
                    public_key_hex=pub_hex,
                    public_key_hash=pub_hash,
                    password=password,
                    token=token,
                    created_at=datetime.utcnow().isoformat(),
                )
                set_active_session(user_id)
                self.api.set_token(token)

                self._private_key_hex = priv_hex
                self.user_id         = user_id
                self.token           = token
                self.role            = role.lower()
                self.username        = username
                self.full_name       = full_name
                self.email           = email
                self.public_key_hex  = pub_hex
                self.public_key_hash = pub_hash

                progress("Registration complete ✓")
                return {**result, "offline": False, "private_key_hex": priv_hex}

            except Exception as exc:
                progress(f"Server error: {exc} — saving offline…")

        # ── Offline fallback ──────────────────────────────────────────────────
        progress("Server unavailable — saving registration locally…")
        offline_id = f"offline_{uuid.uuid4().hex[:8]}"

        save_user(
            user_id=offline_id,
            username=username,
            email=email,
            full_name=full_name,
            role=role.lower(),
            private_key_hex=priv_hex,
            public_key_hex=pub_hex,
            public_key_hash=pub_hash,
            password=password,
            token=None,
            created_at=datetime.utcnow().isoformat(),
        )
        set_active_session(offline_id)

        self._private_key_hex = priv_hex
        self.user_id         = offline_id
        self.token           = None
        self.role            = role.lower()
        self.username        = username
        self.full_name       = full_name
        self.email           = email
        self.public_key_hex  = pub_hex
        self.public_key_hash = pub_hash

        # Queue for later sync
        self.offline.queue_register(
            username=username, email=email, full_name=full_name,
            role=role, password=password,
            public_key_hex=pub_hex,
            public_key_compressed=pub_comp,
            public_key_hash=pub_hash,
            temp_id=offline_id,
        )

        progress("Registration queued — will sync when online ✓")
        return {
            "user_id": offline_id, "username": username, "email": email,
            "full_name": full_name, "role": role,
            "public_key_hex": pub_hex, "public_key_hash": pub_hash,
            "private_key_hex": priv_hex,
            "offline": True,
            "note": "Registration queued — will sync when server is available",
        }

    # ══════════════════════════════════════════════════════════════════════════
    # 2. LOGIN
    # ══════════════════════════════════════════════════════════════════════════

    def login(self, email: str, password: str,
              on_progress: Optional[Callable[[str], None]] = None) -> dict:
        """
        Verify credentials, load private key from local DB into memory.
        No passphrase needed — the key is read directly from SQLite.
        """
        def progress(msg):
            if on_progress:
                on_progress(msg)

        # Check local DB first — do we know this user?
        local = find_user_by_email(email)

        if not self._check_online():
            # Offline: verify we have a local record
            if not local:
                raise ConnectionError(
                    "Cannot reach server and no local account found.\n"
                    "Please connect to the internet to log in for the first time."
                )
            progress("Server offline — loading local session…")
            self._hydrate_from_row(local)
            self._load_private_key(password)
            return {**local, "offline": True, "note": "Restored from local session"}

        # Online: authenticate with server
        progress("Authenticating with server…")
        result  = self.api.login(email=email, password=password)
        user_id = str(result["user_id"])
        token   = result["access_token"]

        if not local or local["user_id"] != user_id:
            # User might have registered on another device — we can't recover the key
            if not local:
                raise FileNotFoundError(
                    "Login succeeded on server but this device has no local key.\n"
                    "Register on this device or copy medledger.db from the original device."
                )

        # Update the token in the local DB (user_id may have changed from offline_xxx to int)
        if local and local["user_id"] != user_id:
            # Migrate offline id -> real server id
            progress("Syncing offline account to server id…")
            # Decrypt the private key from the old offline record, then re-encrypt
            # it under the new (confirmed) server user_id entry.
            from core.keystore import decrypt_private_key
            migrated_priv = decrypt_private_key(local["private_key_enc"], password)
            save_user(
                user_id=user_id,
                username=result["username"],
                email=email,
                full_name=result.get("full_name", local.get("full_name", "")),
                role=result["role"].lower(),
                private_key_hex=migrated_priv,
                public_key_hex=local["public_key_hex"],
                public_key_hash=local["public_key_hash"],
                password=password,
                token=token,
            )
        else:
            update_token(user_id, token)

        set_active_session(user_id)
        self.api.set_token(token)

        row = load_user(user_id) or local
        self._hydrate_from_row(row)
        self.token = token
        self.api.set_token(token)
        self._load_private_key(password)

        progress("Login successful ✓")
        return {**result, "offline": False}

    def _hydrate_from_row(self, row: dict):
        self.user_id         = row.get("user_id")
        self.token           = row.get("token")
        self.role            = (row.get("role") or "").lower() or None
        self.username        = row.get("username")
        self.full_name       = row.get("full_name")
        self.email           = row.get("email")
        self.public_key_hex  = row.get("public_key_hex")
        self.public_key_hash = row.get("public_key_hash")

    # ══════════════════════════════════════════════════════════════════════════
    # 3. UPLOAD FILE
    # ══════════════════════════════════════════════════════════════════════════

    def upload_file(
        self,
        file_path: str,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> dict:
        def progress(msg):
            if on_progress:
                on_progress(msg)

        if not self.is_logged_in:
            raise PermissionError("You must be logged in to upload files.")

        priv_hex     = self._get_private_key()
        path         = Path(file_path)
        content_type = _guess_content_type(path)

        progress(f"Reading {path.name}…")
        file_bytes = path.read_bytes()

        progress("Encrypting file…")
        result = encrypt_document(
            file_bytes=file_bytes,
            patient_pub_hex=self.public_key_hex,
            patient_priv_hex=priv_hex,
        )

        if self._check_online():
            progress("Uploading to server…")
            try:
                upload_result = self.api.upload_record(
                    encrypted_blob=result["encrypted_blob"],
                    original_filename=path.name,
                    content_type="application/octet-stream",
                    content_hash=result["content_hash"],
                    signature=result["signature"],
                    encrypted_dek=result["encrypted_dek"],
                )
                progress("Upload complete ✓")
                return {**upload_result, "offline": False}
            except Exception as exc:
                progress(f"Upload failed: {exc} — saving offline…")

        progress("Saving encrypted file locally…")
        offline_result = self.offline.encrypt_and_store_local(
            file_bytes=file_bytes,
            original_filename=path.name,
            content_type=content_type,
            patient_id=self.user_id,
            public_key_hex=self.public_key_hex,
            private_key_hex=priv_hex,
        )
        progress("File queued for upload ✓")
        return offline_result

    # ══════════════════════════════════════════════════════════════════════════
    # 4. LIST RECORDS
    # ══════════════════════════════════════════════════════════════════════════

    def list_records(self) -> list:
        if not self.is_logged_in:
            return []
        records = []
        if self._check_online():
            try:
                resp    = self.api.list_my_records()
                records = resp.get("records", [])
            except Exception:
                pass
        offline_records = self.offline.list_local_records(self.user_id)
        for rec in offline_records:
            rec["offline"] = True
        return records + offline_records

    # ══════════════════════════════════════════════════════════════════════════
    # 5. DOWNLOAD AND DECRYPT
    # ══════════════════════════════════════════════════════════════════════════

    def download_and_decrypt(
        self,
        record_id: str,
        save_path: str,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> str:
        def progress(msg):
            if on_progress:
                on_progress(msg)

        priv_hex = self._get_private_key()
        progress("Fetching encrypted record…")
        encrypted_blob, dek_bundle, _ = self.api.download_record(record_id)
        progress("Decrypting…")
        plaintext = decrypt_document(encrypted_blob, dek_bundle, priv_hex)
        progress(f"Saving to {save_path}…")
        Path(save_path).write_bytes(plaintext)
        progress("Done ✓")
        return save_path

    # ══════════════════════════════════════════════════════════════════════════
    # 6. GRANT DOCTOR ACCESS
    # ══════════════════════════════════════════════════════════════════════════

    def grant_doctor_access(
        self,
        record_id: str,
        doctor_id: int,
        time_window_hours: int = 24,
        permission_level: str = "view_only",
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> dict:
        def progress(msg):
            if on_progress:
                on_progress(msg)

        if not self.is_patient:
            raise PermissionError("Only patients can grant access.")
        if not self._check_online():
            raise ConnectionError("Must be online to grant doctor access.")

        priv_hex = self._get_private_key()

        progress("Fetching doctor's public key…")
        doctor_info       = self.api.get_user_public_key(doctor_id)
        doctor_pub_hex    = doctor_info["public_key_hex"]
        doctor_pub_hash   = doctor_info["public_key_hash"]

        progress("Fetching your encrypted DEK…")
        _, dek_bundle, _  = self.api.download_record(record_id)

        progress("Re-wrapping key for doctor…")
        doctor_dek = rewrap_dek_for_doctor(dek_bundle, priv_hex, doctor_pub_hex)

        progress("Signing permission…")
        valid_from  = datetime.now(timezone.utc)
        valid_until = valid_from + timedelta(hours=time_window_hours)
        payload = {
            "patient_id":              str(self.user_id),
            "grantee_public_key_hash": doctor_pub_hash,
            "record_id":               record_id,
            "valid_from":              valid_from.replace(tzinfo=None).isoformat(),
            "valid_until":             valid_until.replace(tzinfo=None).isoformat(),
            "permission_level":        permission_level,
        }
        sig_hex = sign_permission_payload(priv_hex, payload)

        progress("Submitting permission grant…")
        result = self.api.grant_permission(
            doctor_id=doctor_id,
            record_id=record_id,
            time_window_hours=time_window_hours,
            permission_level=permission_level,
            signature_hex=sig_hex,
            doctor_encrypted_dek=doctor_dek,
            valid_from=payload["valid_from"],    # send the exact timestamps that were signed
            valid_until=payload["valid_until"],
        )
        progress("Access granted ✓")
        return result

    # ══════════════════════════════════════════════════════════════════════════
    # 7. DOCTOR VIEW
    # ══════════════════════════════════════════════════════════════════════════

    def doctor_download_and_decrypt(
        self,
        record_id: str,
        patient_public_key_hex: str,
        save_path: str,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> str:
        def progress(msg):
            if on_progress:
                on_progress(msg)

        if not self.is_doctor:
            raise PermissionError("Only doctors can use this function.")

        priv_hex = self._get_private_key()
        progress("Verifying permission and fetching record…")
        encrypted_blob, dek_bundle, _ = self.api.doctor_view_record(
            record_id=record_id,
            patient_public_key_hex=patient_public_key_hex,
        )
        progress("Decrypting…")
        plaintext = decrypt_document(encrypted_blob, dek_bundle, priv_hex)
        progress(f"Saving to {save_path}…")
        Path(save_path).write_bytes(plaintext)
        progress("Done ✓")
        return save_path

    # ══════════════════════════════════════════════════════════════════════════
    # 8. REVOKE / PERMISSIONS
    # ══════════════════════════════════════════════════════════════════════════

    def revoke_permission(self, permission_id: str) -> dict:
        if not self.is_patient:
            raise PermissionError("Only patients can revoke permissions.")
        if not self._check_online():
            raise ConnectionError("Must be online to revoke permissions.")
        return self.api.revoke_permission(permission_id, self.user_id)

    def list_my_permissions(self) -> list:
        if not self._check_online():
            return []
        try:
            result = self.api.get_my_permissions(self.user_id)
            return result if isinstance(result, list) else result.get("permissions", [])
        except Exception:
            return []

    def get_user_public_key(self, user_id: int) -> dict:
        return self.api.get_user_public_key(user_id)

    # ══════════════════════════════════════════════════════════════════════════
    # 9. LOGOUT
    # ══════════════════════════════════════════════════════════════════════════

    def logout(self):
        clear_session()
        self._private_key_hex = None
        self.user_id = self.token = self.role = None
        self.username = self.full_name = self.email = None
        self.public_key_hex = self.public_key_hash = None
        self.api.set_token(None)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _guess_content_type(path: Path) -> str:
    return {
        ".pdf":   "application/pdf",
        ".jpg":   "image/jpeg",
        ".jpeg":  "image/jpeg",
        ".png":   "image/png",
        ".dcm":   "application/dicom",
        ".dicom": "application/dicom",
    }.get(path.suffix.lower(), "application/octet-stream")
