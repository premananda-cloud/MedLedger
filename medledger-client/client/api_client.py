"""
client/api_client.py - HTTP calls to the MedLedger FastAPI backend.

Every method raises requests.exceptions.RequestException on network failure
so the orchestrator can catch and fall back to offline mode.

TLS: all requests verify the server certificate by default (requests default).
     Set MEDLEDGER_TLS_VERIFY=0 only in isolated local dev environments —
     never in staging or production.
"""

import json
import logging
import os
import requests
from typing import Optional
from config import SERVER_URL, CONNECT_TIMEOUT_S, REQUEST_TIMEOUT_S

logger = logging.getLogger(__name__)

# Verify TLS certs unless explicitly disabled for local dev.
# Acceptable values: "0" / "false" to disable; anything else = verify.
_tls_verify_env = os.getenv("MEDLEDGER_TLS_VERIFY", "1").strip().lower()
_TLS_VERIFY: bool = _tls_verify_env not in ("0", "false", "no")
if not _TLS_VERIFY:
    logger.warning(
        "TLS certificate verification is DISABLED (MEDLEDGER_TLS_VERIFY=0). "
        "This must never be used outside a local dev environment."
    )


class APIClient:

    def __init__(self, token: Optional[str] = None):
        self.base  = SERVER_URL.rstrip("/")
        self.token = token
        self.session = requests.Session()
        self.session.verify = _TLS_VERIFY   # enforce cert verification by default

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def set_token(self, token: str):
        self.token = token

    # ── Connectivity ──────────────────────────────────────────────────────────

    def is_server_available(self) -> bool:
        """Quick check — returns True if server responds within CONNECT_TIMEOUT_S."""
        try:
            r = self.session.get(
                f"{self.base}/api/auth/health",
                timeout=CONNECT_TIMEOUT_S,
            )
            return r.status_code == 200
        except Exception:
            return False

    # ── Auth ──────────────────────────────────────────────────────────────────

    def register(
        self,
        username: str,
        email: str,
        full_name: str,
        role: str,           # "patient" or "doctor"
        password: str,
        public_key_hex: str,
        public_key_compressed: str,
        public_key_hash: str,
    ) -> dict:
        """
        Register a new user. Returns server response including user_id.
        NOTE: We generate the keypair client-side; we only send the PUBLIC key.
        """
        payload = {
            "username":             username,
            "email":                email,
            "full_name":            full_name,
            "role":                 role,
            "password":             password,
            "public_key_hex":       public_key_hex,
            "public_key_compressed": public_key_compressed,
            "public_key_hash":      public_key_hash,
        }
        r = self.session.post(
            f"{self.base}/api/auth/register",
            json=payload,
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    def login(self, email: str, password: str) -> dict:
        """Login and return token + user info."""
        payload = {"email": email, "password": password}
        r = self.session.post(
            f"{self.base}/api/auth/login",
            json=payload,
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    def get_profile(self) -> dict:
        r = self.session.get(
            f"{self.base}/api/auth/me",
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    # ── Records ───────────────────────────────────────────────────────────────

    def upload_record(
        self,
        encrypted_blob: bytes,
        original_filename: str,
        content_type: str,
        content_hash: str,
        signature: str,
        encrypted_dek: dict,          # ECIES bundle as dict
        patient_id: Optional[int] = None,
    ) -> dict:
        """
        Upload an encrypted medical record.
        Sends multipart form:  file (encrypted blob) + metadata fields.
        """
        files   = {"file": (original_filename, encrypted_blob, "application/octet-stream")}
        data    = {
            "content_hash":  content_hash,
            "signature":     signature,
            "encrypted_dek": json.dumps(encrypted_dek),
        }
        if patient_id is not None:
            data["patient_id"] = str(patient_id)

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        r = self.session.post(
            f"{self.base}/records/upload",
            files=files,
            data=data,
            headers=headers,
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    def list_my_records(self) -> dict:
        r = self.session.get(
            f"{self.base}/records/my",
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    def download_record(self, record_id: str) -> tuple:
        """
        Download encrypted blob for patient.
        Returns (encrypted_blob: bytes, dek_bundle: dict, content_type: str)
        """
        r = self.session.get(
            f"{self.base}/records/{record_id}",
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        dek_bundle   = json.loads(r.headers.get("X-DEK-Bundle", "{}"))
        content_type = r.headers.get("X-Content-Type", "application/octet-stream")
        return r.content, dek_bundle, content_type

    def get_record_meta(self, record_id: str) -> dict:
        r = self.session.get(
            f"{self.base}/records/{record_id}/meta",
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    # ── Permissions ───────────────────────────────────────────────────────────

    def grant_permission(
        self,
        doctor_id: int,
        record_id: str,
        time_window_hours: int,
        permission_level: str,
        signature_hex: str,                # ECDSA signature produced CLIENT-SIDE
        doctor_encrypted_dek: dict,
        valid_from: Optional[str] = None,  # ISO timestamp the client signed
        valid_until: Optional[str] = None, # ISO timestamp the client signed
    ) -> dict:
        """
        Submit a permission grant.
        Private key NEVER sent — only the signature over the canonical payload.
        patient_id is determined server-side from the JWT token.
        valid_from / valid_until must match exactly what the client signed.
        """
        payload = {
            "doctor_id":           str(doctor_id),
            "record_id":           record_id,
            "time_window_hours":   time_window_hours,
            "permission_level":    permission_level,
            "signature_hex":       signature_hex,
            "doctor_encrypted_dek": json.dumps(doctor_encrypted_dek),
        }
        if valid_from:
            payload["valid_from"] = valid_from
        if valid_until:
            payload["valid_until"] = valid_until
        r = self.session.post(
            f"{self.base}/permissions/grant",
            json=payload,
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    def revoke_permission(self, permission_id: str, patient_id: int) -> dict:
        payload = {"permission_id": permission_id, "patient_id": str(patient_id)}
        r = self.session.post(
            f"{self.base}/permissions/revoke",
            json=payload,
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    def get_my_permissions(self, patient_id: int) -> dict:
        r = self.session.get(
            f"{self.base}/permissions/patient/{patient_id}",
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()

    def doctor_view_record(
        self,
        record_id: str,
        patient_public_key_hex: str,
    ) -> tuple:
        """
        Doctor downloads a record they have permission to see.
        Returns (encrypted_blob: bytes, dek_bundle: dict, content_type: str)
        """
        payload = {"patient_public_key_hex": patient_public_key_hex}
        r = self.session.post(
            f"{self.base}/records/{record_id}/doctor-view",
            json=payload,
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        dek_bundle   = json.loads(r.headers.get("X-DEK-Bundle", "{}"))
        content_type = r.headers.get("X-Content-Type", "application/octet-stream")
        return r.content, dek_bundle, content_type

    def get_user_public_key(self, target_user_id: int) -> dict:
        """Fetch another user's public key (for doctor access grant flow)."""
        r = self.session.get(
            f"{self.base}/users/{target_user_id}/public-key",
            headers=self._headers(),
            timeout=REQUEST_TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()
