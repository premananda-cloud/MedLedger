"""
client/offline_client.py - Local-only operations when server is unreachable.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import OFFLINE_DIR
from core.crypto import encrypt_document, decrypt_document

QUEUE_FILE = OFFLINE_DIR / "queue.json"


def _load_queue() -> list:
    if not QUEUE_FILE.exists():
        return []
    try:
        return json.loads(QUEUE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

def _save_queue(q: list):
    QUEUE_FILE.write_text(json.dumps(q, indent=2), encoding="utf-8")

def _enqueue(op: str, payload: dict):
    q = _load_queue()
    q.append({"id": str(uuid.uuid4()), "operation": op,
               "payload": payload, "queued_at": datetime.utcnow().isoformat()})
    _save_queue(q)

def get_pending_queue() -> list:
    return _load_queue()

def clear_queue_item(item_id: str):
    _save_queue([q for q in _load_queue() if q["id"] != item_id])


class OfflineClient:

    def queue_register(
        self,
        username: str, email: str, full_name: str, role: str, password: str,
        public_key_hex: str, public_key_compressed: str, public_key_hash: str,
        temp_id: str,
    ):
        """Queue a registration to be replayed when server comes back.

        NOTE: The plaintext password is NOT written to the queue file.
        When the queue is replayed the orchestrator must re-prompt for the
        password, or pass it through in-memory only.
        """
        _enqueue("register", {
            "username":              username,
            "email":                 email,
            "full_name":             full_name,
            "role":                  role,
            # password intentionally omitted — never written to disk in plaintext
            "public_key_hex":        public_key_hex,
            "public_key_compressed": public_key_compressed,
            "public_key_hash":       public_key_hash,
            "temp_id":               temp_id,
        })

    def encrypt_and_store_local(
        self,
        file_bytes: bytes,
        original_filename: str,
        content_type: str,
        patient_id,
        public_key_hex: str,
        private_key_hex: str,          # ← hex, not PEM
    ) -> dict:
        """Encrypt and queue a file upload."""
        result    = encrypt_document(file_bytes, public_key_hex, private_key_hex)
        local_id  = str(uuid.uuid4())
        suffix    = Path(original_filename).suffix or ""
        blob_path = OFFLINE_DIR / f"{local_id}{suffix}.enc"
        dek_path  = OFFLINE_DIR / f"{local_id}.dek.json"

        blob_path.write_bytes(result["encrypted_blob"])
        dek_path.write_text(json.dumps(result["encrypted_dek"]), encoding="utf-8")

        meta = {
            "local_id":          local_id,
            "patient_id":        patient_id,
            "original_filename": original_filename,
            "content_type":      content_type,
            "content_hash":      result["content_hash"],
            "signature":         result["signature"],
            "blob_path":         str(blob_path),
            "dek_path":          str(dek_path),
            "created_at":        datetime.utcnow().isoformat(),
            "synced":            False,
        }
        _enqueue("upload", meta)
        return {"record_id": local_id, "offline": True, **meta}

    def decrypt_local(self, blob_path: str, dek_bundle, private_key_hex: str) -> bytes:
        return decrypt_document(Path(blob_path).read_bytes(), dek_bundle, private_key_hex)

    def list_local_records(self, patient_id) -> list:
        return [
            q["payload"] for q in _load_queue()
            if q["operation"] == "upload"
            and str(q["payload"].get("patient_id")) == str(patient_id)
        ]
