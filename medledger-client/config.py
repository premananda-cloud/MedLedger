"""
config.py - Central configuration for MedLedger Desktop Client
Edit SERVER_URL to point to your FastAPI backend.
"""

import os
from pathlib import Path

# ── Server ────────────────────────────────────────────────────────────────────
SERVER_URL = os.getenv("MEDLEDGER_SERVER", "http://localhost:8000")

# ── Local storage paths ───────────────────────────────────────────────────────
APP_DIR        = Path(__file__).parent
KEYS_DIR       = APP_DIR / "keys"          # PEM files live here
OFFLINE_DIR    = APP_DIR / "offline_records"  # Encrypted blobs when offline
SESSION_FILE   = APP_DIR / "keys" / "session.json"  # Persisted login session

# ── Crypto constants ──────────────────────────────────────────────────────────
DEK_SIZE_BYTES     = 32       # AES-256
GCM_IV_SIZE_BYTES  = 12
GCM_TAG_SIZE_BYTES = 16
EC_CURVE           = "secp256r1"   # P-256, matches server

# ── Supported file types ──────────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = [
    ("PDF files",        "*.pdf"),
    ("JPEG images",      "*.jpg *.jpeg"),
    ("PNG images",       "*.png"),
    ("DICOM scans",      "*.dcm *.dicom"),
    ("All supported",    "*.pdf *.jpg *.jpeg *.png *.dcm *.dicom"),
]

# ── UI ────────────────────────────────────────────────────────────────────────
APP_TITLE   = "MedLedger"
APP_VERSION = "1.0.0-hackathon"
WINDOW_W    = 1100
WINDOW_H    = 700
THEME_COLOR = "#1a73e8"   # Medical blue

# ── Timeouts ─────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT_S  = 10   # seconds before falling back to offline
CONNECT_TIMEOUT_S  = 3    # quick check for server availability

# Ensure dirs exist at import time
KEYS_DIR.mkdir(exist_ok=True)
OFFLINE_DIR.mkdir(exist_ok=True)
