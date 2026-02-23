"""
config.py - Central configuration for MedLedger Desktop Client.
"""

import os
from pathlib import Path

# ── Server ────────────────────────────────────────────────────────────────────
SERVER_URL = os.getenv("MEDLEDGER_SERVER", "http://localhost:8000")

# ── Local storage paths ───────────────────────────────────────────────────────
APP_DIR      = Path(__file__).parent
KEYS_DIR     = APP_DIR / "keys"           # SQLite DB lives here
OFFLINE_DIR  = APP_DIR / "offline_records"
SESSION_FILE = KEYS_DIR / "session.json"  # kept for compat, not used by new keystore

# ── Supported file types ──────────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = [
    ("PDF files",    "*.pdf"),
    ("JPEG images",  "*.jpg *.jpeg"),
    ("PNG images",   "*.png"),
    ("DICOM scans",  "*.dcm *.dicom"),
    ("All supported","*.pdf *.jpg *.jpeg *.png *.dcm *.dicom"),
]

# ── UI ────────────────────────────────────────────────────────────────────────
APP_TITLE   = "MedLedger"
APP_VERSION = "1.0.0-demo"
WINDOW_W    = 1100
WINDOW_H    = 700
THEME_COLOR = "#1a73e8"

# ── Timeouts ──────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT_S  = 10
CONNECT_TIMEOUT_S  = 3

# ── Crypto constants (informational) ─────────────────────────────────────────
DEK_SIZE_BYTES     = 32
GCM_IV_SIZE_BYTES  = 12
GCM_TAG_SIZE_BYTES = 16
EC_CURVE           = "secp256r1"

# Ensure dirs exist
KEYS_DIR.mkdir(exist_ok=True)
OFFLINE_DIR.mkdir(exist_ok=True)
