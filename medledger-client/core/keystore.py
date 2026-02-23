"""
core/keystore.py - Local key and session persistence.

Private key storage:
  - keys/<user_id>.key  — AES-256-GCM encrypted, PBKDF2-HMAC-SHA256 derived key
  - Legacy fallback: keys/<user_id>.pem  (plaintext, for existing dev keys)

Session storage:
  - keys/session.json  — user_id, token, role, public_key_hex, etc.

Passphrase notes:
  - The key passphrase is SEPARATE from the account password.
  - It is never sent to the server — only used to decrypt the local key file.
  - Wrong passphrase raises ValueError (AES-GCM tag mismatch).
"""

import json
import os
import hashlib
from pathlib import Path
from typing import Optional
from config import KEYS_DIR, SESSION_FILE
from core.crypto import load_keypair_from_pem, KeyPair


# ══════════════════════════════════════════════════════════════════════════════
# Encrypted private key storage
# ══════════════════════════════════════════════════════════════════════════════

_PBKDF2_ITERATIONS = 200_000
_PBKDF2_HASH       = "sha256"
_SALT_LEN          = 32
_IV_LEN            = 12


def save_private_key(user_id, pem_text: str, passphrase: str) -> Path:
    """
    Encrypt and save private key PEM to keys/<user_id>.key using:
      PBKDF2-HMAC-SHA256 (200k iters, random 32-byte salt) → 32-byte AES key
      AES-256-GCM (random 12-byte IV)

    File format (JSON):
      { "v": 1, "salt": hex, "iv": hex, "ct": hex, "tag": hex }

    Returns the path written.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt    = os.urandom(_SALT_LEN)
    iv      = os.urandom(_IV_LEN)
    aes_key = _derive_key(passphrase, salt)

    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, pem_text.encode("utf-8"), None)  # last 16 bytes = tag
    ct_body    = ciphertext[:-16]
    tag        = ciphertext[-16:]

    blob = {
        "v":    1,
        "salt": salt.hex(),
        "iv":   iv.hex(),
        "ct":   ct_body.hex(),
        "tag":  tag.hex(),
    }

    path = KEYS_DIR / f"{user_id}.key"
    path.write_text(json.dumps(blob), encoding="utf-8")
    return path


def load_private_key_pem(user_id, passphrase: str) -> str:
    """
    Decrypt and return the PEM for user_id.
    Raises FileNotFoundError if no key exists.
    Raises ValueError on wrong passphrase (GCM tag mismatch).
    Falls back to legacy plaintext .pem if no .key file found.
    """
    key_path = KEYS_DIR / f"{user_id}.key"
    if key_path.exists():
        return _decrypt_key_file(key_path, passphrase)

    # Legacy plaintext fallback
    pem_path = KEYS_DIR / f"{user_id}.pem"
    if pem_path.exists():
        return pem_path.read_text(encoding="utf-8")

    raise FileNotFoundError(
        f"No key file found for user {user_id}. "
        f"Expected: {key_path} or {pem_path}"
    )


def _decrypt_key_file(path: Path, passphrase: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    blob    = json.loads(path.read_text(encoding="utf-8"))
    salt    = bytes.fromhex(blob["salt"])
    iv      = bytes.fromhex(blob["iv"])
    ct_body = bytes.fromhex(blob["ct"])
    tag     = bytes.fromhex(blob["tag"])

    aes_key = _derive_key(passphrase, salt)
    try:
        plaintext = AESGCM(aes_key).decrypt(iv, ct_body + tag, None)
        return plaintext.decode("utf-8")
    except Exception:
        raise ValueError(
            "Wrong key passphrase (or corrupted key file). "
            "Please enter the passphrase you chose when you registered."
        )


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        _PBKDF2_HASH,
        passphrase.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=32,
    )


def load_keypair(user_id, passphrase: str) -> KeyPair:
    """Decrypt and reconstruct KeyPair. Raises on wrong passphrase."""
    pem = load_private_key_pem(user_id, passphrase)
    return load_keypair_from_pem(pem)


def key_exists(user_id) -> bool:
    return (KEYS_DIR / f"{user_id}.key").exists() or (KEYS_DIR / f"{user_id}.pem").exists()


def delete_private_key(user_id):
    """Remove key from disk (logout / account deletion)."""
    for suffix in (".key", ".pem"):
        path = KEYS_DIR / f"{user_id}{suffix}"
        if path.exists():
            path.unlink()


# ══════════════════════════════════════════════════════════════════════════════
# Session persistence  (survives app restart)
# ══════════════════════════════════════════════════════════════════════════════

def save_session(
    user_id: int,
    token: str,
    role: str,
    username: str,
    full_name: str,
    email: str,
    public_key_hex: str,
    public_key_hash: str,
):
    """Persist login session to disk so user stays logged in after restart."""
    data = {
        "user_id":         user_id,
        "token":           token,
        "role":            role,
        "username":        username,
        "full_name":       full_name,
        "email":           email,
        "public_key_hex":  public_key_hex,
        "public_key_hash": public_key_hash,
    }
    SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_session() -> Optional[dict]:
    """Load persisted session. Returns None if not found or corrupt."""
    if not SESSION_FILE.exists():
        return None
    try:
        return json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def clear_session():
    """Remove session file (logout)."""
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


def has_session() -> bool:
    return SESSION_FILE.exists()
