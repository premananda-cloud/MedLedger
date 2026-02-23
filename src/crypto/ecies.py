"""
ECIES - Elliptic Curve Integrated Encryption Scheme (P-256)
Location: src/crypto/ecies.py

Used to encrypt/decrypt the Data Encryption Key (DEK) with EC public/private keys.

How it works
────────────
encrypt(recipient_public_key_hex, dek_bytes):
    1. Generate a fresh ephemeral EC keypair (throwaway)
    2. ECDH: shared_secret = ephemeral_private * recipient_public
    3. HKDF-SHA256(shared_secret) → 32-byte AES key
    4. AES-256-GCM encrypt the DEK
    5. Return:  ephemeral_public_hex | iv_hex | ciphertext_hex | tag_hex
       packed as a single JSON-serialisable dict

decrypt(recipient_private_key_pem, ecies_bundle):
    1. Load ephemeral public key from bundle
    2. ECDH: shared_secret = recipient_private * ephemeral_public
    3. HKDF-SHA256(shared_secret) → same 32-byte AES key
    4. AES-256-GCM decrypt → original DEK bytes

Security properties
───────────────────
- Forward secrecy: ephemeral key is thrown away after each encrypt call
- Authenticated encryption: GCM tag prevents ciphertext tampering
- No padding oracle: AES-GCM is stream-mode
- Deterministic key derivation: HKDF with fixed info string
"""

import os
import json
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

_CURVE    = ec.SECP256R1()
_BACKEND  = default_backend()
_HKDF_INFO = b"MedLedger-DEK-v1"   # domain-separation constant


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def ecies_encrypt(recipient_public_key_hex: str, plaintext: bytes) -> dict:
    """
    Encrypt *plaintext* (typically a 32-byte DEK) for *recipient_public_key_hex*.

    Returns a dict:
        {
          "epk":  "<65-byte ephemeral public key, hex>",
          "iv":   "<12-byte GCM IV, hex>",
          "ct":   "<ciphertext, hex>",
          "tag":  "<16-byte GCM auth tag, hex>"
        }

    The dict is safe to JSON-serialise and store in the DB as text.
    """
    # 1. Parse recipient public key
    recipient_pub = _load_public_key_hex(recipient_public_key_hex)

    # 2. Generate ephemeral keypair
    eph_private = ec.generate_private_key(_CURVE, _BACKEND)
    eph_public  = eph_private.public_key()

    # 3. ECDH shared secret
    shared_secret = eph_private.exchange(ec.ECDH(), recipient_pub)

    # 4. Derive AES key via HKDF
    aes_key = _hkdf(shared_secret)

    # 5. AES-256-GCM encrypt
    iv         = os.urandom(12)
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)   # last 16 bytes = GCM tag
    ct_body    = ciphertext[:-16]
    tag        = ciphertext[-16:]

    # 6. Serialise ephemeral public key (uncompressed, 65 bytes)
    epk_bytes = eph_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    return {
        "epk": epk_bytes.hex(),
        "iv":  iv.hex(),
        "ct":  ct_body.hex(),
        "tag": tag.hex(),
    }


def ecies_decrypt(recipient_private_key_pem: str, bundle: dict) -> bytes:
    """
    Decrypt an ECIES bundle produced by ecies_encrypt().

    *bundle* is the dict (or a JSON string of it) returned by ecies_encrypt().
    Returns the original plaintext bytes (the DEK).

    Raises ValueError on any decryption failure (wrong key, tampered data, etc.)
    """
    if isinstance(bundle, str):
        bundle = json.loads(bundle)

    try:
        epk_bytes = bytes.fromhex(bundle["epk"])
        iv        = bytes.fromhex(bundle["iv"])
        ct_body   = bytes.fromhex(bundle["ct"])
        tag       = bytes.fromhex(bundle["tag"])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Malformed ECIES bundle: {exc}") from exc

    # 1. Load recipient private key
    try:
        recipient_priv = serialization.load_pem_private_key(
            recipient_private_key_pem.encode("utf-8"),
            password=None,
            backend=_BACKEND,
        )
    except Exception as exc:
        raise ValueError(f"Failed to load private key: {exc}") from exc

    # 2. Load ephemeral public key
    try:
        eph_public = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, epk_bytes)
    except Exception as exc:
        raise ValueError(f"Failed to load ephemeral public key: {exc}") from exc

    # 3. ECDH shared secret
    shared_secret = recipient_priv.exchange(ec.ECDH(), eph_public)

    # 4. Derive same AES key
    aes_key = _hkdf(shared_secret)

    # 5. AES-256-GCM decrypt (GCM tag appended back)
    try:
        aesgcm    = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ct_body + tag, None)
    except Exception as exc:
        raise ValueError(f"Decryption failed (wrong key or tampered data): {exc}") from exc

    return plaintext


# ──────────────────────────────────────────────────────────────────────────────
# File-level AES-256-GCM helpers (used by record_service to encrypt files)
# ──────────────────────────────────────────────────────────────────────────────

def aes_gcm_encrypt(dek: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with *dek* using AES-256-GCM.

    Returns (iv, ciphertext_with_tag).
    The IV is 12 random bytes. The ciphertext includes the 16-byte GCM tag
    appended at the end (standard AESGCM behaviour in the cryptography lib).
    """
    iv     = os.urandom(12)
    aesgcm = AESGCM(dek)
    ct     = aesgcm.encrypt(iv, plaintext, None)
    return iv, ct


def aes_gcm_decrypt(dek: bytes, iv: bytes, ciphertext_with_tag: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext produced by aes_gcm_encrypt().

    Raises ValueError on authentication failure.
    """
    try:
        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(iv, ciphertext_with_tag, None)
    except Exception as exc:
        raise ValueError(f"AES-GCM decryption failed: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _hkdf(shared_secret: bytes) -> bytes:
    """Derive a 256-bit AES key from an ECDH shared secret via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
        backend=_BACKEND,
    ).derive(shared_secret)


def _load_public_key_hex(hex_str: str) -> ec.EllipticCurvePublicKey:
    """Parse an uncompressed P-256 public key from its hex representation."""
    try:
        key_bytes = bytes.fromhex(hex_str)
        return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, key_bytes)
    except Exception as exc:
        raise ValueError(f"Invalid public key hex: {exc}") from exc
