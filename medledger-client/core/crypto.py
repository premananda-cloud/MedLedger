"""
core/crypto.py - All cryptographic operations for MedLedger client.

Handles:
  - EC keypair generation (P-256)
  - ECIES encrypt/decrypt  (DEK wrapping)
  - AES-256-GCM encrypt/decrypt (file content)
  - ECDSA sign / verify    (document hash signing)
  - SHA-256 hashing
"""

import os
import json
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

_CURVE     = ec.SECP256R1()
_BACKEND   = default_backend()
_HKDF_INFO = b"MedLedger-DEK-v1"


# ══════════════════════════════════════════════════════════════════════════════
# Keypair generation
# ══════════════════════════════════════════════════════════════════════════════

class KeyPair:
    def __init__(self, private_key, public_key):
        self._private = private_key
        self._public  = public_key

    @property
    def private_key_pem(self) -> str:
        return self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    @property
    def public_key_hex(self) -> str:
        """Uncompressed 65-byte public key as hex (matches server format)."""
        return self._public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        ).hex()

    @property
    def public_key_compressed(self) -> str:
        """Compressed 33-byte public key as hex."""
        return self._public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        ).hex()

    @property
    def public_key_hash(self) -> str:
        """SHA-256 of the uncompressed public key bytes — used as grantee ID."""
        raw = bytes.fromhex(self.public_key_hex)
        return hashlib.sha256(raw).hexdigest()


def generate_keypair() -> KeyPair:
    """Generate a fresh P-256 EC keypair."""
    private_key = ec.generate_private_key(_CURVE, _BACKEND)
    return KeyPair(private_key, private_key.public_key())


def load_keypair_from_pem(pem_text: str) -> KeyPair:
    """Reconstruct a KeyPair from a PEM private key string."""
    private_key = serialization.load_pem_private_key(
        pem_text.encode("utf-8"), password=None, backend=_BACKEND
    )
    return KeyPair(private_key, private_key.public_key())


def get_public_key_hex_from_pem(pem_text: str) -> str:
    kp = load_keypair_from_pem(pem_text)
    return kp.public_key_hex


# ══════════════════════════════════════════════════════════════════════════════
# Hashing
# ══════════════════════════════════════════════════════════════════════════════

def sha256_file(data: bytes) -> str:
    """Return hex SHA-256 of raw file bytes (plaintext, before encryption)."""
    return hashlib.sha256(data).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# AES-256-GCM  — file content encryption
# ══════════════════════════════════════════════════════════════════════════════

def generate_dek() -> bytes:
    """Generate a random 256-bit Data Encryption Key."""
    return os.urandom(32)


def aes_gcm_encrypt(dek: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with dek using AES-256-GCM.
    Returns: IV (12 bytes) + ciphertext + GCM tag (16 bytes) — all concatenated.
    The first 12 bytes of the result are always the IV.
    """
    iv     = os.urandom(12)
    aesgcm = AESGCM(dek)
    ct     = aesgcm.encrypt(iv, plaintext, None)   # ct includes 16-byte tag
    return iv + ct


def aes_gcm_decrypt(dek: bytes, blob: bytes) -> bytes:
    """
    Decrypt blob produced by aes_gcm_encrypt().
    blob = IV (12 bytes) + ciphertext+tag
    Raises ValueError on authentication failure.
    """
    iv  = blob[:12]
    ct  = blob[12:]
    try:
        return AESGCM(dek).decrypt(iv, ct, None)
    except Exception as exc:
        raise ValueError(f"AES-GCM decryption failed: {exc}") from exc


# ══════════════════════════════════════════════════════════════════════════════
# ECIES  — DEK wrapping / unwrapping with EC public/private keys
# ══════════════════════════════════════════════════════════════════════════════

def ecies_encrypt(recipient_public_key_hex: str, plaintext: bytes) -> dict:
    """
    Wrap plaintext (a DEK) for recipient_public_key_hex using ECIES.
    Returns a JSON-serialisable dict:
      { "epk": hex, "iv": hex, "ct": hex, "tag": hex }
    """
    recipient_pub = _load_public_key_hex(recipient_public_key_hex)

    eph_private = ec.generate_private_key(_CURVE, _BACKEND)
    eph_public  = eph_private.public_key()

    shared_secret = eph_private.exchange(ec.ECDH(), recipient_pub)
    aes_key       = _hkdf(shared_secret)

    iv         = os.urandom(12)
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    ct_body    = ciphertext[:-16]
    tag        = ciphertext[-16:]

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


def ecies_decrypt(recipient_private_key_pem: str, bundle) -> bytes:
    """
    Unwrap an ECIES bundle (dict or JSON string) using the recipient's private key.
    Returns the original plaintext bytes (the DEK).
    Raises ValueError on any failure.
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

    recipient_priv = serialization.load_pem_private_key(
        recipient_private_key_pem.encode("utf-8"), password=None, backend=_BACKEND
    )
    eph_public = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, epk_bytes)

    shared_secret = recipient_priv.exchange(ec.ECDH(), eph_public)
    aes_key       = _hkdf(shared_secret)

    try:
        return AESGCM(aes_key).decrypt(iv, ct_body + tag, None)
    except Exception as exc:
        raise ValueError(f"ECIES decryption failed (wrong key or tampered data): {exc}") from exc


# ══════════════════════════════════════════════════════════════════════════════
# ECDSA  — document hash signing / verification
# ══════════════════════════════════════════════════════════════════════════════

def sign_hash(private_key_pem: str, data_hash_hex: str) -> str:
    """
    Sign a SHA-256 hash with the patient's private key.
    Returns DER signature as hex string.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None, backend=_BACKEND
    )
    sig = private_key.sign(
        bytes.fromhex(data_hash_hex),
        ec.ECDSA(hashes.SHA256()),
    )
    return sig.hex()


def sign_permission_payload(private_key_pem: str, payload: dict) -> str:
    """
    Sign a permission payload dict exactly as the server reconstructs it:
      json.dumps(payload, sort_keys=True, separators=(',', ':'))
    then ECDSA-P256 sign the raw UTF-8 bytes (the library SHA-256s internally).

    Returns DER signature as hex string.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None, backend=_BACKEND
    )
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    return sig.hex()


def verify_signature(public_key_hex: str, data_hash_hex: str, signature_hex: str) -> bool:
    """
    Verify an ECDSA signature.
    Returns True if valid, False otherwise.
    """
    try:
        pub = _load_public_key_hex(public_key_hex)
        pub.verify(
            bytes.fromhex(signature_hex),
            bytes.fromhex(data_hash_hex),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Full document encryption pipeline
# ══════════════════════════════════════════════════════════════════════════════

def encrypt_document(
    file_bytes: bytes,
    patient_public_key_hex: str,
    patient_private_key_pem: str,
) -> dict:
    """
    Complete pipeline:
      1. SHA-256 hash of plaintext
      2. Sign hash with patient private key
      3. Generate DEK
      4. AES-GCM encrypt file with DEK
      5. ECIES wrap DEK with patient public key

    Returns dict with everything needed to send to server:
      {
        "content_hash":    hex string  (SHA-256 of original plaintext),
        "signature":       hex string  (ECDSA signature over content_hash),
        "encrypted_blob":  bytes       (IV + AES-GCM ciphertext+tag),
        "encrypted_dek":   dict        (ECIES bundle, DEK wrapped for patient),
      }
    """
    content_hash  = sha256_file(file_bytes)
    signature     = sign_hash(patient_private_key_pem, content_hash)
    dek           = generate_dek()
    encrypted_blob = aes_gcm_encrypt(dek, file_bytes)
    encrypted_dek  = ecies_encrypt(patient_public_key_hex, dek)

    return {
        "content_hash":   content_hash,
        "signature":      signature,
        "encrypted_blob": encrypted_blob,
        "encrypted_dek":  encrypted_dek,
    }


def decrypt_document(
    encrypted_blob: bytes,
    encrypted_dek_bundle,
    private_key_pem: str,
) -> bytes:
    """
    Reverse pipeline:
      1. ECIES unwrap DEK using private key
      2. AES-GCM decrypt blob using DEK
    Returns original plaintext bytes.
    """
    dek = ecies_decrypt(private_key_pem, encrypted_dek_bundle)
    return aes_gcm_decrypt(dek, encrypted_blob)


def rewrap_dek_for_doctor(
    encrypted_dek_bundle,
    patient_private_key_pem: str,
    doctor_public_key_hex: str,
) -> dict:
    """
    Patient re-wraps a DEK for a doctor:
      1. Decrypt DEK with patient private key
      2. Re-encrypt DEK with doctor's public key
    Returns new ECIES bundle (dict) for doctor.
    """
    dek = ecies_decrypt(patient_private_key_pem, encrypted_dek_bundle)
    return ecies_encrypt(doctor_public_key_hex, dek)


# ══════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ══════════════════════════════════════════════════════════════════════════════

def _hkdf(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
        backend=_BACKEND,
    ).derive(shared_secret)


def _load_public_key_hex(hex_str: str) -> ec.EllipticCurvePublicKey:
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, bytes.fromhex(hex_str))
    except Exception as exc:
        raise ValueError(f"Invalid public key hex: {exc}") from exc
