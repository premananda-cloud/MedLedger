"""
core/crypto.py - All cryptographic operations for MedLedger client.

SIMPLIFIED MODEL:
  - Private key is a raw 32-byte P-256 scalar stored as a 64-char hex string.
  - Public key is derived on the fly — never stored separately.
  - No PEM, no passphrase in the external API.

Public API:
  generate_private_key_hex()             -> str  (64 hex chars)
  derive_public_key_hex(priv_hex)        -> str  (130 hex chars, uncompressed 04...)
  derive_public_key_compressed(priv_hex) -> str  (66 hex chars)
  derive_public_key_hash(priv_hex)       -> str  (64 hex chars, SHA-256)

  encrypt_document(file_bytes, pub_hex, priv_hex)            -> dict
  decrypt_document(encrypted_blob, dek_bundle, priv_hex)     -> bytes
  rewrap_dek_for_doctor(bundle, patient_priv_hex, doc_pub)   -> dict
  sha256_file(data)                                          -> str
"""

import os
import json
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

_CURVE     = ec.SECP256R1()
_BACKEND   = default_backend()
_HKDF_INFO = b"MedLedger-DEK-v1"


# ── Private / public key helpers ──────────────────────────────────────────────

def generate_private_key_hex() -> str:
    """Generate a fresh P-256 private key; return the raw 32-byte scalar as 64 hex chars."""
    priv = ec.generate_private_key(_CURVE, _BACKEND)
    raw  = priv.private_numbers().private_value.to_bytes(32, "big")
    return raw.hex()


def _priv_hex_to_key(priv_hex: str):
    """64-char hex -> cryptography EllipticCurvePrivateKey."""
    return ec.derive_private_key(int(priv_hex, 16), _CURVE, _BACKEND)


def derive_public_key_hex(priv_hex: str) -> str:
    """Uncompressed 65-byte (130 hex char) public key."""
    return _priv_hex_to_key(priv_hex).public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ).hex()


def derive_public_key_compressed(priv_hex: str) -> str:
    """Compressed 33-byte (66 hex char) public key."""
    return _priv_hex_to_key(priv_hex).public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    ).hex()


def derive_public_key_hash(priv_hex: str) -> str:
    """SHA-256 of the uncompressed public key bytes — 64 hex chars."""
    return hashlib.sha256(bytes.fromhex(derive_public_key_hex(priv_hex))).hexdigest()


def sha256_file(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def _aes_gcm_encrypt(dek: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + AESGCM(dek).encrypt(iv, plaintext, None)


def _aes_gcm_decrypt(dek: bytes, blob: bytes) -> bytes:
    try:
        return AESGCM(dek).decrypt(blob[:12], blob[12:], None)
    except Exception as exc:
        raise ValueError(f"AES-GCM decryption failed: {exc}") from exc


# ── ECIES ─────────────────────────────────────────────────────────────────────

def _load_pub_hex(hex_str: str):
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, bytes.fromhex(hex_str))


def _hkdf(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=_HKDF_INFO, backend=_BACKEND).derive(shared)


def ecies_encrypt(recipient_pub_hex: str, plaintext: bytes) -> dict:
    """Wrap DEK for recipient. Returns {epk, iv, ct, tag}."""
    eph      = ec.generate_private_key(_CURVE, _BACKEND)
    shared   = eph.exchange(ec.ECDH(), _load_pub_hex(recipient_pub_hex))
    aes_key  = _hkdf(shared)
    iv       = os.urandom(12)
    ct_full  = AESGCM(aes_key).encrypt(iv, plaintext, None)
    return {
        "epk": eph.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex(),
        "iv":  iv.hex(),
        "ct":  ct_full[:-16].hex(),
        "tag": ct_full[-16:].hex(),
    }


def ecies_decrypt(priv_hex: str, bundle) -> bytes:
    """Unwrap ECIES bundle using private key hex. Returns DEK bytes."""
    if isinstance(bundle, str):
        bundle = json.loads(bundle)
    try:
        epk   = bytes.fromhex(bundle["epk"])
        iv    = bytes.fromhex(bundle["iv"])
        ct    = bytes.fromhex(bundle["ct"])
        tag   = bytes.fromhex(bundle["tag"])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Malformed ECIES bundle: {exc}") from exc
    shared  = _priv_hex_to_key(priv_hex).exchange(
        ec.ECDH(),
        ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, epk),
    )
    try:
        return AESGCM(_hkdf(shared)).decrypt(iv, ct + tag, None)
    except Exception as exc:
        raise ValueError(f"ECIES decryption failed: {exc}") from exc


# ── ECDSA ─────────────────────────────────────────────────────────────────────

def sign_hash(priv_hex: str, data_hash_hex: str) -> str:
    """Sign a SHA-256 hash. Returns DER signature as hex."""
    return _priv_hex_to_key(priv_hex).sign(
        bytes.fromhex(data_hash_hex), ec.ECDSA(hashes.SHA256())
    ).hex()


def sign_permission_payload(priv_hex: str, payload: dict) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _priv_hex_to_key(priv_hex).sign(data, ec.ECDSA(hashes.SHA256())).hex()


# ── Document pipeline ─────────────────────────────────────────────────────────

def encrypt_document(file_bytes: bytes, patient_pub_hex: str, patient_priv_hex: str) -> dict:
    content_hash   = sha256_file(file_bytes)
    signature      = sign_hash(patient_priv_hex, content_hash)
    dek            = os.urandom(32)
    encrypted_blob = _aes_gcm_encrypt(dek, file_bytes)
    encrypted_dek  = ecies_encrypt(patient_pub_hex, dek)
    return {
        "content_hash":   content_hash,
        "signature":      signature,
        "encrypted_blob": encrypted_blob,
        "encrypted_dek":  encrypted_dek,
    }


def decrypt_document(encrypted_blob: bytes, encrypted_dek_bundle, priv_hex: str) -> bytes:
    dek = ecies_decrypt(priv_hex, encrypted_dek_bundle)
    return _aes_gcm_decrypt(dek, encrypted_blob)


def rewrap_dek_for_doctor(encrypted_dek_bundle, patient_priv_hex: str,
                          doctor_pub_hex: str) -> dict:
    dek = ecies_decrypt(patient_priv_hex, encrypted_dek_bundle)
    return ecies_encrypt(doctor_pub_hex, dek)
