# src/crypto/__init__.py
"""
Cryptographic Core Module for MedLedger
=======================================

Provides cryptographic operations for key management, threshold secret sharing,
recovery mechanisms, and ECDSA signature verification.

Modules:
- key_manager: ECDSA P-256 key generation, encryption/decryption, QR codes
- recovery_key_manager: Recovery key generation, fragment management for 3-of-5 recovery
- secret_sharing: Shamir's Secret Sharing (3-of-5) over GF(256)
- signature_verifier: Permission signing and verification using ECDSA P-256

Exported Classes:
- KeyManager, KeyPair, EncryptedKeyBackup
- RecoveryKeyManager, RecoveryKey, EncryptedFragment, FragmentLocation, RecoveryStatus, RecoveryAttempt
- ShamirSecretSharing, SecretShare, GaloisField
- SignatureVerifier

Exported Functions:
- compute_public_key_hash (from key_manager)
"""

from .key_manager import (
    KeyManager,
    KeyPair,
    EncryptedKeyBackup,
    compute_public_key_hash,
)

from .recovery_key_manager import (
    RecoveryKeyManager,
    RecoveryKey,
    EncryptedFragment,
    FragmentLocation,
    RecoveryStatus,
    RecoveryAttempt,
)

from .secret_sharing import (
    ShamirSecretSharing,
    SecretShare,
    GaloisField,
)

from .signature_verifier import (
    SignatureVerifier,
)

__all__ = [
    # key_manager
    "KeyManager",
    "KeyPair",
    "EncryptedKeyBackup",
    "compute_public_key_hash",

    # recovery_key_manager
    "RecoveryKeyManager",
    "RecoveryKey",
    "EncryptedFragment",
    "FragmentLocation",
    "RecoveryStatus",
    "RecoveryAttempt",

    # secret_sharing
    "ShamirSecretSharing",
    "SecretShare",
    "GaloisField",

    # signature_verifier
    "SignatureVerifier",
]