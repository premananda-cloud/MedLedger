"""
auth/ — Pure authentication domain logic.

Layer contract:
  ✓ Pure functions and classes only
  ✗ No database access
  ✗ No HTTP calls
  ✗ No file system access (except blocklist_path passed in by caller)
  ✗ No SMTP / external service clients
  ✗ No singletons / global state

Public surface
--------------
from auth import (
    # Services
    TOTPService,
    EmailVerification,
    PoWService,
    PasswordService,
    TokenService,

    # Models / result types
    TOTPConfig, TOTPVerifyResult,
    VerificationCode, EmailValidationResult,
    AuthChallenge, PoWVerifyResult,
    PasswordHash, PasswordValidationResult,
    TokenPayload, TokenVerifyResult,

    # Enums
    EmailStatus, PasswordStrength, PoWStatus,
)
"""

from .email_verification import EmailVerification
from .models import (
    AuthChallenge,
    EmailStatus,
    EmailValidationResult,
    PasswordHash,
    PasswordStrength,
    PasswordValidationResult,
    PoWStatus,
    PoWVerifyResult,
    TOTPConfig,
    TOTPVerifyResult,
    TokenPayload,
    TokenVerifyResult,
    VerificationCode,
)
from .password import PasswordService
from .pow import PoWService
from .token import TokenService
from .totp import TOTPService

__all__ = [
    # Services
    "TOTPService",
    "EmailVerification",
    "PoWService",
    "PasswordService",
    "TokenService",
    # Models
    "TOTPConfig",
    "TOTPVerifyResult",
    "VerificationCode",
    "EmailValidationResult",
    "AuthChallenge",
    "PoWVerifyResult",
    "PasswordHash",
    "PasswordValidationResult",
    "TokenPayload",
    "TokenVerifyResult",
    # Enums
    "EmailStatus",
    "PasswordStrength",
    "PoWStatus",
]
