"""
auth/ — Self-contained authentication workers.

Layer contract:
  ✓ Each module does its specific job and returns results
  ✓ External domain libraries are fine (pyotp, wholemail, disposable-email-domains)
  ✗ No database access
  ✗ No user context / user IDs
  ✗ No session storage

from auth import (
    EmailAuthModule,
    TOTPModule,
    POWModule,
    PasswordModule,
    # Models
    EmailSendResult, EmailValidationResult,
    TOTPSecret,
    POWChallenge, POWVerifyResult,
    PasswordHashResult, PasswordStrengthResult,
)
"""

from .email    import EmailAuthModule
from .totp     import TOTPModule
from .pow      import POWModule
from .password import PasswordModule

from .models import (
    EmailSendResult,
    EmailValidationResult,
    TOTPSecret,
    POWChallenge,
    POWVerifyResult,
    PasswordHashResult,
    PasswordStrengthResult,
)

__all__ = [
    # Modules
    "EmailAuthModule",
    "TOTPModule",
    "POWModule",
    "PasswordModule",
    # Models
    "EmailSendResult",
    "EmailValidationResult",
    "TOTPSecret",
    "POWChallenge",
    "POWVerifyResult",
    "PasswordHashResult",
    "PasswordStrengthResult",
]
