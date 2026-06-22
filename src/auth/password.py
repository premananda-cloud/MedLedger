"""
auth/password.py — PasswordModule

Responsibility: hash passwords, verify them, and score their strength.

What it does:
  ✓ PBKDF2-SHA512 hashing with a random salt
  ✓ Timing-safe verification
  ✓ Strength scoring with actionable feedback

What it does NOT do:
  ✗ Store anything
  ✗ Know about users
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import List, Optional

from .models import PasswordHashResult, PasswordStrengthResult


_PROD_ITERATIONS = 600_000   # OWASP 2023
_TEST_ITERATIONS = 1_000
_KEY_LENGTH      = 64        # bytes → 512-bit key
_SALT_BYTES      = 16

_COMMON = frozenset({
    "password", "12345678", "qwerty123", "letmein123",
    "password123", "admin123", "welcome1", "monkey123",
})
_KEYBOARD = ("qwerty", "asdfgh", "zxcvbn", "123456", "qazwsx")


def _is_test() -> bool:
    return os.getenv("APP_ENV") == "test" or os.getenv("TESTING") == "true"


class PasswordModule:
    """
    Pure password hashing and validation.

    The orchestrator stores the returned PasswordHashResult fields
    (hash_hex, salt_hex, iterations) and passes them back on verification.

    Usage:
        module = PasswordModule()

        # Registration:
        strength = module.validate_strength("MyP@ssw0rd!")
        if not strength.valid:
            raise BadRequest(strength.issues)
        ph = module.hash_password("MyP@ssw0rd!")
        db.store(user_id, ph.hash_hex, ph.salt_hex, ph.iterations)

        # Login:
        row = db.fetch(user_id)
        ok = module.verify_password("MyP@ssw0rd!", row.hash_hex,
                                    row.salt_hex, row.iterations)
    """

    def __init__(self, min_length: int = 8, iterations: Optional[int] = None):
        self.min_length = min_length
        self.iterations = (
            iterations if iterations is not None
            else (_TEST_ITERATIONS if _is_test() else _PROD_ITERATIONS)
        )

    # ──────────────────────────────────────────
    # Hashing
    # ──────────────────────────────────────────

    def hash_password(self, password: str, salt: Optional[bytes] = None) -> PasswordHashResult:
        """
        Hash a password with PBKDF2-HMAC-SHA512.

        Args:
            password: Plain-text password.
            salt:     Raw bytes — generated if omitted.

        Returns:
            PasswordHashResult with hex-encoded hash and salt to store.
        """
        if salt is None:
            salt = secrets.token_bytes(_SALT_BYTES)
        elif isinstance(salt, str):
            salt = bytes.fromhex(salt)

        derived = hashlib.pbkdf2_hmac(
            "sha512",
            password.encode("utf-8"),
            salt,
            self.iterations,
            dklen=_KEY_LENGTH,
        )
        return PasswordHashResult(
            hash_hex=derived.hex(),
            salt_hex=salt.hex(),
            iterations=self.iterations,
        )

    # ──────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────

    def verify_password(
        self,
        password:   str,
        hash_hex:   str,
        salt_hex:   str,
        iterations: int,
    ) -> bool:
        """
        Timing-safe password verification.

        Always performs the full hash even for non-existent users.
        The caller should pass dummy values for missing accounts to prevent
        user-enumeration via timing.

        Args:
            password:   Submitted plain-text password.
            hash_hex:   Stored hash (hex).
            salt_hex:   Stored salt (hex).
            iterations: Iteration count used when the hash was created.
        """
        computed = hashlib.pbkdf2_hmac(
            "sha512",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            iterations,
            dklen=_KEY_LENGTH,
        )
        try:
            return hmac.compare_digest(computed, bytes.fromhex(hash_hex))
        except Exception:
            return False

    # ──────────────────────────────────────────
    # Strength validation
    # ──────────────────────────────────────────

    def validate_strength(self, password: str) -> PasswordStrengthResult:
        """
        Score password strength and return actionable feedback.

        Scoring (each criterion adds 1 point, max 5):
          1. Uppercase letter
          2. Lowercase letter
          3. Digit
          4. Special character
          5. Length ≥ 12

        Minimum to pass: score ≥ 3 AND length ≥ min_length.

        Returns:
            PasswordStrengthResult with valid, score, strength label, and
            a list of issues the user can act on.
        """
        issues: List[str] = []

        if not password:
            return PasswordStrengthResult(
                valid=False, score=0, strength="invalid",
                issues=["Password is required."],
            )

        if password.lower() in _COMMON:
            return PasswordStrengthResult(
                valid=False, score=0, strength="weak",
                issues=["This password is too common. Choose something more unique."],
            )

        if any(pat in password.lower() for pat in _KEYBOARD):
            issues.append("Avoid keyboard patterns (e.g. 'qwerty', '123456').")

        has_upper   = bool(re.search(r"[A-Z]", password))
        has_lower   = bool(re.search(r"[a-z]", password))
        has_digit   = bool(re.search(r"[0-9]", password))
        has_special = bool(re.search(r'[!@#$%^&*()\[\]{};:\'",.<>/?\\|`~\-_=+]', password))
        has_long    = len(password) >= 12

        if not has_upper:   issues.append("Add at least one uppercase letter.")
        if not has_lower:   issues.append("Add at least one lowercase letter.")
        if not has_digit:   issues.append("Add at least one number.")
        if not has_special: issues.append("Add at least one special character.")
        if len(password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters.")

        score = sum([has_upper, has_lower, has_digit, has_special, has_long])

        if   score >= 5 and len(password) >= 16: strength = "very_strong"
        elif score >= 4 and len(password) >= 12: strength = "strong"
        elif score >= 3 and len(password) >= 10: strength = "good"
        elif score >= 2 and len(password) >= self.min_length: strength = "fair"
        else: strength = "weak"

        valid = score >= 3 and len(password) >= self.min_length and not any(
            pat in password.lower() for pat in _KEYBOARD
        )

        return PasswordStrengthResult(
            valid=valid, score=score, strength=strength,
            issues=[i for i in issues if i],
        )
