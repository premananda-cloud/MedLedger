"""
auth/password.py — Pure password hashing and strength validation.

Zero I/O. Depends only on stdlib (hashlib, secrets, re, hmac, os).

Responsibilities:
  • Validate password strength
  • Hash passwords with PBKDF2-SHA512
  • Verify a submitted password against a stored hash (timing-safe)

The caller (auth_service / user_service) is responsible for:
  • Persisting PasswordHash (hash_hex + salt_hex + iterations)
  • Choosing iteration count based on environment
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Optional

from .models import PasswordHash, PasswordStrength, PasswordValidationResult


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

_DEFAULT_ITERATIONS_PROD = 600_000   # OWASP 2023 recommendation
_DEFAULT_ITERATIONS_TEST = 1_000     # fast for test suites
_KEY_LENGTH              = 64        # bytes → 512-bit derived key
_MIN_SALT_BYTES          = 16

_COMMON_PASSWORDS = frozenset({
    "password", "12345678", "qwerty123", "letmein123",
    "password123", "admin123", "welcome1", "monkey123",
})

_KEYBOARD_PATTERNS = ("qwerty", "asdfgh", "zxcvbn", "123456", "qazwsx")


def _is_test_env() -> bool:
    return os.getenv("APP_ENV") == "test" or os.getenv("TESTING") == "true"


# ─────────────────────────────────────────────
# Service
# ─────────────────────────────────────────────

class PasswordService:
    """
    Pure password hashing and validation helper.

    Usage:
        svc = PasswordService()

        # Registration:
        result = svc.validate("MyP@ssw0rd!")
        if not result.valid:
            raise BadRequest(result.message)
        ph = svc.hash("MyP@ssw0rd!")
        db.store(user_id, ph.hash_hex, ph.salt_hex, ph.iterations)

        # Login:
        ph_stored = db.load(user_id)   # PasswordHash or plain fields
        ok = svc.verify("MyP@ssw0rd!", ph_stored.hash_hex,
                        ph_stored.salt_hex, ph_stored.iterations)
    """

    def __init__(
        self,
        min_length:  int           = 8,
        iterations:  Optional[int] = None,   # None → auto (test/prod)
        key_length:  int           = _KEY_LENGTH,
    ):
        self.min_length = min_length
        self.iterations = (
            iterations
            if iterations is not None
            else (_DEFAULT_ITERATIONS_TEST if _is_test_env() else _DEFAULT_ITERATIONS_PROD)
        )
        self.key_length = key_length

    # ──────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────

    def validate(self, password: str) -> PasswordValidationResult:
        """
        Score a password and decide whether it meets the minimum bar.

        Scoring criteria (each adds 1 point, max 5):
          1. Uppercase letter
          2. Lowercase letter
          3. Digit
          4. Special character
          5. Length ≥ 12

        Minimum to pass: score ≥ 3 AND len ≥ min_length.
        """
        if not password or not isinstance(password, str):
            return PasswordValidationResult(
                valid=False, message="Password is required",
                strength=0, strength_label=PasswordStrength.INVALID,
            )

        details = {
            "length":          len(password),
            "has_uppercase":   bool(re.search(r"[A-Z]", password)),
            "has_lowercase":   bool(re.search(r"[a-z]", password)),
            "has_digit":       bool(re.search(r"[0-9]", password)),
            "has_special":     bool(re.search(r'[!@#$%^&*()\[\]{};:\'",.<>/?\\|`~\-_=+]', password)),
            "has_length_bonus": len(password) >= 12,
        }
        score = sum([
            details["has_uppercase"],
            details["has_lowercase"],
            details["has_digit"],
            details["has_special"],
            details["has_length_bonus"],
        ])

        # Common / pattern checks (fail fast, don't reveal score)
        if password.lower() in _COMMON_PASSWORDS:
            return PasswordValidationResult(
                valid=False,
                message="This password is too common. Please choose a stronger one.",
                strength=score, strength_label=PasswordStrength.WEAK, details=details,
            )

        if any(pat in password.lower() for pat in _KEYBOARD_PATTERNS):
            label = PasswordStrength.WEAK
            meets = score >= 3 and len(password) >= self.min_length
            return PasswordValidationResult(
                valid=meets,
                message="Password contains a keyboard pattern." if meets else
                        f"Password must be at least {self.min_length} characters and meet 3 of 5 complexity criteria.",
                strength=score, strength_label=label, details=details,
            )

        # Strength label
        if   score >= 5 and len(password) >= 16: label = PasswordStrength.VERY_STRONG
        elif score >= 4 and len(password) >= 12: label = PasswordStrength.STRONG
        elif score >= 3 and len(password) >= 10: label = PasswordStrength.GOOD
        elif score >= 2 and len(password) >= self.min_length: label = PasswordStrength.FAIR
        elif len(password) >= self.min_length:   label = PasswordStrength.WEAK
        else:                                    label = PasswordStrength.INVALID

        meets = score >= 3 and len(password) >= self.min_length
        return PasswordValidationResult(
            valid=meets,
            message="Password is valid." if meets else
                    f"Password must be at least {self.min_length} characters and meet 3 of 5 complexity criteria.",
            strength=score, strength_label=label, details=details,
        )

    # ──────────────────────────────────────────
    # Hashing
    # ──────────────────────────────────────────

    def hash(
        self,
        password: str,
        salt:     Optional[bytes] = None,
    ) -> PasswordHash:
        """
        Hash a password with PBKDF2-HMAC-SHA512.

        Args:
            password: Plain-text password.
            salt:     Raw bytes (generated if omitted).

        Returns:
            PasswordHash with hex-encoded hash and salt.
        """
        if salt is None:
            salt = secrets.token_bytes(_MIN_SALT_BYTES)
        elif isinstance(salt, str):
            salt = bytes.fromhex(salt)

        derived = hashlib.pbkdf2_hmac(
            "sha512",
            password.encode("utf-8"),
            salt,
            self.iterations,
            dklen=self.key_length,
        )
        return PasswordHash(
            hash_hex=derived.hex(),
            salt_hex=salt.hex(),
            iterations=self.iterations,
        )

    # ──────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────

    def verify(
        self,
        password:   str,
        hash_hex:   str,
        salt_hex:   str,
        iterations: int,
    ) -> bool:
        """
        Timing-safe password verification.

        Args:
            password:   Plain-text submitted by the user.
            hash_hex:   Stored hash (hex string).
            salt_hex:   Stored salt (hex string).
            iterations: The iteration count used when the hash was created.

        Returns True if the password matches.

        Always performs the hash operation (even for missing users) to
        prevent user-enumeration via timing differences — the caller should
        supply dummy values for non-existent users.
        """
        computed = hashlib.pbkdf2_hmac(
            "sha512",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            iterations,
            dklen=self.key_length,
        )
        try:
            return hmac.compare_digest(computed, bytes.fromhex(hash_hex))
        except Exception:
            return False
