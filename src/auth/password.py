"""
auth/password.py — PasswordModule

Responsibility: hash passwords, verify them, and score their strength.

What it does:
  ✓ PBKDF2-SHA512 hashing with a random salt (primary API — tests depend on this)
  ✓ Argon2id hashing via hash_password_argon2() (used by auth_service internally)
  ✓ Timing-safe verification for both
  ✓ Transparent needs_rehash() detection for Argon2
  ✓ Strength scoring with actionable feedback

What it does NOT do:
  ✗ Store anything
  ✗ Know about users

Design note:
  hash_password() keeps the PBKDF2 API (returns PasswordHashResult with
  .hash_hex / .salt_hex / .iterations) so existing tests and any callers
  that depend on separate fields keep working unchanged.

  auth_service uses verify_password(password, hash_str) with a single
  Argon2id string — that overload is detected automatically by checking
  whether hash_hex starts with '$argon2'.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import List, Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from .models import PasswordStrengthResult, PasswordHashResult


_PROD_ITERATIONS = 600_000   # OWASP 2023
_TEST_ITERATIONS = 1_000
_KEY_LENGTH      = 64        # bytes → 512-bit key
_SALT_BYTES      = 16

# Argon2id — OWASP 2023 recommended params
_PH = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

_COMMON = frozenset({
    "password", "12345678", "qwerty123", "letmein123",
    "password123", "admin123", "welcome1", "monkey123",
})
_KEYBOARD = ("qwerty", "asdfgh", "zxcvbn", "123456", "qazwsx")


def _is_test() -> bool:
    return os.getenv("APP_ENV") == "test" or os.getenv("TESTING") == "true"


class PasswordModule:
    """
    Password hashing, verification, and strength validation.

    Primary API (PBKDF2 — backward compatible with tests):
        ph = module.hash_password("MyP@ssw0rd!")
        # ph.hash_hex, ph.salt_hex, ph.iterations
        ok = module.verify_password("MyP@ssw0rd!", ph.hash_hex, ph.salt_hex, ph.iterations)

    Argon2id API (used by auth_service for new hashes):
        hash_str = module.hash_password_argon2("MyP@ssw0rd!")
        ok = module.verify_password("MyP@ssw0rd!", hash_str)
        if module.needs_rehash(hash_str): ...
    """

    def __init__(self, min_length: int = 8, iterations: Optional[int] = None):
        self.min_length = min_length
        self.iterations = (
            iterations if iterations is not None
            else (_TEST_ITERATIONS if _is_test() else _PROD_ITERATIONS)
        )

    # ──────────────────────────────────────────
    # PBKDF2 hashing (primary / test-compatible API)
    # ──────────────────────────────────────────

    def hash_password(self, password: str, salt: Optional[bytes] = None) -> PasswordHashResult:
        """
        Hash with PBKDF2-HMAC-SHA512. Returns PasswordHashResult with
        .hash_hex, .salt_hex, .iterations — store all three separately.

        Args:
            password: Plain-text password.
            salt:     Raw bytes or hex string — generated if omitted.
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
    # Argon2id hashing (single self-contained string)
    # ──────────────────────────────────────────

    def hash_password_argon2(self, password: str) -> str:
        """
        Hash with Argon2id. Returns a single opaque string that embeds
        algorithm, parameters, salt, and hash — store as one column.
        Use verify_password(password, hash_str) to verify.
        """
        return _PH.hash(password)

    def needs_rehash(self, hash_str: str) -> bool:
        """True if the Argon2 hash was made with outdated parameters."""
        try:
            return _PH.check_needs_rehash(hash_str)
        except InvalidHashError:
            return True

    # ──────────────────────────────────────────
    # Verification — handles both PBKDF2 and Argon2id
    # ──────────────────────────────────────────

    def verify_password(
        self,
        password:   str,
        hash_hex:   str,
        salt_hex:   str = "",
        iterations: int = 0,
    ) -> bool:
        """
        Timing-safe verification. Supports two calling conventions:

        PBKDF2 (3-arg, used by tests):
            verify_password(password, hash_hex, salt_hex, iterations)

        Argon2id (2-arg, used by auth_service):
            verify_password(password, argon2_hash_string)
            # hash_hex starts with '$argon2' — salt_hex and iterations ignored
        """
        # Detect Argon2id by the hash string prefix
        if hash_hex.startswith("$argon2"):
            try:
                return _PH.verify(hash_hex, password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False

        # PBKDF2 path
        try:
            salt_bytes = bytes.fromhex(salt_hex) if salt_hex else b""
            iters = iterations if iterations > 0 else self.iterations
            computed = hashlib.pbkdf2_hmac(
                "sha512",
                password.encode("utf-8"),
                salt_bytes,
                iters,
                dklen=_KEY_LENGTH,
            )
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
          5. Length >= 12

        Minimum to pass: score >= 3 AND length >= min_length AND no keyboard pattern.
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

        has_keyboard = any(pat in password.lower() for pat in _KEYBOARD)
        if has_keyboard:
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

        valid = (
            score >= 3
            and len(password) >= self.min_length
            and not has_keyboard
        )

        return PasswordStrengthResult(
            valid=valid, score=score, strength=strength,
            issues=[i for i in issues if i],
        )
