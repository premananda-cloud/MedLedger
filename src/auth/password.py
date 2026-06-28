"""
auth/password.py — PasswordModule

Responsibility: hash passwords, verify them, and score their strength.

What it does:
  ✓ Argon2id hashing (salt embedded in hash string — nothing to store separately)
  ✓ Timing-safe verification via argon2-cffi
  ✓ Transparent rehash detection (call needs_rehash after verify)
  ✓ Strength scoring with actionable feedback

What it does NOT do:
  ✗ Store anything
  ✗ Know about users

Migration note:
  If you have existing PBKDF2 hashes in the DB, use verify_password_with_migration()
  in AuthService — it falls back to PBKDF2 on first login and rehashes to Argon2id.
"""
from __future__ import annotations

import re
from typing import List, Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from .models import PasswordStrengthResult


# OWASP 2023-recommended Argon2id parameters.
# m=64MB, t=3 iterations, p=4 parallel lanes.
# Salt is generated internally by argon2-cffi (16 bytes by default).
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


class PasswordModule:
    """
    Pure password hashing and validation.

    Argon2id produces a single self-contained string that encodes the
    algorithm, parameters, salt, and hash — nothing needs to be stored
    separately. The orchestrator stores only the returned hash string.

    Usage:
        module = PasswordModule()

        # Registration:
        strength = module.validate_strength("MyP@ssw0rd!")
        if not strength.valid:
            raise BadRequest(strength.issues)
        hash_str = module.hash_password("MyP@ssw0rd!")
        db.store(user_id, hash_str)           # one column, one value

        # Login:
        row = db.fetch(user_id)
        ok = module.verify_password("MyP@ssw0rd!", row.password_hash)

        # After verify, check whether the hash needs upgrading:
        if ok and module.needs_rehash(row.password_hash):
            db.set_password_hash(user_id, module.hash_password(submitted_pw))
    """

    def __init__(self, min_length: int = 8):
        self.min_length = min_length

    # ──────────────────────────────────────────
    # Hashing
    # ──────────────────────────────────────────

    def hash_password(self, password: str) -> str:
        """
        Hash a password with Argon2id.

        The returned string is self-contained — store it verbatim as the
        single password_hash column. No salt or iteration fields required.

        Args:
            password: Plain-text password.

        Returns:
            Argon2id hash string, e.g.
            '$argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>'
        """
        return _PH.hash(password)

    # ──────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────

    def verify_password(self, password: str, hash_str: str) -> bool:
        """
        Verify a password against a stored Argon2id hash.

        Timing-safe — argon2-cffi always runs the full hash computation.
        Call needs_rehash() afterwards to detect parameter upgrades.

        Args:
            password: Submitted plain-text password.
            hash_str: Stored Argon2id hash string.

        Returns:
            True if the password matches, False otherwise.
        """
        try:
            return _PH.verify(hash_str, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, hash_str: str) -> bool:
        """
        True if the stored hash was produced with outdated parameters.

        Call this after a successful verify_password(). If True, rehash
        with hash_password() and update the stored value.
        """
        try:
            return _PH.check_needs_rehash(hash_str)
        except InvalidHashError:
            return True   # unparseable → treat as needing rehash

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

        Minimum to pass: score ≥ 3 AND length ≥ min_length AND no keyboard pattern.

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
