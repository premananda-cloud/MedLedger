"""
auth/email_verification.py — Pure email-verification logic.

Zero I/O. Zero sending. Zero storage.

Responsibilities:
  • Validate email format / domain classification
  • Generate verification codes
  • Hash codes for safe storage
  • Verify a submitted code against its stored hash

The caller (auth_service) is responsible for:
  • Persisting the VerificationCode (only store code_hash + expires_at)
  • Passing the plain code to email_client for delivery
  • Enforcing per-email attempt counts (stored in the DB/cache, not here)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from pathlib import Path
from typing import Optional, Set

from .models import EmailStatus, EmailValidationResult, VerificationCode


# ─────────────────────────────────────────────
# Domain classification
# ─────────────────────────────────────────────

# Built-in sets — extend by passing blocklist_path to EmailVerification.
_DISPOSABLE_DOMAINS: Set[str] = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com",
    "yopmail.com", "throwaway.email", "sharklasers.com", "trashmail.com",
    "fakeinbox.com", "temp-mail.org", "dispostable.com", "maildrop.cc",
    "getairmail.com", "deadaddress.com", "discard.email", "spam4.me",
    "anonaddy.com",
}

_SPAM_DOMAINS: Set[str] = {
    "0-mail.com", "spam.la", "spamhog.com", "mailsac.com",
    "tmail.com", "xagf.com", "bcaoo.com", "fvzck.com",
}


def _load_blocked_domains(path: Path) -> Set[str]:
    """Load extra blocked domains from a JSON file (best-effort)."""
    domains: Set[str] = set()
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            domains.update(data)
        elif isinstance(data, dict):
            for key in ("disposable_domains", "spam_domains", "blocked_domains"):
                domains.update(data.get(key, []))
    except Exception:
        pass  # file missing or malformed — caller handles gracefully
    return domains


def _validate_format(email: str) -> bool:
    if not email or "@" not in email:
        return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def _suspicious_plus_addressing(local: str) -> bool:
    """Heuristic: user+randomlongstring123@domain.com looks like abuse."""
    if "+" in local:
        after = local.split("+", 1)[1]
        if len(after) > 10 and any(c.isdigit() for c in after):
            return True
    return False


# ─────────────────────────────────────────────
# Code hashing
# ─────────────────────────────────────────────

def _hash_code(code: str) -> str:
    """SHA-256 hash of a verification code (hex). Fast enough for short-lived codes."""
    return hashlib.sha256(code.encode()).hexdigest()


def _codes_match(submitted: str, stored_hash: str) -> bool:
    """Timing-safe comparison."""
    return hmac.compare_digest(_hash_code(submitted), stored_hash)


# ─────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────

class EmailVerification:
    """
    Pure email-verification logic.

    Stateless — every method is a pure function of its inputs.

    Example usage in auth_service:
        ev = EmailVerification()

        # On send:
        result = ev.validate("user@example.com")
        if not result.is_valid:
            raise BadRequest(result.message)
        vc = ev.generate_code("user@example.com")
        email_client.send(to=vc_email, code=vc.code)       # plain code
        db.store(email, code_hash=vc.code_hash,             # hashed only
                 expires_at=vc.expires_at, attempts=0)

        # On verify:
        record = db.get(email)
        outcome = ev.verify_code(submitted_code, record.code_hash,
                                 record.expires_at, record.attempts)
    """

    def __init__(
        self,
        code_length:   int            = 6,
        expiry_seconds: int           = 600,    # 10 min
        max_attempts:  int            = 3,
        blocklist_path: Optional[Path] = None,
    ):
        self.code_length    = code_length
        self.expiry_seconds = expiry_seconds
        self.max_attempts   = max_attempts

        self._extra_blocked: Set[str] = set()
        if blocklist_path:
            self._extra_blocked = _load_blocked_domains(blocklist_path)

    # ──────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────

    def validate(self, email: str) -> EmailValidationResult:
        """
        Classify an email address without generating a code.
        Call this before generate_code() to surface errors early.
        """
        if not email:
            return EmailValidationResult(
                is_valid=False, status=EmailStatus.INVALID_FORMAT,
                message="Email address is required",
            )

        if not _validate_format(email):
            return EmailValidationResult(
                is_valid=False, status=EmailStatus.INVALID_FORMAT,
                message="Invalid email format",
            )

        normalized = email.lower().strip()
        try:
            domain = normalized.split("@")[1]
        except IndexError:
            return EmailValidationResult(
                is_valid=False, status=EmailStatus.INVALID_FORMAT,
                message="Could not extract domain",
            )

        if domain in _DISPOSABLE_DOMAINS or domain in self._extra_blocked:
            return EmailValidationResult(
                is_valid=False, status=EmailStatus.DISPOSABLE,
                message="Disposable email addresses are not allowed",
                normalized_email=normalized,
            )

        if domain in _SPAM_DOMAINS:
            return EmailValidationResult(
                is_valid=False, status=EmailStatus.SPAM,
                message="This email domain is blocked",
                normalized_email=normalized,
            )

        local = normalized.split("@")[0]
        if _suspicious_plus_addressing(local):
            return EmailValidationResult(
                is_valid=False, status=EmailStatus.SPAM,
                message="Email address appears suspicious",
                normalized_email=normalized,
            )

        return EmailValidationResult(
            is_valid=True, status=EmailStatus.VALID,
            message="Email is valid", normalized_email=normalized,
        )

    # ──────────────────────────────────────────
    # Code generation
    # ──────────────────────────────────────────

    def generate_code(self, email: str) -> VerificationCode:
        """
        Generate a cryptographically secure verification code.

        Returns a VerificationCode:
          • code       — plain text; pass to email_client, do NOT persist
          • code_hash  — SHA-256 hash; persist this in your DB
          • expires_at — unix timestamp

        Does NOT validate the email format — call validate() first.
        """
        plain = "".join(str(secrets.randbelow(10)) for _ in range(self.code_length))
        now   = time.time()

        return VerificationCode(
            code=plain,
            code_hash=_hash_code(plain),
            expires_at=now + self.expiry_seconds,
            expires_in_seconds=self.expiry_seconds,
        )

    # ──────────────────────────────────────────
    # Code verification (pure — no state)
    # ──────────────────────────────────────────

    def verify_code(
        self,
        submitted_code: str,
        stored_hash:    str,
        expires_at:     float,
        attempts_used:  int,
    ) -> dict:
        """
        Verify a submitted code against a stored hash.

        Args:
            submitted_code: What the user typed in.
            stored_hash:    The code_hash stored in your DB.
            expires_at:     Unix timestamp when the code expires.
            attempts_used:  How many failed attempts have occurred so far.

        Returns a dict:
            {
              "verified":     bool,
              "message":      str,
              "attempts_left": int,     # remaining attempts if failed
            }

        The caller MUST increment attempts_used in the DB on every call
        and delete the record on success or when attempts_left reaches 0.
        """
        if time.time() > expires_at:
            return {"verified": False, "message": "Verification code has expired", "attempts_left": 0}

        if attempts_used >= self.max_attempts:
            return {"verified": False, "message": "Too many failed attempts. Request a new code.", "attempts_left": 0}

        if not _codes_match(submitted_code, stored_hash):
            remaining = self.max_attempts - (attempts_used + 1)
            return {
                "verified":     False,
                "message":      f"Invalid code. {remaining} attempt{'s' if remaining != 1 else ''} remaining.",
                "attempts_left": remaining,
            }

        return {"verified": True, "message": "Email verified successfully", "attempts_left": self.max_attempts - attempts_used}
