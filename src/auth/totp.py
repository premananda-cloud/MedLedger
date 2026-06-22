"""
auth/totp.py — TOTPModule

Responsibility: generate TOTP secrets and verify codes.

What it does:
  ✓ Generates base32 secrets + provisioning URIs
  ✓ Verifies 6-digit codes against a supplied secret
  ✓ Generates backup codes

What it does NOT do:
  ✗ Store secrets
  ✗ Know about users
  ✗ Fetch secrets from anywhere — the caller supplies them
"""
from __future__ import annotations

import secrets
import time
from typing import List, Optional

import pyotp

from .models import TOTPSecret


class TOTPModule:
    """
    Stateless TOTP helper.

    Secrets are never stored here. The orchestrator fetches the secret
    from the database and passes it in on every verify call.

    Usage:
        module = TOTPModule(issuer="MyApp")

        # Setup (on registration):
        result = module.generate_secret(email="user@example.com")
        db.store(user_id, encrypted(result.secret))
        return result.uri  # → frontend shows QR code

        # Verify (on login):
        secret = db.fetch(user_id)
        ok = module.verify_code(secret=secret, code=submitted_code)
    """

    def __init__(self, issuer: str = "AuthSystem", window: int = 1):
        """
        Args:
            issuer: Label shown in the authenticator app.
            window: ±N time-steps (30 s each) tolerated for clock skew.
        """
        self.issuer = issuer
        self.window = window

    # ──────────────────────────────────────────
    # Secret generation
    # ──────────────────────────────────────────

    def generate_secret(self, email: str) -> TOTPSecret:
        """
        Generate a fresh TOTP secret for an account.

        The caller MUST persist `result.secret` (ideally encrypted).
        The caller returns `result.uri` to the frontend for QR display.

        Args:
            email: Account identifier shown in the authenticator app.
        """
        secret = pyotp.random_base32()
        totp   = pyotp.TOTP(secret, issuer=self.issuer, name=email)

        return TOTPSecret(
            secret=secret,
            uri=totp.provisioning_uri(name=email, issuer_name=self.issuer),
            issuer=self.issuer,
            email=email,
        )

    # ──────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────

    def verify_code(self, secret: str, code: str) -> bool:
        """
        Verify a 6-digit TOTP code against a stored secret.

        Args:
            secret: The base32 secret retrieved from DB by the orchestrator.
            code:   The code submitted by the user.
        """
        if not secret or not code:
            return False
        totp = pyotp.TOTP(secret, issuer=self.issuer)
        return totp.verify(code, valid_window=self.window)

    # ──────────────────────────────────────────
    # Backup codes
    # ──────────────────────────────────────────

    def generate_backup_codes(self, count: int = 8) -> List[str]:
        """
        Generate one-time backup codes.

        Returns a list of plain codes. The caller is responsible for
        hashing and storing them; these are never stored here.

        Format: XXXX-XXXX (8 hex chars split for readability)
        """
        return [
            f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
            for _ in range(count)
        ]

    # ──────────────────────────────────────────
    # Test helpers (non-prod use only)
    # ──────────────────────────────────────────

    def current_token(self, secret: str) -> Optional[str]:
        """Get the currently valid token for a secret. Use in tests only."""
        if not secret:
            return None
        return pyotp.TOTP(secret, issuer=self.issuer).now()
