"""
auth/totp.py — Pure TOTP logic.

Zero I/O. Depends only on: pyotp, stdlib.
Caller is responsible for persisting secrets.
"""
from __future__ import annotations

import time
from typing import Optional

import pyotp

from .models import TOTPConfig, TOTPVerifyResult


class TOTPService:
    """
    Stateless TOTP helper.

    Secrets are NOT stored here. The caller (user_service / auth_service)
    must persist and supply them.

    Usage:
        svc = TOTPService(issuer="MyApp")
        config = svc.generate(email)          # → TOTPConfig; persist config.secret
        result = svc.verify(secret, token)    # → TOTPVerifyResult
    """

    def __init__(self, issuer: str = "AuthSystem", window: int = 1):
        """
        Args:
            issuer: Label shown in the authenticator app.
            window: ±N time-steps (30 s each) accepted around current time.
        """
        self.issuer = issuer
        self.window = window

    # ──────────────────────────────────────────
    # Secret generation
    # ──────────────────────────────────────────

    def generate(self, account_name: str) -> TOTPConfig:
        """
        Generate a fresh TOTP secret for an account.

        Returns TOTPConfig containing the secret (plain) and the QR URI.
        The caller MUST store `config.secret` and MUST NOT return it to the
        end-user after the setup step.

        Args:
            account_name: Email or username — shown in the authenticator app.
        """
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret, issuer=self.issuer, name=account_name)

        return TOTPConfig(
            secret=secret,
            qr_code_uri=totp.provisioning_uri(
                name=account_name,
                issuer_name=self.issuer,
            ),
            manual_key=secret,
            issuer=self.issuer,
            account_name=account_name,
        )

    # ──────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────

    def verify(self, secret: str, token: str) -> TOTPVerifyResult:
        """
        Verify a 6-digit TOTP token against a stored secret.

        Args:
            secret:  The base32 secret retrieved from persistent storage.
            token:   The code the user submitted.
        """
        if not secret:
            return TOTPVerifyResult(
                verified=False,
                message="No TOTP secret provided",
            )

        totp = pyotp.TOTP(secret, issuer=self.issuer)

        # Walk the window manually so we can report the delta for logging.
        now = int(time.time())
        for delta in range(-self.window, self.window + 1):
            check_time = now + delta * 30
            if totp.at(check_time) == token:
                return TOTPVerifyResult(
                    verified=True,
                    message=f"TOTP verified (delta={delta})",
                    delta=delta,
                )

        return TOTPVerifyResult(verified=False, message="Invalid TOTP token")

    # ──────────────────────────────────────────
    # Test helpers (use only in non-prod code)
    # ──────────────────────────────────────────

    def current_token(self, secret: str) -> Optional[str]:
        """Return the current valid token for a secret (for testing)."""
        if not secret:
            return None
        return pyotp.TOTP(secret, issuer=self.issuer).now()

    def token_at(self, secret: str, timestamp: float) -> Optional[str]:
        """Return the token valid at a specific unix timestamp (for testing)."""
        if not secret:
            return None
        return pyotp.TOTP(secret, issuer=self.issuer).at(int(timestamp))
