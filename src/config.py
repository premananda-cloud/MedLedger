"""
config.py — Application settings loaded from environment / .env file.

All secrets come from environment variables. Never commit a .env file.

Usage:
    from config import settings
    settings.jwt_secret
    settings.database_url
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────────────────────────
    app_name:  str  = "MedLedger"
    debug:     bool = False
    api_prefix: str = "/api"

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str   # e.g. postgresql+asyncpg://user:pass@host/db

    # ── JWT ──────────────────────────────────────────────────────────────────
    jwt_secret:         str
    jwt_expiry_seconds: int = 3_600      # access token — 1 hour
    refresh_expiry_days: int = 30

    # ── Email (Gmail App Password) ────────────────────────────────────────────
    gmail_user:         str
    gmail_app_password: str

    # ── Proof of Work ─────────────────────────────────────────────────────────
    pow_difficulty:     int = 4
    pow_expiry_seconds: int = 300

    # ── Rate limiting ─────────────────────────────────────────────────────────
    max_login_attempts:          int = 5
    login_lockout_minutes:       int = 15
    max_verification_attempts:   int = 3
    verification_expiry_minutes: int = 10

    # ── TOTP ──────────────────────────────────────────────────────────────────
    totp_issuer: str = "MedLedger"
    totp_window: int = 1   # ±N time-steps tolerated

    # ── Company (email templates) ─────────────────────────────────────────────
    company_name:          str = "MedLedger"
    company_logo_link:     str = ""
    company_website_link:  str = ""
    customer_support_link: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


# Module-level singleton for convenience imports
settings = get_settings()
