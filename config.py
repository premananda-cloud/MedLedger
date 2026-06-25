"""
config.py — Application settings loaded from .env / environment variables.

Lives in ~/projects/m/ alongside main.py.
Packages are in src/, but config is here so pydantic-settings finds .env
in the project root without any path gymnastics.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List

from pydantic import computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Ensure src/ is on sys.path (config may be imported before main.py bootstraps)
_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_ENV_FILE = Path(__file__).parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str

    @field_validator("database_url", mode="before")
    @classmethod
    def _make_async(cls, v: str) -> str:
        """Rewrite postgresql:// → postgresql+asyncpg:// for async SQLAlchemy."""
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    # ── JWT ───────────────────────────────────────────────────────────────────
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    @computed_field
    @property
    def jwt_expiry_seconds(self) -> int:
        return self.access_token_expire_minutes * 60

    # ── TOTP ─────────────────────────────────────────────────────────────────
    totp_issuer: str = "MedLedger"
    totp_window: int = 1

    # ── Proof of Work ────────────────────────────────────────────────────────
    pow_difficulty: int = 4
    pow_expiry_seconds: int = 300

    # ── CORS ─────────────────────────────────────────────────────────────────
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors(cls, v) -> List[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                return json.loads(v)
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    app_name: str = "MedLedger API"
    app_version: str = "1.0.0"
    log_level: str = "INFO"

    # ── Email / branding ──────────────────────────────────────────────────────
    company_name: str = "MedLedger"
    company_logo_link: str = "https://example.com/logo.png"
    company_website_link: str = "https://example.com"
    customer_support_link: str = "https://example.com/support"

    # ── Misc ──────────────────────────────────────────────────────────────────
    env: str = "development"


settings = Settings()
