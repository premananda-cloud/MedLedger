"""
Application settings. Reads from environment (populated by load_env.py before import).
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "postgresql://postgres:postgres@localhost:5432/medledger_db"

    # ── JWT / Session ─────────────────────────────────────────────────────────
    jwt_secret: str = "CHANGE_ME_IN_PRODUCTION_USE_LONG_RANDOM_STRING"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # ── Cookies ───────────────────────────────────────────────────────────────
    cookie_secure: bool = False          # True in production (HTTPS only)
    cookie_samesite: str = "lax"
    cookie_domain: str | None = None

    # ── CORS ──────────────────────────────────────────────────────────────────
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_login: str = "10/minute"
    rate_limit_register: str = "5/minute"

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    app_name: str = "MedLedger API"
    app_version: str = "1.0.0"

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
