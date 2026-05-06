"""
CypherAegis Config Loader
Location: src/services/config.py

Loads config.json from src/database/config.json.
All other modules import from here — nobody reads config.json directly.

Usage:
    from src.services.config import cfg
    url    = cfg.postgres_url        # resolved DATABASE_URL
    secret = cfg.jwt_secret          # resolved string
    keygen = cfg.keygen_on_server    # bool
"""

import json
import os
from pathlib import Path
from dataclasses import dataclass

# ── Locate config.json ────────────────────────────────────────────────────────
_HERE        = Path(__file__).resolve().parent   # .../src/services/
_SRC         = _HERE.parent                      # .../src/
_CONFIG_PATH = _SRC / "database" / "config.json"


def _load_raw() -> dict:
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"config.json not found at {_CONFIG_PATH}. "
            "Copy config.json to src/database/ before starting."
        )
    with open(_CONFIG_PATH, "r") as f:
        return json.load(f)


# ── Typed config object ───────────────────────────────────────────────────────

@dataclass
class AppConfig:
    # Postgres
    postgres_url: str

    # JWT
    jwt_secret:           str
    jwt_algorithm:        str
    jwt_expiration_hours: int

    # Crypto behaviour
    keygen_on_server: bool   # True  → server generates keypair (dev/test)
                             # False → client must supply public keys (production)

    # Server
    host:            str
    port:            int
    env:             str             # "development" | "production"
    allowed_origins: list[str]

    @property
    def is_dev(self) -> bool:
        return self.env.lower() != "production"


def _build_config(raw: dict) -> AppConfig:
    # ── Postgres URL ──────────────────────────────────────────────────────────
    pg_env_var   = raw.get("postgres", {}).get("url_env", "DATABASE_URL")
    postgres_url = os.getenv(pg_env_var, "")

    # ── JWT ───────────────────────────────────────────────────────────────────
    jwt_cfg         = raw.get("jwt", {})
    secret_env      = jwt_cfg.get("secret_env", "JWT_SECRET")
    secret_fallback = jwt_cfg.get("secret_fallback", "")
    jwt_secret      = os.getenv(secret_env, "") or secret_fallback
    if not jwt_secret:
        raise ValueError(
            f"JWT secret not configured. Set the '{secret_env}' environment variable "
            "or add 'secret_fallback' to config.json (dev only)."
        )

    # ── Crypto ────────────────────────────────────────────────────────────────
    keygen_on_server = raw.get("crypto", {}).get("keygen_on_server", True)

    # ── Server ────────────────────────────────────────────────────────────────
    srv = raw.get("server", {})

    return AppConfig(
        postgres_url=postgres_url,
        jwt_secret=jwt_secret,
        jwt_algorithm=jwt_cfg.get("algorithm", "HS256"),
        jwt_expiration_hours=int(jwt_cfg.get("expiration_hours", 1)),
        keygen_on_server=bool(keygen_on_server),
        host=srv.get("host", "0.0.0.0"),
        port=int(srv.get("port", 8000)),
        env=srv.get("env", "development"),
        allowed_origins=srv.get("allowed_origins", ["http://localhost:3000"]),
    )


# ── Singleton ─────────────────────────────────────────────────────────────────
cfg: AppConfig = _build_config(_load_raw())
