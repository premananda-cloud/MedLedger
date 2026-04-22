"""
database/__init__.py

Config-driven factory for both stores.
Routing is determined by cfg.db_backend ("json" | "postgres").

Usage:
    from src.database import get_user_store, get_vault_store

    users = get_user_store()
    vault = get_vault_store()
"""

from __future__ import annotations

from src.services.config import cfg

_user_store  = None
_vault_store = None


def get_user_store():
    """Singleton user store, backend chosen by config.json db_backend."""
    global _user_store
    if _user_store is None:
        if cfg.db_backend == "postgres":
            from src.database.pg_user_store import PgUserStore
            _user_store = PgUserStore(dsn=cfg.postgres_url)
        else:
            from src.database.user_store import UserStore
            _user_store = UserStore(cfg.json_db_path)
    return _user_store


def get_vault_store():
    """Singleton vault store, backend chosen by config.json db_backend."""
    global _vault_store
    if _vault_store is None:
        if cfg.db_backend == "postgres":
            from src.database.pg_vault_store import PgVaultStore
            _vault_store = PgVaultStore(dsn=cfg.postgres_url)
        else:
            from src.database.vault_store import VaultStore
            _vault_store = VaultStore(cfg.vault_db_path)
    return _vault_store


__all__ = ["get_user_store", "get_vault_store"]
