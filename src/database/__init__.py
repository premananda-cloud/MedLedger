"""
database/__init__.py

PostgreSQL-only factory for both stores.
Requires DATABASE_URL (built from .env by load_env.py).

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
    """Singleton PgUserStore. Raises RuntimeError if DATABASE_URL is missing."""
    global _user_store
    if _user_store is None:
        if not cfg.postgres_url:
            raise RuntimeError(
                "DATABASE_URL is not set. "
                "Add DB_NAME, DB_HOST, DB_PASSWORD, DB_USER to your .env file."
            )
        from src.database.pg_user_store import PgUserStore
        _user_store = PgUserStore(dsn=cfg.postgres_url)
    return _user_store


def get_vault_store():
    """Singleton PgVaultStore. Raises RuntimeError if DATABASE_URL is missing."""
    global _vault_store
    if _vault_store is None:
        if not cfg.postgres_url:
            raise RuntimeError(
                "DATABASE_URL is not set. "
                "Add DB_NAME, DB_HOST, DB_PASSWORD, DB_USER to your .env file."
            )
        from src.database.pg_vault_store import PgVaultStore
        _vault_store = PgVaultStore(dsn=cfg.postgres_url)
    return _vault_store


__all__ = ["get_user_store", "get_vault_store"]
