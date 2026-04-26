"""
database/__init__.py

Config-driven factory for both stores.
Routing is determined by cfg.db_backend ("json" | "postgres").

Supported backends
──────────────────
  postgres  Full support — PgUserStore + PgVaultStore (recommended).
  json      User store only (JsonStore). Vault requires postgres; attempting
            to use it with db_backend=json raises NotImplementedError.

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
    """
    Singleton user store, backend chosen by config.json db_backend.

    postgres → PgUserStore   (psycopg2, ThreadedConnectionPool)
    json     → JsonStore     (src/services/json_store.py, file-backed)
    """
    global _user_store
    if _user_store is None:
        if cfg.db_backend == "postgres":
            from src.database.pg_user_store import PgUserStore
            if not cfg.postgres_url:
                raise RuntimeError(
                    "db_backend is 'postgres' but DATABASE_URL is not set. "
                    "Set DB_NAME, DB_HOST, DB_PASSWORD, DB_USER in your .env file."
                )
            _user_store = PgUserStore(dsn=cfg.postgres_url)
        else:
            # JSON file-backed store — lives in src/services/json_store.py.
            # BUG-FIX: the old code referenced src.database.user_store which
            # never existed; the real implementation is JsonStore.
            from src.services.json_store import JsonStore
            _user_store = JsonStore(cfg.json_db_path)
    return _user_store


def get_vault_store():
    """
    Singleton vault store, backend chosen by config.json db_backend.

    postgres → PgVaultStore  (full implementation)
    json     → NotImplementedError (no file-backed vault store exists)
    """
    global _vault_store
    if _vault_store is None:
        if cfg.db_backend == "postgres":
            from src.database.pg_vault_store import PgVaultStore
            if not cfg.postgres_url:
                raise RuntimeError(
                    "db_backend is 'postgres' but DATABASE_URL is not set. "
                    "Set DB_NAME, DB_HOST, DB_PASSWORD, DB_USER in your .env file."
                )
            _vault_store = PgVaultStore(dsn=cfg.postgres_url)
        else:
            # BUG-FIX: the old code referenced src.database.vault_store which
            # never existed. A file-backed vault store has not been implemented.
            # Switch db_backend to "postgres" in src/database/config.json to
            # use the vault.
            raise NotImplementedError(
                "The vault store requires db_backend='postgres'. "
                "A file-backed vault store has not been implemented. "
                "Set db_backend to 'postgres' in src/database/config.json "
                "and configure your Postgres credentials in .env."
            )
    return _vault_store


__all__ = ["get_user_store", "get_vault_store"]
