"""
Store Factory
Location: src/services/store.py

Returns the active user-identity storage backend as decided by config.json.
Every service that needs user persistence imports get_store() from here.

Delegates to src/database/user_store.UserStore (json backend) or
src/database/sql_store.SqlStore (sqlite/postgres) — the new typed-schema layer.

Usage:
    from src.services.store import get_store
    store = get_store()
    user  = store.get_by_email("alice@example.com")  # returns UserRecord
"""

from src.services.config import cfg


def _build_store():
    backend = cfg.db_backend

    if backend == "json":
        from src.database.user_store import UserStore
        return UserStore(cfg.json_db_path)

    if backend == "sqlite":
        from src.database.sql_store import SqlStore
        return SqlStore(db_url=f"sqlite:///{cfg.sqlite_path}")

    if backend == "postgres":
        if not cfg.postgres_url:
            raise RuntimeError(
                "db_backend is 'postgres' but DATABASE_URL env var is not set."
            )
        from src.database.sql_store import SqlStore
        return SqlStore(db_url=cfg.postgres_url)

    raise ValueError(f"Unknown db_backend in config.json: '{backend}'")


# Singleton — built once at import time, reused for the lifetime of the process.
_store = None


def get_store():
    global _store
    if _store is None:
        _store = _build_store()
    return _store
