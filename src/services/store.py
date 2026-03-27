"""
Store Factory
Location: src/database/store.py

Returns the active storage backend as decided by config.json.
Every service that needs persistence imports get_store() from here.

Usage:
    from src.database.store import get_store
    store = get_store()
    user  = store.get_by_email("alice@example.com")

Adding a new backend:
    1. Implement the same public interface as JsonStore in a new class.
    2. Add a branch in _build_store() below.
    3. Update config.json → "db_backend" to the new name.
    Nothing else changes.
"""

from src.config import cfg


def _build_store():
    backend = cfg.db_backend

    if backend == "json":
        from src.database.json_store import JsonStore
        return JsonStore(cfg.json_db_path)

    if backend == "sqlite":
        # SQLite uses the existing SQLAlchemy session via connection.py.
        # Wrap it in a thin adapter so callers use the same interface.
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
