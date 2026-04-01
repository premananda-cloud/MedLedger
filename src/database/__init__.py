"""
database/__init__.py

Factory functions for both stores. Config-driven paths; call once at
startup and pass the instances around (or use the singletons below).

Usage:
    from src.database import get_user_store, get_vault_store

    users = get_user_store()
    vault = get_vault_store()
"""

from __future__ import annotations
from pathlib import Path

from src.services.config import cfg

_user_store  = None
_vault_store = None


def get_user_store():
    """Singleton UserStore backed by data/users.json."""
    global _user_store
    if _user_store is None:
        from src.database.user_store import UserStore
        _user_store = UserStore(cfg.json_db_path)
    return _user_store


def get_vault_store():
    """Singleton VaultStore backed by database/vault.json."""
    global _vault_store
    if _vault_store is None:
        from src.database.vault_store import VaultStore
        _vault_store = VaultStore(cfg.vault_db_path)
    return _vault_store


__all__ = ["get_user_store", "get_vault_store"]
