"""
Store Factory
Location: src/services/store.py

Delegates to src/database.get_user_store() — the single config-aware singleton.
Kept for backward compatibility with registration.py imports.

    from src.services.store import get_store
    store = get_store()
"""

from src.database import get_user_store


def get_store():
    return get_user_store()
