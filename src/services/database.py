"""
src/services/database.py
asyncpg connection pool — shared across the entire app lifetime.
"""
import asyncpg
import logging
from src.services.config import get_settings

logger = logging.getLogger("medledger.db")

_pool: asyncpg.Pool | None = None


async def init_pool() -> None:
    global _pool
    settings = get_settings()
    _pool = await asyncpg.create_pool(
        dsn=settings.database_url,
        min_size=2,
        max_size=20,
        command_timeout=60,
    )
    logger.info("Database pool initialised.")


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        logger.info("Database pool closed.")


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialised. Call init_pool() first.")
    return _pool


class DB:
    """Thin wrapper so route handlers can use `async with DB() as conn`."""

    async def __aenter__(self) -> asyncpg.Connection:
        self._conn = await get_pool().acquire()
        return self._conn

    async def __aexit__(self, *_):
        await get_pool().release(self._conn)
