"""
load_env.py

Loads .env, builds DATABASE_URL from individual DB_* vars, and exports it
so that src/services/config.py can read it on first import.

IMPORTANT: must be imported BEFORE any src.* imports.
main.py does `import load_env` as its very first line for this reason.
"""

from dotenv import load_dotenv
import os
import logging

load_dotenv()

_DB_NAME     = os.getenv("DB_NAME")
_DB_HOST     = os.getenv("DB_HOST")
_DB_PASSWORD = os.getenv("DB_PASSWORD")
_DB_USER     = os.getenv("DB_USER")
_DB_PORT     = os.getenv("DB_PORT", "5432")

if all([_DB_NAME, _DB_HOST, _DB_PASSWORD, _DB_USER]):
    _database_url = (
        f"postgresql://{_DB_USER}:{_DB_PASSWORD}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"
    )
    os.environ.setdefault("DATABASE_URL", _database_url)
else:
    logging.getLogger("medledger.load_env").warning(
        "Postgres environment variables (DB_NAME, DB_HOST, DB_PASSWORD, DB_USER) "
        "are not set — the server will fail on first DB access."
    )
