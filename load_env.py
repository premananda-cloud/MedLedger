"""
load_env.py

Loads .env/.env, validates required DB vars, and exports DATABASE_URL so
that src/services/config.py can read it when it first imports.

IMPORTANT: this module must be imported BEFORE any src.* imports.
main.py does `import load_env` as its very first line for this reason.
"""

from dotenv import load_dotenv
import os

# Unusual but valid path — keep as-is
load_dotenv()

_DB_NAME     = os.getenv('DB_NAME')
_DB_HOST     = os.getenv('DB_HOST')
_DB_PASSWORD = os.getenv('DB_PASSWORD')
_DB_USER     = os.getenv('DB_USER')
_DB_PORT     = os.getenv('DB_PORT', '5432')

if all([_DB_NAME, _DB_HOST, _DB_PASSWORD, _DB_USER, _DB_PORT]):
    # Build and publish DATABASE_URL so config.py picks it up at import time.
    # setdefault keeps any value the caller already set in the environment.
    _database_url = (
        f"postgresql://{_DB_USER}:{_DB_PASSWORD}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"
    )
    os.environ.setdefault('DATABASE_URL', _database_url)
else:
    # Postgres vars not set — only a problem if db_backend == "postgres".
    # The store factory in src/database/__init__.py will raise a clear error
    # when it tries to connect if the URL is missing.
    import logging as _logging
    _logging.getLogger("medledger.load_env").warning(
        "Postgres environment variables (DB_NAME, DB_HOST, DB_PASSWORD, DB_USER) "
        "are not set. This is fine if db_backend is 'json'; otherwise the server "
        "will fail when it first tries to connect to the database."
    )
