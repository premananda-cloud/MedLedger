"""
src/database/main.py — DATABASE UTILITIES ONLY.

This file previously contained a duplicate FastAPI application factory that was
out-of-sync with src/api/main.py.  That duplicate has been removed because:

  1. Two app instances means two separate middleware stacks — security headers,
     rate limiting, and CORS hardening applied in src/api/main.py were silently
     absent from any process that imported THIS file instead.
  2. The duplicate global exception handler leaked internal exception details
     (str(exc)) to clients — a vulnerability fixed in src/api/main.py.
  3. Its Swagger UI was always enabled with no production guard.

The canonical application entry point is:
    src/api/main.py  ->  uvicorn src.api.main:app

Database helpers (init_db, drop_db, check_db_connection) live in:
    src/database/connection.py
"""
