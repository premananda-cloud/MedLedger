# src/api/__init__.py
"""
API Layer - FastAPI routes and endpoints

app is defined in src/api/main.py and imported directly by uvicorn:
    uvicorn src.api.main:app

Do NOT eagerly import app here — it causes any startup error anywhere in
the import chain to be reported as the misleading:
    ImportError: cannot import name 'app' from 'src.api.main'
instead of the actual underlying error.
"""
