"""
main.py — Application entrypoint.

Usage:
    uvicorn main:app --port 8000 --reload                  # development
    uvicorn main:app --host 0.0.0.0 --port 8000            # production
"""
from __future__ import annotations

import sys
from pathlib import Path

# ── Path bootstrap ────────────────────────────────────────────────────────────
# main.py lives in  ~/projects/m/
# packages live in  ~/projects/m/src/
# Add src/ so all internal imports (routes, middleware, services …) resolve.
_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
# ─────────────────────────────────────────────────────────────────────────────

import logging
import logging.config
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from middleware.auth import AuthMiddleware
from routes import (
    auth_router,
    grants_router,
    keys_router,
    shares_router,
    vault_router,
)
from routes.deps import _token_module, db_repo_factory


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                "datefmt": "%Y-%m-%dT%H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
            },
        },
        "root": {
            "level": settings.log_level,
            "handlers": ["console"],
        },
    }
)

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    log.info("Starting up — env=%s", settings.env)
    yield
    log.info("Shutting down")


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="End-to-end encrypted vault, sharing, and grant API.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ─────────────────────────────────────────────────────────────────────────────
# CORS  (outermost — must be added before AuthMiddleware)
# ─────────────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Auth middleware
# ─────────────────────────────────────────────────────────────────────────────

app.add_middleware(
    AuthMiddleware,
    token_module=_token_module(),
    db_repo_factory=db_repo_factory,
)


# ─────────────────────────────────────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────────────────────────────────────

app.include_router(auth_router,   prefix="/api")
app.include_router(keys_router,   prefix="/api")
app.include_router(shares_router, prefix="/api")
app.include_router(vault_router,  prefix="/api")
app.include_router(grants_router, prefix="/api")


# ─────────────────────────────────────────────────────────────────────────────
# Global exception handler
# ─────────────────────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": "An unexpected error occurred."},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["health"], include_in_schema=False)
async def health() -> dict:
    return {"status": "ok"}
