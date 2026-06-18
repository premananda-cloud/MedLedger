"""
main.py — MedLedger FastAPI application entry point.
"""

import load_env  # noqa: F401 — must run before any os.getenv calls

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.routes.auth import router as auth_router
from src.services.database import close_db, get_db

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: warm up the DB pool
    db = await get_db()
    logger.info("Database connected: %s", db.dsn.split("@")[-1])  # hide credentials
    yield
    # Shutdown: close pool cleanly
    await close_db()
    logger.info("Database pool closed.")


app = FastAPI(
    title="MedLedger API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(auth_router)

# Add your other routers here, e.g.:
# from src.routes.vault  import router as vault_router
# from src.routes.shares import router as shares_router
# app.include_router(vault_router)
# app.include_router(shares_router)


@app.get("/health")
async def health():
    return {"status": "ok"}
