"""
CypherAegis / MedLedger — FastAPI Application
Location: main.py

Run:
    uvicorn main:app --reload --port 8000

Docs:
    http://localhost:8000/docs
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import pathlib

from src.services.config import cfg
from src.services.auth import router as auth_router
from src.api.vault import router as vault_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("medledger")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("MedLedger starting — env=%s db=%s", cfg.env, cfg.db_backend)
    yield
    logger.info("MedLedger shutdown")


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="CypherAegis / MedLedger",
    description=(
        "Patient-controlled healthcare data vault. "
        "P-256 cryptography, ECIES DEK wrapping, ECDSA-signed permissions."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(vault_router)

# ── Static UI ─────────────────────────────────────────────────────────────────
_ui_dir = pathlib.Path(__file__).parent / "UI"
if _ui_dir.exists():
    app.mount("/ui", StaticFiles(directory=_ui_dir, html=True), name="ui")


@app.get("/", tags=["health"])
async def root():
    if _ui_dir.exists():
        return RedirectResponse("/ui/index.html")
    return {"service": "MedLedger", "status": "ok", "env": cfg.env}


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "db_backend": cfg.db_backend}
