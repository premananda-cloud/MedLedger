"""
main.py
MedLedger FastAPI application.

IMPORTANT: load_env must be imported first so DATABASE_URL is set
before any src.* module reads it.
"""
import load_env  # noqa: F401 — must be first

import logging
import uvicorn
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from src.services.config import get_settings
from src.services.database import init_pool, close_pool
from src.routes import auth, shares, vault

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("medledger")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting MedLedger API…")
    await init_pool()
    yield
    logger.info("Shutting down…")
    await close_pool()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url="/api/redoc" if settings.debug else None,
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global error handler ──────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception on {request.url}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(auth.router,   prefix="/api", tags=["auth"])
app.include_router(shares.router, prefix="/api", tags=["shares"])
app.include_router(vault.router,  prefix="/api", tags=["vault"])

# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["system"])
async def health():
    return {"status": "ok", "version": settings.app_version}

# ── Serve static UI (index.html + assets) ────────────────────────────────────
# Mount AFTER API routes so /api/* always hits the backend first.
try:
    app.mount("/", StaticFiles(directory="static", html=True), name="static")
except RuntimeError:
    pass  # No static/ dir yet — fine in dev


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
