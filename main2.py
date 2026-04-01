"""
CypherAegis / MedLedger — FastAPI Application
Location: main.py

Run:
    uvicorn main:app --reload --port 8000

Docs:
    http://localhost:8000/docs
    UI: http://localhost:8000/
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

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

# ── CORS Middleware (Fix OPTIONS requests) ───────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# ── Static Files & UI Serving ────────────────────────────────────────────────
# Get the directory where main.py is located
BASE_DIR = Path(__file__).parent

# Serve UI files if the directory exists
UI_DIR = BASE_DIR / "UI"
if UI_DIR.exists():
    # Mount the UI directory for static files
    app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
    logger.info(f"UI directory mounted at /ui from {UI_DIR}")
    
    @app.get("/", tags=["ui"])
    async def serve_ui():
        """Serve the main UI dashboard"""
        index_file = UI_DIR / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {"error": "UI not found", "message": "Please create UI/index.html"}
else:
    logger.warning(f"UI directory not found at {UI_DIR}")
    
    @app.get("/", tags=["ui"])
    async def ui_not_available():
        return {
            "message": "UI not available",
            "instructions": "Create a UI/index.html file to enable the dashboard"
        }


# ── API Routers ──────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(vault_router)


# ── Health & Root Endpoints ─────────────────────────────────────────────────
@app.get("/api/health", tags=["health"])
async def health():
    """Health check endpoint"""
    return {"status": "ok", "db_backend": cfg.db_backend, "ui_available": UI_DIR.exists()}


@app.get("/api/info", tags=["info"])
async def info():
    """API information"""
    return {
        "service": "MedLedger",
        "version": "0.1.0",
        "env": cfg.env,
        "endpoints": {
            "auth": "/api/auth",
            "vault": "/api/vault",
            "docs": "/docs",
            "ui": "/"
        }
    }


# ── Optional: Add a redirect from /app to / for convenience ─────────────────
@app.get("/app", tags=["ui"])
async def redirect_to_ui():
    """Redirect /app to the main UI"""
    return FileResponse(str(UI_DIR / "index.html")) if (UI_DIR / "index.html").exists() else {"error": "UI not found"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )