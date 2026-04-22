"""
CypherAegis / MedLedger — FastAPI Application
Location: main.py

Run:
    uvicorn main:app --reload --port 8000

Docs:
    http://localhost:8000/docs
"""
from __future__ import annotations

import load_env

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, HTMLResponse
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
    # Mount static assets (app.jsx, fonts, etc.) — everything except index.html
    app.mount("/ui/static", StaticFiles(directory=_ui_dir), name="ui-static")


@app.get("/ui/app.jsx", include_in_schema=False)
async def ui_jsx():
    """Serve app.jsx directly (Babel loads it via <script src>)."""
    jsx_path = _ui_dir / "app.jsx"
    return HTMLResponse(
        content=jsx_path.read_text(encoding="utf-8"),
        media_type="application/javascript",
    )


@app.get("/ui/index.html", include_in_schema=False)
@app.get("/ui/", include_in_schema=False)
async def ui_index():
    """
    Serve index.html with the API base URL injected from the environment.

    Set API_BASE_URL in your .env (or environment) to point the browser
    at a non-default server without touching any source files:

        API_BASE_URL=https://my-server.example.com
    """
    index_path = _ui_dir / "index.html"
    html = index_path.read_text(encoding="utf-8")

    # Resolve the public-facing API URL.
    # .env / environment overrides config.json server settings.
    api_base = os.environ.get("API_BASE_URL", "").strip().rstrip("/")
    if not api_base:
        # Fall back to what config.json says about the server
        scheme = "https" if cfg.env == "production" else "http"
        host   = cfg.host if cfg.host != "0.0.0.0" else "localhost"
        api_base = f"{scheme}://{host}:{cfg.port}"

    # Inject a small <script> that sets window.__ML_BASE before React boots.
    # This makes the banner prompt disappear entirely when served from FastAPI.
    injection = (
        f'<script>window.MEDLEDGER_API = "{api_base}";</script>\n  '
    )
    html = html.replace("</head>", f"  {injection}</head>", 1)

    return HTMLResponse(content=html)


@app.get("/", tags=["health"])
async def root():
    if _ui_dir.exists():
        return RedirectResponse("/ui/index.html")
    return {"service": "MedLedger", "status": "ok", "env": cfg.env}


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "db_backend": cfg.db_backend}
