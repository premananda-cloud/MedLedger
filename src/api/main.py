"""
MedLedger FastAPI Application
Location: src/api/main.py

Main application entry point. Initializes FastAPI, database, and routes.
"""

import os
import logging

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

logger = logging.getLogger(__name__)

from src.database.connection import init_db
from src.api.routes import auth, permissions
from src.api.routes.records import router as records_router, public_key_router

# ==================== Rate Limiter ====================

# Keyed by real client IP. In production behind a reverse proxy, set the
# FORWARDED_ALLOW_IPS env var (uvicorn) so the real IP is forwarded correctly.
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ==================== FastAPI App Initialization ====================

_ENV = os.getenv("APP_ENV", "development").lower()
_is_prod = _ENV == "production"

app = FastAPI(
    title="MedLedger API",
    description="Blockchain-based healthcare data management with patient-controlled access",
    version="1.0.0",
    # Disable interactive docs in production — they expose the full API surface
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
)

# Wire rate limiter state into the app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


# ==================== Security Headers Middleware ====================

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    # Only add HSTS in production where TLS is guaranteed
    if _is_prod:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

# ==================== CORS Configuration ====================

# Allow frontend to communicate with API
# FIX #8: allow_origins="*" is incompatible with allow_credentials=True (browsers reject it).
# Read allowed origins from env; fall back to localhost for local dev only.
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8081")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # explicit list, never "*" with credentials
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== Database Initialization ====================

# Create all tables on startup
@app.on_event("startup")
async def startup():
    """Initialize database on app startup"""
    try:
        init_db()
        logger.info("Database tables created/verified")
    except Exception as e:
        logger.critical("Error initializing database: %s", e, exc_info=True)
        raise  # fatal — don't silently continue with a broken DB


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on app shutdown"""
    logger.info("MedLedger API shutting down")


# ==================== Routes Registration ====================

app.include_router(auth.router)
app.include_router(permissions.router)
app.include_router(records_router)
app.include_router(public_key_router)

# ==================== Health Check ====================

@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    """Root endpoint - API is alive"""
    return {
        "status": "ok",
        "service": "MedLedger API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "docs": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json"
        }
    }


@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


# ==================== Error Handlers ====================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler — never leaks internal exception details to clients."""
    # Log full traceback server-side only
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
    )


# ==================== API Documentation ====================

@app.get("/api-info")
async def api_info():
    """Get API information and usage guide"""
    return {
        "service": "MedLedger - Patient-Controlled Healthcare Data",
        "version": "1.0.0",
        "description": "Healthcare data management with cryptographic access control",
        "features": [
            "ECDSA P-256 keypair generation",
            "Patient-signed access permissions",
            "Time-limited access windows",
            "Immutable audit trail",
            "Instant access revocation",
            "Shamir 3-of-5 key recovery"
        ],
        "endpoints": {
            "authentication": "/auth/register, /auth/login",
            "permissions": "/permissions/grant, /permissions/verify, /permissions/revoke",
            "audit": "/permissions/audit"
        },
        "documentation": "Visit /docs for interactive Swagger UI"
    }


if __name__ == "__main__":
    import uvicorn

    # Run with: python -m src.api.main
    # Or: uvicorn src.api.main:app --reload --port 8000

    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )