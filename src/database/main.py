"""
MedLedger FastAPI Application
Location: src/api/main.py

Main application entry point. Initializes FastAPI, database, and routes.
"""

import os

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from src.database.models import Base, engine, create_all_tables
from src.api.routes import auth, permissions
from src.api.routes.records import router as records_router, public_key_router

# ==================== FastAPI App Initialization ====================

app = FastAPI(
    title="MedLedger API",
    description="Blockchain-based healthcare data management with patient-controlled access",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

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
        create_all_tables(engine)
        print("✓ Database tables created/verified")
    except Exception as e:
        print(f"✗ Error initializing database: {str(e)}")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on app shutdown"""
    print("MedLedger API shutting down")


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
async def global_exception_handler(request, exc):
    """Global exception handler"""
    print(f"Unhandled exception: {str(exc)}")
    return {
        "error": "Internal server error",
        "detail": str(exc),
        "timestamp": datetime.utcnow().isoformat()
    }


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
    # FIX: Removed duplicate CORSMiddleware block that was placed after uvicorn.run()
    # (unreachable dead code) and which would have overridden the secure CORS config above
    # with a wildcard-style localhost list, undermining the environment-variable-driven approach.
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Auto-reload on code changes
        log_level="info"
    )