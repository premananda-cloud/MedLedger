"""
routes/deps.py — FastAPI dependency injection.

All service instances are created once at startup and reused.
The DB session is the only thing created per-request.

Usage in routes:
    @router.get("/something")
    async def handler(
        current_user: dict = Depends(get_current_user),
        auth_svc: AuthService = Depends(get_auth_service),
    ):
        ...
"""
from __future__ import annotations

from functools import lru_cache
from typing import AsyncGenerator

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from config import settings
from database import DatabaseRepository
from auth.email    import EmailAuthModule
from auth.totp     import TOTPModule
from auth.password import PasswordModule
from auth.pow      import POWModule
from services.audit_service import AuditService
from services.auth_service  import AuthService
from services.key_service   import KeyService
from services.grant_service import GrantService
from services.relay_service import RelayService
from services.token         import TokenModule
from middleware.auth        import get_current_user  # re-export for routes

# ─────────────────────────────────────────────────────────────────────────────
# Database engine + session factory (created once)
# ─────────────────────────────────────────────────────────────────────────────

_engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    pool_pre_ping=True,
)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a fresh AsyncSession per request, auto-closed after."""
    async with _session_factory() as session:
        yield session


async def get_db_repo(
    session: AsyncSession = Depends(get_session),
) -> DatabaseRepository:
    """Return a DatabaseRepository bound to the per-request session."""
    return DatabaseRepository(session)


# Standalone factory (used by middleware for JTI checks — no FastAPI DI)
async def db_repo_factory() -> DatabaseRepository:
    async with _session_factory() as session:
        return DatabaseRepository(session)


# ─────────────────────────────────────────────────────────────────────────────
# Auth modules (stateless — created once, shared)
# ─────────────────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _email_module() -> EmailAuthModule:
    return EmailAuthModule(
        company_name=settings.company_name,
        company_logo_link=settings.company_logo_link,
        company_website_link=settings.company_website_link,
        customer_support_link=settings.customer_support_link,
    )

@lru_cache(maxsize=1)
def _totp_module() -> TOTPModule:
    return TOTPModule(issuer=settings.totp_issuer, window=settings.totp_window)

@lru_cache(maxsize=1)
def _password_module() -> PasswordModule:
    return PasswordModule()

@lru_cache(maxsize=1)
def _pow_module() -> POWModule:
    return POWModule(
        difficulty=settings.pow_difficulty,
        expiry_seconds=settings.pow_expiry_seconds,
    )

@lru_cache(maxsize=1)
def _token_module() -> TokenModule:
    return TokenModule(
        secret=settings.jwt_secret,
        expiry_seconds=settings.jwt_expiry_seconds,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Service dependencies (one per request — share the DB session)
# ─────────────────────────────────────────────────────────────────────────────

async def get_audit_service(
    db_repo: DatabaseRepository = Depends(get_db_repo),
) -> AuditService:
    return AuditService(db_repo)


async def get_key_service(
    db_repo:  DatabaseRepository = Depends(get_db_repo),
    audit:    AuditService       = Depends(get_audit_service),
) -> KeyService:
    return KeyService(db_repo, audit)


async def get_grant_service(
    db_repo: DatabaseRepository = Depends(get_db_repo),
    audit:   AuditService       = Depends(get_audit_service),
) -> GrantService:
    return GrantService(db_repo, audit)


async def get_relay_service(
    db_repo:  DatabaseRepository = Depends(get_db_repo),
    key_svc:  KeyService         = Depends(get_key_service),
    grant_svc: GrantService      = Depends(get_grant_service),
    audit:    AuditService       = Depends(get_audit_service),
) -> RelayService:
    return RelayService(db_repo, key_svc, grant_svc, audit)


async def get_auth_service(
    db_repo: DatabaseRepository = Depends(get_db_repo),
    audit:   AuditService       = Depends(get_audit_service),
) -> AuthService:
    return AuthService(
        db_repo=db_repo,
        email_module=_email_module(),
        totp_module=_totp_module(),
        password_module=_password_module(),
        token_module=_token_module(),
        pow_module=_pow_module(),
        audit_service=audit,
        config=settings,
    )


# Re-export for convenience
__all__ = [
    "get_current_user",
    "get_db_repo",
    "get_auth_service",
    "get_key_service",
    "get_grant_service",
    "get_relay_service",
    "get_audit_service",
    "db_repo_factory",
    "_token_module",
]
