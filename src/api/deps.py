"""
API Dependencies
Location: src/api/deps.py

Provides require_auth — a FastAPI dependency that validates the Bearer JWT
and returns a CallerIdentity with the user's id, email, and public_key_hash.
"""

from __future__ import annotations

from dataclasses import dataclass
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.services.registration import RegistrationService, AuthenticationError
from src.database import get_user_store

_bearer = HTTPBearer()


@dataclass
class CallerIdentity:
    user_id:         int
    email:           str
    public_key_hash: str
    public_key_hex:  str


async def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> CallerIdentity:
    """
    Validate Bearer JWT. Raises 401 on any failure.
    Returns CallerIdentity for use in endpoint handlers.
    """
    try:
        payload = RegistrationService.verify_token(credentials.credentials)
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = int(payload["sub"])
    store   = get_user_store()
    user    = store.get_by_id(user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return CallerIdentity(
        user_id=user.id,
        email=user.email,
        public_key_hash=user.public_key_hash or "",
        public_key_hex=user.public_key_hex or "",
    )
