"""
src/middleware/auth_middleware.py
FastAPI dependency that extracts and validates the JWT from the HttpOnly cookie.
"""
import logging
from fastapi import Cookie, HTTPException, status, Depends
from jose import JWTError

from src.services.auth_service import decode_access_token, is_token_revoked
from src.services.database import DB

logger = logging.getLogger("medledger.auth")


class CurrentUser:
    def __init__(self, user_id_hex: str, username: str, jti: str, db_id: int):
        self.user_id_hex = user_id_hex
        self.username = username
        self.jti = jti
        self.db_id = db_id


async def get_current_user(
    access_token: str | None = Cookie(default=None),
) -> CurrentUser:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )
    if not access_token:
        raise credentials_exc
    try:
        payload = decode_access_token(access_token)
        user_id_hex: str = payload.get("sub")
        username: str = payload.get("username")
        jti: str = payload.get("jti")
        if not user_id_hex or not username or not jti:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    if await is_token_revoked(jti):
        raise credentials_exc

    async with DB() as conn:
        row = await conn.fetchrow(
            "SELECT id, is_active, account_deleted FROM users WHERE user_id_hex = $1",
            user_id_hex,
        )
    if not row or not row["is_active"] or row["account_deleted"]:
        raise credentials_exc

    return CurrentUser(
        user_id_hex=user_id_hex,
        username=username,
        jti=jti,
        db_id=row["id"],
    )


# Optional auth — returns None if not logged in instead of raising
async def get_current_user_optional(
    access_token: str | None = Cookie(default=None),
) -> CurrentUser | None:
    try:
        return await get_current_user(access_token)
    except HTTPException:
        return None
