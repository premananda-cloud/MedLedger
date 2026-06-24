"""
routes/ — All FastAPI routers.

Mount in main.py:
    from routes import auth_router, keys_router, shares_router, vault_router, grants_router

    app.include_router(auth_router,   prefix="/api")
    app.include_router(keys_router,   prefix="/api")
    app.include_router(shares_router, prefix="/api")
    app.include_router(vault_router,  prefix="/api")
    app.include_router(grants_router, prefix="/api")
"""
from .auth   import router as auth_router
from .keys   import router as keys_router
from .shares import router as shares_router
from .vault  import router as vault_router
from .grants import router as grants_router

__all__ = [
    "auth_router",
    "keys_router",
    "shares_router",
    "vault_router",
    "grants_router",
]
