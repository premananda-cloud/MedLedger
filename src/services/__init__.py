"""
services/ — Orchestration layer for MedLedger.

Layer contract:
  ✓ Imports from auth/ and database/
  ✓ All business logic and flow decisions live here
  ✗ No crypto operations (all crypto is on the frontend)
  ✗ No raw SQL (DatabaseRepository handles all queries)
  ✗ No plaintext payload storage (relay is zero-knowledge pass-through)

Dependency order (build / inject in this order):
  1. AuditService(db_repo)
  2. KeyService(db_repo, audit_service)
  3. GrantService(db_repo, audit_service)
  4. RelayService(db_repo, key_service, grant_service, audit_service)
  5. AuthService(db_repo, email_module, totp_module, password_module,
                 token_module, pow_module, audit_service, config)
"""

from .audit_service import AuditService
from .auth_service  import AuthService
from .grant_service import GrantService
from .key_service   import KeyService
from .relay_service import RelayService
from .token         import TokenModule

__all__ = [
    "AuditService",
    "AuthService",
    "GrantService",
    "KeyService",
    "RelayService",
    "TokenModule",
]
