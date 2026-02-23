# src/services/__init__.py
"""
Business Logic Services
=======================

Provides service classes for registration, permission management, and cryptographic operations.

Exports:
- RegistrationService: User registration and login logic
- PermissionService: Access permission grant/verify/revoke logic
- PermissionError: Custom exception for permission operations
- RegistrationError, UserAlreadyExistsError: Registration exceptions
"""

from .registration import (
    RegistrationService,
    RegistrationError,
    UserAlreadyExistsError,
)

from .permission_service import (
    PermissionService,
    PermissionError,
)

__all__ = [
    "RegistrationService",
    "RegistrationError",
    "UserAlreadyExistsError",
    "PermissionService",
    "PermissionError",
]