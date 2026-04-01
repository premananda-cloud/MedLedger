# src/services/__init__.py
"""
Business Logic Services
"""

from .registration import (
    RegistrationService,
    RegistrationError,
    UserAlreadyExistsError,
    AuthenticationError,
    LoginResult,
)

# TODO: Add PermissionService when implemented
# from .permission_service import (
#     PermissionService,
#     PermissionError,
# )

__all__ = [
    "RegistrationService",
    "RegistrationError",
    "UserAlreadyExistsError",
    # "PermissionService",
    # "PermissionError",
]
