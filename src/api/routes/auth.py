"""
Authentication Routes
Location: src/api/routes/auth.py
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime
import os

from src.services.registration import RegistrationService, RegistrationError, UserAlreadyExistsError
# FIX #10: Import from the correct schema location (src/schemas/user.py)
from src.schemas.user import (
    RegisterRequest, RegisterResponse, LoginRequest, LoginResponse,
    UserProfile, ErrorResponse, ValidationErrorResponse
)
from src.database.connection import get_db

router = APIRouter(
    prefix="/api/auth",
    tags=["authentication"],
    responses={
        400: {"model": ErrorResponse, "description": "Bad request"},
        409: {"model": ErrorResponse, "description": "Conflict (user exists)"},
        422: {"model": ValidationErrorResponse, "description": "Validation error"},
    }
)


def get_registration_service(db: Session = Depends(get_db)) -> RegistrationService:
    """Dependency: create RegistrationService with validated JWT secret."""
    jwt_secret = os.getenv("JWT_SECRET")
    # FIX #7: RegistrationService constructor now raises if secret is missing/insecure
    return RegistrationService(db, jwt_secret)


async def get_current_user_id(request: Request, db: Session = Depends(get_db)) -> int:
    """Extract and verify user ID from JWT Bearer token."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    jwt_secret = os.getenv("JWT_SECRET")
    service = RegistrationService(db, jwt_secret)

    try:
        payload = service.verify_jwt_token(token)
        return int(payload.get("sub"))
    except RegistrationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


# ==================== Endpoints ====================

@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
)
async def register_user(
    request: RegisterRequest,
    service: RegistrationService = Depends(get_registration_service),
) -> RegisterResponse:
    """
    Register a new PATIENT or DOCTOR.

    ⚠️ The private key is returned ONCE in this response — save it immediately.
    """
    try:
        # FIX #2: register_user is not async — no await
        return service.register_user(request)
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except RegistrationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during registration",
        )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Login user",
)
async def login_user(
    request: LoginRequest,
    service: RegistrationService = Depends(get_registration_service),
) -> LoginResponse:
    """Authenticate with email + password. Returns a JWT access token."""
    try:
        # FIX #2: login_user is not async — no await
        return service.login_user(request)
    except RegistrationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login",
        )


@router.get(
    "/me",
    response_model=UserProfile,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
)
async def get_current_user_profile(
    user_id: int = Depends(get_current_user_id),
    service: RegistrationService = Depends(get_registration_service),
) -> UserProfile:
    """Return the authenticated user's profile."""
    try:
        # FIX #2: get_user_profile is not async — no await
        return service.get_user_profile(user_id)
    except RegistrationError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving user profile",
        )


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {"status": "healthy", "service": "authentication", "timestamp": datetime.utcnow().isoformat() + "Z"}