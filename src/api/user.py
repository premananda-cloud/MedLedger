"""
Pydantic Schemas - Request/Response validation for FastAPI
Location: src/api/schemas/user.py

Defines:
- RegisterRequest: User registration input
- RegisterResponse: Registration response with private key and JWT
- LoginRequest: Login credentials
- LoginResponse: JWT token
- UserProfile: User information response
"""

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from datetime import datetime
from enum import Enum


class UserRoleEnum(str, Enum):
    """User role options"""
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"


# ==================== Registration ====================

class RegisterRequest(BaseModel):
    """User registration request"""
    
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern="^[a-zA-Z0-9_-]+$",
        description="Username (alphanumeric, dash, underscore)"
    )
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (min 8 chars, should include upper/lower/numbers)"
    )
    full_name: str = Field(..., min_length=2, max_length=255)
    role: UserRoleEnum = Field(..., description="PATIENT or DOCTOR")

    # Client-generated public key (client holds the private key — server never sees it)
    public_key_hex: str = Field(..., description="Uncompressed P-256 public key — 130 hex chars (04…)")
    public_key_compressed: str = Field(..., description="Compressed public key — 66 hex chars")
    public_key_hash: str = Field(..., description="SHA-256 of uncompressed public key bytes — 64 hex chars")

    @validator('password')
    def validate_password_strength(cls, v):
        """Minimum 6 characters for demo. Relax further if needed."""
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "dr_smith",
                "email": "dr.smith@hospital.com",
                "password": "SecurePass123!",
                "full_name": "Dr. John Smith",
                "role": "DOCTOR"
            }
        }


class RegisterResponse(BaseModel):
    """
    Registration response with cryptographic keys
    
    ⚠️ WARNING: Private key is returned ONCE and only in this response.
    User MUST save it immediately. It cannot be recovered!
    """
    
    user_id: int
    username: str
    email: str
    role: UserRoleEnum
    full_name: str
    
    # Cryptographic Key Material
    public_key_hash: str = Field(..., description="SHA256 hash of public key (unique ID)")
    public_key_compressed: str = Field(..., description="Compressed public key (33 bytes hex)")
    
    # CRITICAL: Private Key (never stored again)
    private_key_pem: str = Field(
        ...,
        description="PEM-encoded private key (SAVE THIS NOW - cannot be recovered!)"
    )
    private_key_qr: str = Field(
        ...,
        description="QR code containing private key (for offline backup)"
    )
    
    # Authentication
    access_token: str = Field(..., description="JWT for API authentication")
    token_type: str = "Bearer"
    expires_in: int = 3600  # 1 hour
    
    # User Instructions
    warning_message: str = "⚠️ SAVE YOUR PRIVATE KEY IMMEDIATELY - It cannot be recovered if lost!"
    
    created_at: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "user_id": 42,
                "username": "dr_smith",
                "email": "dr.smith@hospital.com",
                "role": "DOCTOR",
                "full_name": "Dr. John Smith",
                "public_key_hash": "7f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
                "public_key_compressed": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
                "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\n...",
                "private_key_qr": "data:image/png;base64,iVBORw0KGgo...",
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 3600,
                "created_at": "2025-02-15T10:30:00Z"
            }
        }


# ==================== Login ====================

class LoginRequest(BaseModel):
    """User login request"""
    
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=1)
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "dr.smith@hospital.com",
                "password": "SecurePass123!"
            }
        }


class LoginResponse(BaseModel):
    """Login response with JWT token"""
    
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    
    # User Info (non-sensitive)
    user_id: int
    username: str
    email: str
    role: UserRoleEnum
    full_name: str
    public_key_hash: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 3600,
                "user_id": 42,
                "username": "dr_smith",
                "email": "dr.smith@hospital.com",
                "role": "DOCTOR",
                "full_name": "Dr. John Smith",
                "public_key_hash": "7f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f"
            }
        }


# ==================== User Profile ====================

class UserProfile(BaseModel):
    """User profile information"""
    
    user_id: int
    username: str
    email: str
    role: UserRoleEnum
    full_name: str
    
    # Public Key Info (safe to share)
    public_key_hash: str
    public_key_compressed: str
    
    # Status
    is_active: bool
    is_verified: bool
    
    # Timestamps
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True  # For SQLAlchemy conversion
        json_schema_extra = {
            "example": {
                "user_id": 42,
                "username": "dr_smith",
                "email": "dr.smith@hospital.com",
                "role": "DOCTOR",
                "full_name": "Dr. John Smith",
                "public_key_hash": "7f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
                "public_key_compressed": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
                "is_active": True,
                "is_verified": True,
                "created_at": "2025-02-15T10:30:00Z",
                "last_login": "2025-02-15T14:45:00Z"
            }
        }


# ==================== Public Key Retrieval ====================

class PublicKeyResponse(BaseModel):
    """Public key information (shared with others for encryption)"""
    
    public_key_hash: str
    public_key_uncompressed: str  # Full 65-byte public key
    public_key_compressed: str    # 33-byte compressed format
    algorithm: str = "ECDSA-P256"
    
    class Config:
        json_schema_extra = {
            "example": {
                "public_key_hash": "7f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
                "public_key_uncompressed": "04a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a...",
                "public_key_compressed": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
                "algorithm": "ECDSA-P256"
            }
        }


# ==================== Error Responses ====================

class ErrorResponse(BaseModel):
    """Standard error response"""
    
    status: int
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": 400,
                "error": "ValidationError",
                "detail": "Username must be 3-50 characters",
                "timestamp": "2025-02-15T10:30:00Z"
            }
        }


class ValidationErrorResponse(BaseModel):
    """Detailed validation error response"""
    
    status: int = 422
    error: str = "ValidationError"
    errors: list = Field(..., description="List of field validation errors")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": 422,
                "error": "ValidationError",
                "errors": [
                    {
                        "field": "password",
                        "message": "Password must contain at least one uppercase letter"
                    },
                    {
                        "field": "username",
                        "message": "Username already exists"
                    }
                ]
            }
        }
