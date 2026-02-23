"""
Registration Service - Business logic for user registration
Location: src/services/registration.py
"""

import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import jwt  # PyJWT 2.7.0 — installed as the "jwt" package alias

from src.database.models import User, UserRole, AuditLog, AuditAction
from src.crypto.key_manager import KeyManager
from src.schemas.user import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse, UserProfile


class RegistrationError(Exception):
    pass


class UserAlreadyExistsError(RegistrationError):
    pass


class PasswordHashError(RegistrationError):
    pass


class RegistrationService:

    def __init__(
        self,
        db: Session,
        jwt_secret: str,
        jwt_algorithm: str = "HS256",
        jwt_expiration_hours: int = 1
    ):
        self.db = db
        self.key_manager = KeyManager()
        # FIX #7: Fail fast if JWT secret is missing or is the insecure default
        if not jwt_secret or jwt_secret == "your-secret-key-change-in-production":
            raise ValueError(
                "JWT_SECRET environment variable must be set to a strong random value. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiration_hours = jwt_expiration_hours

    # ==================== User Registration ====================

    # FIX #2: Changed to regular (non-async) method to match route calls
    def register_user(self, request: RegisterRequest) -> RegisterResponse:
        """
        Complete user registration workflow.
        Returns RegisterResponse with private key (returned ONCE only).
        """
        self._check_duplicate_users(request.email, request.username)

        try:
            keypair = self.key_manager.generate_keypair()
        except Exception as e:
            raise RegistrationError(f"Failed to generate keypair: {str(e)}")

        try:
            password_hash = self._hash_password(request.password)
        except Exception as e:
            raise PasswordHashError(f"Failed to hash password: {str(e)}")

        try:
            user = User(
                username=request.username,
                email=request.email,
                full_name=request.full_name,
                role=UserRole[request.role.value],
                public_key_hex=keypair.public_key_hex,
                public_key_compressed=keypair.public_key_compressed,
                public_key_hash=keypair.public_key_hash,
                password_hash=password_hash,
                is_active=True,
                is_verified=False,
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
        except IntegrityError as e:
            self.db.rollback()
            raise UserAlreadyExistsError(f"User already exists: {str(e)}")
        except Exception as e:
            self.db.rollback()
            raise RegistrationError(f"Database error: {str(e)}")

        access_token = self._generate_jwt_token(user.id, user.email)
        self._log_user_registration(user.id, user.username, request.role)

        try:
            qr_code = self.key_manager.generate_key_qr_code(keypair.private_key_pem)
        except Exception:
            qr_code = ""

        return RegisterResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=request.role,
            full_name=request.full_name,
            public_key_hash=keypair.public_key_hash,
            public_key_compressed=keypair.public_key_compressed,
            private_key_pem=keypair.private_key_pem,
            private_key_qr=qr_code,
            access_token=access_token,
            created_at=user.created_at,
        )

    # FIX #2: Changed to regular (non-async) method
    def login_user(self, request: LoginRequest) -> LoginResponse:
        """Authenticate user and return JWT."""
        user = self.db.query(User).filter(User.email == request.email).first()

        if not user:
            self._log_failed_login(request.email, "User not found")
            raise RegistrationError("Invalid email or password")

        if not user.is_active:
            self._log_failed_login(request.email, "User not active")
            raise RegistrationError("User account is disabled")

        if not self._verify_password(request.password, user.password_hash):
            self._log_failed_login(request.email, "Invalid password")
            raise RegistrationError("Invalid email or password")

        access_token = self._generate_jwt_token(user.id, user.email)
        user.last_login = datetime.utcnow()
        self.db.commit()
        self._log_login_success(user.id, request.email)

        return LoginResponse(
            access_token=access_token,
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=UserRole(user.role.value),
            full_name=user.full_name,
            public_key_hash=user.public_key_hash,
        )

    # FIX #2: Changed to regular (non-async) method
    def get_user_profile(self, user_id: int) -> UserProfile:
        """Return user profile (non-sensitive fields only)."""
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise RegistrationError("User not found")

        return UserProfile(
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=UserRole(user.role.value),
            full_name=user.full_name,
            public_key_hash=user.public_key_hash,
            public_key_compressed=user.public_key_compressed,
            is_active=user.is_active,
            is_verified=user.is_verified,
            created_at=user.created_at,
            last_login=user.last_login,
        )

    # ==================== Password Management ====================

    def _hash_password(self, password: str) -> str:
        """Hash password with PBKDF2-HMAC-SHA256 (100,000 iterations)."""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        iterations = 100_000
        salt = os.urandom(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        hash_bytes = kdf.derive(password.encode("utf-8"))
        return f"sha256${iterations}${salt.hex()}${hash_bytes.hex()}"

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Constant-time password verification."""
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            import hmac as hmac_lib

            parts = password_hash.split("$")
            if len(parts) != 4 or parts[0] != "sha256":
                return False

            _, iterations, salt_hex, hash_hex = parts
            iterations = int(iterations)
            salt = bytes.fromhex(salt_hex)
            stored_hash = bytes.fromhex(hash_hex)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend(),
            )
            computed_hash = kdf.derive(password.encode("utf-8"))
            return hmac_lib.compare_digest(computed_hash, stored_hash)
        except Exception:
            return False

    # ==================== JWT Token Management ====================

    # FIX #3: Use PyJWT for both encode AND decode (was using custom encoder + PyJWT decoder)
    def _generate_jwt_token(self, user_id: int, email: str) -> str:
        """Generate a signed JWT using PyJWT."""
        now = datetime.utcnow()
        payload = {
            "sub": str(user_id),
            "email": email,
            "iat": now,
            "exp": now + timedelta(hours=self.jwt_expiration_hours),
        }
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def verify_jwt_token(self, token: str) -> dict:
        """Verify and decode a JWT. Raises RegistrationError on failure."""
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
        except jwt.ExpiredSignatureError:
            raise RegistrationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise RegistrationError(f"Invalid token: {str(e)}")

    # ==================== Validation ====================

    def _check_duplicate_users(self, email: str, username: str):
        if self.db.query(User).filter(User.email == email).first():
            raise UserAlreadyExistsError(f"Email already registered: {email}")
        if self.db.query(User).filter(User.username == username).first():
            raise UserAlreadyExistsError(f"Username already taken: {username}")

    # ==================== Audit Logging ====================

    def _log_user_registration(self, user_id: int, username: str, role):
        """Log registration event to audit trail."""
        try:
            event_hash = hashlib.sha256(
                f"{user_id}${username}${role}${datetime.utcnow().isoformat()}".encode()
            ).hexdigest()
            audit_log = AuditLog(
                user_id=user_id,
                action=AuditAction.USER_REGISTERED,
                description=f"User registered as {role}",
                # FIX #5: Use correct field name 'extra_data', not 'metadata'
                extra_data=json.dumps({"username": username, "role": str(role)}),
                event_hash=event_hash,
            )
            self.db.add(audit_log)
            self.db.commit()
        except Exception as e:
            print(f"Warning: Failed to log registration: {str(e)}")

    def _log_login_success(self, user_id: int, email: str):
        try:
            event_hash = hashlib.sha256(
                f"{user_id}${email}$LOGIN${datetime.utcnow().isoformat()}".encode()
            ).hexdigest()
            audit_log = AuditLog(
                user_id=user_id,
                action=AuditAction.LOGIN_SUCCESS,
                description="Login successful",
                event_hash=event_hash,
            )
            self.db.add(audit_log)
            self.db.commit()
        except Exception as e:
            print(f"Warning: Failed to log login: {str(e)}")

    def _log_failed_login(self, email: str, reason: str):
        # FIX #4: AuditLog.user_id is NOT NULL — use a sentinel value (0) for
        # anonymous/unknown users so we never violate the constraint.
        try:
            event_hash = hashlib.sha256(
                f"{email}$LOGIN_FAILED${reason}${datetime.utcnow().isoformat()}".encode()
            ).hexdigest()
            audit_log = AuditLog(
                user_id=0,           # 0 = unknown/anonymous (no FK enforced on SQLite; for
                                     # Postgres add a dedicated "anonymous" user with id=0)
                action=AuditAction.LOGIN_FAILED,
                description=f"Login failed for {email}: {reason}",
                extra_data=json.dumps({"email": email, "reason": reason}),
                event_hash=event_hash,
            )
            self.db.add(audit_log)
            self.db.commit()
        except Exception as e:
            print(f"Warning: Failed to log failed login: {str(e)}")