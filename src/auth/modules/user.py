# modules/user.py
import os
import hashlib
import secrets
import re
import hmac
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

# Import our storage module
from .storage import get_storage, reset_storage


class PasswordStrength(Enum):
    """Password strength levels"""
    INVALID = "invalid"
    WEAK = "weak"
    FAIR = "fair"
    GOOD = "good"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


@dataclass
class ValidationResult:
    """Result of validation checks"""
    valid: bool
    message: str
    details: Optional[Dict] = None


@dataclass
class PasswordValidationResult(ValidationResult):
    """Password validation with strength info"""
    strength: int = 0
    strength_label: PasswordStrength = PasswordStrength.INVALID


@dataclass
class CreateUserResult:
    """Result of user creation"""
    created: bool
    message: str
    user_id: Optional[str] = None


class UserManager:
    """
    User management system with secure password handling

    Features:
    - Username validation with customizable rules
    - Password strength checking
    - PBKDF2-SHA512 password hashing (OWASP recommended)
    - Timing-safe password comparison
    - User CRUD operations
    - Configurable security parameters
    """

    def __init__(
        self,
        min_username: int = 3,
        max_username: int = 30,
        min_password: int = 8,
        pbkdf2_iterations: Optional[int] = None,
        pbkdf2_key_length: int = 64,
        reserved_usernames: Optional[set] = None,
        _storage=None
    ):
        """
        Initialize UserManager

        Args:
            min_username: Minimum username length
            max_username: Maximum username length
            min_password: Minimum password length
            pbkdf2_iterations: PBKDF2 iterations (auto-set based on environment)
            pbkdf2_key_length: Length of derived key in bytes
            reserved_usernames: Set of reserved usernames that cannot be used
        """
        self.min_username = min_username
        self.max_username = max_username
        self.min_password = min_password
        self.pbkdf2_key_length = pbkdf2_key_length

        # Auto-set iterations based on environment
        if pbkdf2_iterations is None:
            is_test = os.getenv('APP_ENV') == 'test' or os.getenv('TESTING') == 'true'
            self.pbkdf2_iterations = 1000 if is_test else 600_000
        else:
            self.pbkdf2_iterations = pbkdf2_iterations

        # Reserved usernames (system accounts, etc.)
        self.reserved_usernames = reserved_usernames or {
            'admin', 'root', 'system', 'administrator', 'moderator',
            'support', 'help', 'info', 'security', 'abuse', 'postmaster',
            'webmaster', 'hostmaster', 'noreply', 'no-reply', 'null',
            'undefined', 'anonymous', 'guest', 'user', 'test'
        }

        # Get storage instance (use injected one if provided, else singleton)
        self.storage = _storage if _storage is not None else get_storage()

    def validate_username(self, username: str) -> ValidationResult:
        """
        Validate username format and availability

        Args:
            username: Username to validate

        Returns:
            ValidationResult with validity and message
        """
        # Check if username is provided
        if not username or not isinstance(username, str):
            return ValidationResult(
                valid=False,
                message="Username is required"
            )

        # Strip whitespace
        username = username.strip()

        # Check minimum length
        if len(username) < self.min_username:
            return ValidationResult(
                valid=False,
                message=f"Username must be at least {self.min_username} characters"
            )

        # Check maximum length
        if len(username) > self.max_username:
            return ValidationResult(
                valid=False,
                message=f"Username must be at most {self.max_username} characters"
            )

        # Check valid characters (letters, numbers, underscore)
        valid_pattern = r'^[a-zA-Z0-9_]+$'
        if not re.match(valid_pattern, username):
            return ValidationResult(
                valid=False,
                message="Username can only contain letters, numbers, and underscores"
            )

        # Check for common patterns indicating spam
        spam_patterns = [
            r'\d{5,}',  # 5+ consecutive digits
            r'(.)\1{4,}',  # Same character repeated 5+ times
            r'[a-z]{10,}\d{5,}',  # Long letters followed by many digits
        ]
        for pattern in spam_patterns:
            if re.search(pattern, username):
                return ValidationResult(
                    valid=False,
                    message="Username appears to be automatically generated"
                )

        # Check reserved usernames
        if username.lower() in self.reserved_usernames:
            return ValidationResult(
                valid=False,
                message="This username is reserved"
            )

        # Check if username already exists
        if self.storage.username_exists(username):
            return ValidationResult(
                valid=False,
                message="Username already taken"
            )

        return ValidationResult(
            valid=True,
            message="Username is valid"
        )

    def validate_password(self, password: str) -> PasswordValidationResult:
        """
        Validate password strength

        Checks for:
        - Uppercase letters
        - Lowercase letters
        - Numbers
        - Special characters
        - Length bonus (12+ characters)

        Args:
            password: Password to validate

        Returns:
            PasswordValidationResult with strength info
        """
        if not password or not isinstance(password, str):
            return PasswordValidationResult(
                valid=False,
                message="Password is required",
                strength=0,
                strength_label=PasswordStrength.INVALID
            )

        # Calculate complexity criteria
        criteria = 0
        details = {
            'has_uppercase': False,
            'has_lowercase': False,
            'has_digit': False,
            'has_special': False,
            'has_length_bonus': False,
            'length': len(password)
        }

        if re.search(r'[A-Z]', password):
            criteria += 1
            details['has_uppercase'] = True

        if re.search(r'[a-z]', password):
            criteria += 1
            details['has_lowercase'] = True

        if re.search(r'[0-9]', password):
            criteria += 1
            details['has_digit'] = True

        if re.search(r'[!@#$%^&*(),.?\":{}|<>[\]\\;\/\'`~\-_=+]', password):
            criteria += 1
            details['has_special'] = True

        if len(password) >= 12:
            criteria += 1
            details['has_length_bonus'] = True

        # Check for common passwords (simple check)
        common_passwords = {
            'password', '12345678', 'qwerty123', 'letmein123',
            'password123', 'admin123', 'welcome1', 'monkey123'
        }
        is_common = password.lower() in common_passwords

        # Determine strength label
        if criteria >= 5 and len(password) >= 16 and not is_common:
            strength_label = PasswordStrength.VERY_STRONG
        elif criteria >= 4 and len(password) >= 12 and not is_common:
            strength_label = PasswordStrength.STRONG
        elif criteria >= 3 and len(password) >= 10:
            strength_label = PasswordStrength.GOOD
        elif criteria >= 2 and len(password) >= self.min_password:
            strength_label = PasswordStrength.FAIR
        elif len(password) >= self.min_password:
            strength_label = PasswordStrength.WEAK
        else:
            strength_label = PasswordStrength.INVALID

        # Require at least 3 criteria AND minimum length
        meets_minimum = criteria >= 3 and len(password) >= self.min_password

        # Additional checks
        if is_common:
            return PasswordValidationResult(
                valid=False,  # Correctly invalid
                message="This password is too common. Please choose a stronger password.",
                strength=criteria,
                strength_label=PasswordStrength.WEAK,  # Label reflects detected strength
                details=details
            )

        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'qazwsx']
        if any(pattern in password.lower() for pattern in keyboard_patterns):
            strength_label = PasswordStrength.WEAK
            return PasswordValidationResult(
                valid=meets_minimum,
                message="Password contains keyboard pattern" if meets_minimum
                        else "Password must meet at least 3 of 5 complexity criteria",
                strength=criteria,
                strength_label=strength_label,
                details=details
            )

        return PasswordValidationResult(
            valid=meets_minimum,
            message="Password is valid" if meets_minimum
                    else "Password must meet at least 3 of 5 complexity criteria and be at least "
                         f"{self.min_password} characters",
            strength=criteria,
            strength_label=strength_label,
            details=details
        )

    def hash_password(
        self,
        password: str,
        salt: Optional[bytes] = None
    ) -> Tuple[str, str]:
        """
        Hash password using PBKDF2-SHA512

        Args:
            password: Plain text password
            salt: Optional salt (generated if not provided)

        Returns:
            Tuple of (hash_hex, salt_hex)
        """
        if salt is None:
            # Generate cryptographically secure random salt
            salt = secrets.token_bytes(16)

        # Convert salt to bytes if it's hex string
        if isinstance(salt, str):
            salt = bytes.fromhex(salt)

        # Use PBKDF2-HMAC-SHA512
        derived_key = hashlib.pbkdf2_hmac(
            'sha512',
            password.encode('utf-8'),
            salt,
            self.pbkdf2_iterations,
            dklen=self.pbkdf2_key_length
        )

        return derived_key.hex(), salt.hex()

    def create_user(
        self,
        username: str,
        password: str,
        email: str,
        extra_data: Optional[Dict] = None
    ) -> CreateUserResult:
        """
        Create a new user

        Args:
            username: Username
            password: Plain text password
            email: Email address
            extra_data: Additional user data to store

        Returns:
            CreateUserResult with creation status
        """
        # Validate username
        username_valid = self.validate_username(username)
        if not username_valid.valid:
            return CreateUserResult(
                created=False,
                message=username_valid.message
            )

        # Validate password
        password_valid = self.validate_password(password)
        if not password_valid.valid:
            return CreateUserResult(
                created=False,
                message=password_valid.message
            )

        # Check email uniqueness
        if email and self.storage.email_exists(email):
            return CreateUserResult(
                created=False,
                message="Email already registered"
            )

        # Hash the password
        password_hash, salt = self.hash_password(password)

        # Generate unique user ID
        user_id = secrets.token_hex(16)

        # Create user object
        lower_username = username.lower()
        now = datetime.now(timezone.utc)

        user = {
            'userId': user_id,
            'username': lower_username,
            'email': email.lower() if email else None,
            'passwordHash': password_hash,
            'salt': salt,
            'createdAt': now.isoformat(),
            'updatedAt': now.isoformat(),
            'totpEnabled': False,  # Changed to False by default
            'emailVerified': False,  # Changed to False by default
            'verified': False,
            'pbkdf2Iterations': self.pbkdf2_iterations,
            'passwordStrength': password_valid.strength_label.value
        }

        # Add any extra data
        if extra_data:
            user.update(extra_data)

        # Save user to storage
        saved = self.storage.save_user_sync(user)
        if not saved:
            return CreateUserResult(
                created=False,
                message="Username or email already exists"
            )

        return CreateUserResult(
            created=True,
            message="User created successfully",
            user_id=user_id
        )

    async def create_user_async(
        self,
        username: str,
        password: str,
        email: str,
        extra_data: Optional[Dict] = None
    ) -> CreateUserResult:
        """
        Async version of create_user for FastAPI

        Args:
            username: Username
            password: Plain text password
            email: Email address
            extra_data: Additional user data to store

        Returns:
            CreateUserResult with creation status
        """
        # Validate username
        username_valid = self.validate_username(username)
        if not username_valid.valid:
            return CreateUserResult(
                created=False,
                message=username_valid.message
            )

        # Validate password
        password_valid = self.validate_password(password)
        if not password_valid.valid:
            return CreateUserResult(
                created=False,
                message=password_valid.message
            )

        # Check email uniqueness
        if email and self.storage.email_exists(email):
            return CreateUserResult(
                created=False,
                message="Email already registered"
            )

        # Hash the password
        password_hash, salt = self.hash_password(password)

        # Generate unique user ID
        user_id = secrets.token_hex(16)

        # Create user object
        lower_username = username.lower()
        now = datetime.now(timezone.utc)

        user = {
            'userId': user_id,
            'username': lower_username,
            'email': email.lower() if email else None,
            'passwordHash': password_hash,
            'salt': salt,
            'createdAt': now.isoformat(),
            'updatedAt': now.isoformat(),
            'totpEnabled': False,
            'emailVerified': False,
            'verified': False,
            'pbkdf2Iterations': self.pbkdf2_iterations,
            'passwordStrength': password_valid.strength_label.value
        }

        if extra_data:
            user.update(extra_data)

        # Save user to storage (async)
        saved = await self.storage.save_user(user)
        if not saved:
            return CreateUserResult(
                created=False,
                message="Username or email already exists"
            )

        return CreateUserResult(
            created=True,
            message="User created successfully",
            user_id=user_id
        )

    def verify_password(self, username: str, password: str) -> bool:
        """
        Verify a password for a user

        Uses timing-safe comparison to prevent timing attacks

        Args:
            username: Username
            password: Plain text password to verify

        Returns:
            True if password is correct
        """
        user = self.storage.get_user_by_username(username)
        if not user:
            # Still hash to prevent user enumeration via timing
            dummy_salt = secrets.token_bytes(16)
            self.hash_password(password, dummy_salt)
            return False

        # Get stored hash and salt
        stored_hash = user.get('passwordHash')
        stored_salt = user.get('salt')

        if not stored_hash or not stored_salt:
            return False

        # Hash the provided password with stored salt
        computed_hash, _ = self.hash_password(password, stored_salt)

        # Timing-safe comparison
        return hmac.compare_digest(
            bytes.fromhex(computed_hash),
            bytes.fromhex(stored_hash)
        )

    def get_user_info(self, username: str) -> Optional[Dict]:
        """
        Get public user information

        Args:
            username: Username

        Returns:
            Dict with user info or None
        """
        user = self.storage.get_user_by_username(username)
        if not user:
            return None

        return {
            'username': user.get('username'),
            'email': user.get('email'),
            'userId': user.get('userId'),
            'createdAt': user.get('createdAt'),
            'updatedAt': user.get('updatedAt'),
            'totpEnabled': user.get('totpEnabled', False),
            'emailVerified': user.get('emailVerified', False),
            'verified': user.get('verified', False)
        }

    def get_full_user(self, username: str) -> Optional[Dict]:
        """
        Get complete user data (for internal use)

        Args:
            username: Username

        Returns:
            Full user dict or None
        """
        return self.storage.get_user_by_username(username)

    def update_password(
        self,
        username: str,
        old_password: str,
        new_password: str
    ) -> ValidationResult:
        """
        Change user password

        Args:
            username: Username
            old_password: Current password
            new_password: New password

        Returns:
            ValidationResult with update status
        """
        # Verify old password
        if not self.verify_password(username, old_password):
            return ValidationResult(
                valid=False,
                message="Current password is incorrect"
            )

        # Validate new password
        password_valid = self.validate_password(new_password)
        if not password_valid.valid:
            return ValidationResult(
                valid=False,
                message=password_valid.message
            )

        # Hash new password
        new_hash, new_salt = self.hash_password(new_password)

        # Update user
        success = self.storage.update_user_sync(username, {
            'passwordHash': new_hash,
            'salt': new_salt,
            'pbkdf2Iterations': self.pbkdf2_iterations,
            'updatedAt': datetime.now(timezone.utc).isoformat()
        })

        if not success:
            return ValidationResult(
                valid=False,
                message="Failed to update password"
            )

        return ValidationResult(
            valid=True,
            message="Password updated successfully"
        )

    def enable_totp(self, username: str, totp_secret: str) -> bool:
        """
        Enable TOTP for a user

        Args:
            username: Username
            totp_secret: TOTP secret key

        Returns:
            True if enabled successfully
        """
        return self.storage.update_user_sync(username, {
            'totpEnabled': True,
            'totpSecret': totp_secret,
            'updatedAt': datetime.now(timezone.utc).isoformat()
        })

    def verify_email(self, username: str) -> bool:
        """
        Mark user email as verified

        Args:
            username: Username

        Returns:
            True if updated successfully
        """
        return self.storage.update_user_sync(username, {
            'emailVerified': True,
            'verified': True,
            'updatedAt': datetime.now(timezone.utc).isoformat()
        })

    def delete_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Delete a user account

        Args:
            username: Username
            password: Password for verification

        Returns:
            Tuple of (success, message)
        """
        if not self.verify_password(username, password):
            return False, "Invalid password"

        success = self.storage.delete_user_sync(username)
        if success:
            return True, "User deleted successfully"
        return False, "Failed to delete user"

    def list_users(self, page: int = 1, limit: int = 50, include_email: bool = False) -> Dict:
        """
        List users with pagination

        Args:
            page: Page number (1-based)
            limit: Users per page

        Returns:
            Dict with users list and pagination info
        """
        if include_email:
            all_users = self.storage.get_all_users()
        else:
            # Don't expose emails in public listings
            all_users = [
                {k: v for k, v in u.items() if k != 'email'}
                for u in self.storage.get_all_users()
            ]
        total = len(all_users)
        start = (page - 1) * limit
        end = start + limit

        return {
            'users': all_users[start:end],
            'total': total,
            'page': page,
            'limit': limit,
            'pages': (total + limit - 1) // limit
        }

    def get_stats(self) -> Dict:
        """
        Get user statistics

        Returns:
            Dict with user statistics
        """
        users = self.storage.get_all_users_full()

        total = len(users)
        verified = sum(1 for u in users if u.get('verified'))
        totp_enabled = sum(1 for u in users if u.get('totpEnabled'))
        email_verified = sum(1 for u in users if u.get('emailVerified'))

        return {
            'total_users': total,
            'verified_users': verified,
            'totp_enabled': totp_enabled,
            'email_verified': email_verified,
            'unverified_users': total - verified
        }

    async def reset(self) -> None:
        """Reset user manager (for testing)"""
        await self.storage.reset()


# Singleton pattern
_user_manager_instance: Optional[UserManager] = None


def get_user_manager(
    min_username: int = 3,
    max_username: int = 30,
    min_password: int = 8,
    pbkdf2_iterations: Optional[int] = None,
    reserved_usernames: Optional[set] = None
) -> UserManager:
    """
    Get or create the singleton UserManager instance

    Args:
        min_username: Minimum username length
        max_username: Maximum username length
        min_password: Minimum password length
        pbkdf2_iterations: PBKDF2 iterations
        reserved_usernames: Set of reserved usernames

    Returns:
        UserManager instance
    """
    global _user_manager_instance
    if _user_manager_instance is None:
        _user_manager_instance = UserManager(
            min_username=min_username,
            max_username=max_username,
            min_password=min_password,
            pbkdf2_iterations=pbkdf2_iterations,
            reserved_usernames=reserved_usernames
        )
    return _user_manager_instance


async def reset_user_manager() -> None:
    """Reset the singleton instance (for testing)"""
    global _user_manager_instance
    if _user_manager_instance:
        await _user_manager_instance.reset()
    _user_manager_instance = None
