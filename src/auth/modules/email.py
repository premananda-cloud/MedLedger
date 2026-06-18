# modules/email.py
import secrets
import time
import re
import json
from pathlib import Path
from typing import Dict, Optional, Set, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
import os
import hmac


class EmailStatus(Enum):
    """Classification of email addresses"""
    VALID = "valid"
    DISPOSABLE = "disposable"
    SPAM = "spam"
    INVALID_FORMAT = "invalid_format"
    BLOCKED_DOMAIN = "blocked_domain"


@dataclass
class VerificationRecord:
    """Stores verification data for an email"""
    code: str
    expires_at: float
    attempts: int = 0
    verified: bool = False


@dataclass
class EmailValidationResult:
    """Result of email validation check"""
    is_valid: bool
    status: EmailStatus
    message: str
    normalized_email: Optional[str] = None


class EmailValidator:
    """Validates email format and checks against blacklists"""

    # Common disposable email domains (you can load these from a file/API)
    DISPOSABLE_DOMAINS = {
        'mailinator.com', 'guerrillamail.com', 'tempmail.com', '10minutemail.com',
        'yopmail.com', 'throwaway.email', 'sharklasers.com', 'trashmail.com',
        'fakeinbox.com', 'temp-mail.org', 'dispostable.com', 'maildrop.cc',
        'getairmail.com', 'deadaddress.com', 'discard.email', 'spam4.me',
        'anonaddy.com', 'simplelogin.com', 'duck.com'  # DuckDuckGo email protection
    }

    # Known spam/TOR/abuse domains
    SPAM_DOMAINS = {
        '0-mail.com', 'spam.la', 'spamhog.com', 'mailsac.com',
        'tmail.com', 'xagf.com', 'bcaoo.com', 'fvzck.com',
        # Add more from your repository
    }

    def __init__(self, blocklist_path: Optional[Path] = None):
        """
        Initialize email validator

        Args:
            blocklist_path: Path to JSON file containing additional blocked domains
        """
        self.custom_blocked_domains: Set[str] = set()

        if blocklist_path and blocklist_path.exists():
            self._load_custom_blocklist(blocklist_path)

    def _load_custom_blocklist(self, path: Path):
        """Load custom blocked domains from JSON file"""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    domains = data.get('disposable_domains', []) + data.get('spam_domains', []) + data.get('blocked_domains', [])
                    self.custom_blocked_domains.update(domains)
                elif isinstance(data, list):
                    self.custom_blocked_domains.update(data)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load blocklist from {path}: {e}")

    @staticmethod
    def validate_format(email: str) -> bool:
        """
        Validate email format using regex

        Returns True if email format is valid
        """
        if not email or '@' not in email:
            return False

        # RFC 5322 compliant email regex (simplified)
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def classify_email(self, email: str) -> EmailValidationResult:
        """
        Classify an email address

        Returns EmailValidationResult with status and message
        """
        if not email:
            return EmailValidationResult(
                is_valid=False,
                status=EmailStatus.INVALID_FORMAT,
                message="Email address is empty"
            )

        if not self.validate_format(email):
            return EmailValidationResult(
                is_valid=False,
                status=EmailStatus.INVALID_FORMAT,
                message="Invalid email format"
            )

        normalized = email.lower().strip()

        # Extract domain
        try:
            domain = normalized.split('@')[1]
        except IndexError:
            return EmailValidationResult(
                is_valid=False,
                status=EmailStatus.INVALID_FORMAT,
                message="Could not extract domain"
            )

        # Check against disposable domains
        if domain in self.DISPOSABLE_DOMAINS or domain in self.custom_blocked_domains:
            return EmailValidationResult(
                is_valid=False,
                status=EmailStatus.DISPOSABLE,
                message="Disposable email addresses are not allowed",
                normalized_email=normalized
            )

        # Check against spam domains
        if domain in self.SPAM_DOMAINS:
            return EmailValidationResult(
                is_valid=False,
                status=EmailStatus.SPAM,
                message="This email domain is blocked",
                normalized_email=normalized
            )

        # Check for common tricks
        if self._detect_plus_addressing_trick(normalized):
            return EmailValidationResult(
                is_valid=False,
                status=EmailStatus.SPAM,
                message="Email address appears suspicious",
                normalized_email=normalized
            )

        return EmailValidationResult(
            is_valid=True,
            status=EmailStatus.VALID,
            message="Email is valid",
            normalized_email=normalized
        )

    def _detect_plus_addressing_trick(self, email: str) -> bool:
        """
        Detect abuse of plus addressing (e.g., user+spam1@gmail.com, user+spam2@gmail.com)
        Returns True if pattern looks like abuse
        """
        local_part = email.split('@')[0]
        if '+' in local_part:
            # Check for random strings after plus (potential spam pattern)
            after_plus = local_part.split('+')[1]
            if len(after_plus) > 10 and any(c.isdigit() for c in after_plus):
                return True
        return False


class EmailVerifier:
    """
    Email verification system with code generation and validation

    Features:
    - Time-based code expiry
    - Attempt limiting
    - Email validation (format + blacklist checking)
    - Test mode support
    """

    def __init__(
        self,
        code_length: int = 6,
        expiry_seconds: int = 600,  # 10 minutes
        max_attempts: int = 3,
        blocklist_path: Optional[Path] = None,
        require_email_validation: bool = True
    ):
        """
        Initialize email verifier

        Args:
            code_length: Length of verification code
            expiry_seconds: Code expiry time in seconds
            max_attempts: Maximum verification attempts
            blocklist_path: Path to custom blocklist JSON file
            require_email_validation: Whether to validate emails before generating codes
        """
        self.code_length = code_length
        self.expiry_seconds = expiry_seconds
        self.max_attempts = max_attempts
        self.require_email_validation = require_email_validation
        self.codes: Dict[str, VerificationRecord] = {}
        self.is_test = os.getenv('APP_ENV') == 'test' or os.getenv('TESTING') == 'true'
        self.email_validator = EmailValidator(blocklist_path=blocklist_path)

    def validate_email(self, email: str) -> EmailValidationResult:
        """
        Validate email without generating code

        Use this before generate_code() to check email validity first
        """
        return self.email_validator.classify_email(email)

    def generate_code(self, email: str) -> Tuple[Dict, Optional[EmailValidationResult]]:
        """
        Generate verification code for an email

        Returns:
            Tuple of (code_info_dict, validation_result_or_None)
        """
        normalized_email = email.lower().strip()

        # Validate email if required
        validation_result = None
        if self.require_email_validation:
            validation_result = self.email_validator.classify_email(email)
            if not validation_result.is_valid:
                return {
                    'error': True,
                    'code': None,
                    'message': validation_result.message,
                    'status': validation_result.status.value
                }, validation_result

        # Generate cryptographically secure random code
        code = ''.join(
            str(secrets.randbelow(10))
            for _ in range(self.code_length)
        )

        # Store verification record
        self.codes[normalized_email] = VerificationRecord(
            code=code,
            expires_at=time.time() + self.expiry_seconds,
            attempts=0,
            verified=False
        )

        # In non-test environments, you would send this via email
        if not self.is_test:
            # TODO: Integrate with email sending service (SMTP, SendGrid, etc.)
            print(f"[EMAIL] Verification code for {email}: {code}")

        return {
            'code': code,
            'expires_in_seconds': self.expiry_seconds,
            'expires_at': int(time.time() + self.expiry_seconds),
            'timestamp': int(time.time()),
            'message': 'Verification code generated'
        }, validation_result

    def verify_code(self, email: str, code: str) -> Dict:
        """
        Verify a code for an email address

        Returns:
            Dict with verification result
        """
        normalized_email = email.lower().strip()
        record = self.codes.get(normalized_email)

        # No code found
        if not record:
            return {
                'verified': False,
                'message': 'No verification code found for this email',
                'attempts_left': 0
            }

        # Already verified
        if record.verified:
            return {
                'verified': False,
                'message': 'Email already verified',
                'attempts_left': 0
            }

        # Code expired
        if time.time() > record.expires_at:
            self.codes.pop(normalized_email, None)
            return {
                'verified': False,
                'message': 'Verification code has expired',
                'attempts_left': 0
            }

        # Too many attempts
        if record.attempts >= self.max_attempts:
            self.codes.pop(normalized_email, None)
            return {
                'verified': False,
                'message': 'Too many failed attempts. Request a new code.',
                'attempts_left': 0
            }

        # Increment attempt counter
        record.attempts += 1

        # Check code match
        if record.code != code:
            remaining = self.max_attempts - record.attempts
            return {
                'verified': False,
                'message': f'Invalid code. {remaining} attempts remaining',
                'attempts_left': remaining
            }

        # Success! Mark as verified
        record.verified = True
        return {
            'verified': True,
            'message': 'Email verified successfully',
            'attempts_left': self.max_attempts - record.attempts
        }

    def is_verified(self, email: str) -> bool:
        """Check if an email has been verified"""
        if not email:
            return False
        record = self.codes.get(email.lower().strip())
        return record.verified if record else False

    def get_code_for_testing(self, email: str) -> Optional[str]:
        """
        Get stored code for testing purposes.
        Caller is responsible for only using this in test contexts.
        """
        record = self.codes.get(email.lower().strip() if email else '')
        return record.code if record else None

    def get_status(self) -> Dict:
        """Get current status of the verifier"""
        return {
            'active_codes': len(self.codes),
            'expiry_seconds': self.expiry_seconds,
            'pending_verifications': sum(1 for r in self.codes.values() if not r.verified),
            'verified_count': sum(1 for r in self.codes.values() if r.verified)
        }

    def reset(self):
        """Reset all stored codes (useful for testing)"""
        self.codes.clear()


# Singleton pattern (like your JS version)
_verifier_instance: Optional[EmailVerifier] = None

# email.py - Update the singleton factory

def get_email_verifier(
    code_length: int = 6,
    expiry_seconds: int = 600,
    max_attempts: int = 3,
    blocklist_path: Optional[Path] = None,
    require_email_validation: bool = True,
    force_new: bool = False  # Allow forced recreation
) -> EmailVerifier:
    """
    Get or create the singleton EmailVerifier instance

    Args:
        code_length: Length of verification code
        expiry_seconds: Code expiry time in seconds
        max_attempts: Maximum verification attempts
        blocklist_path: Path to blocklist JSON
        require_email_validation: Whether to validate emails
        force_new: Force creation of new instance with these params
    """
    global _verifier_instance
    if _verifier_instance is None or force_new:
        if _verifier_instance:
            _verifier_instance.reset()

        if blocklist_path is None:
            default_paths = [
                Path('data/blocked_domains.json'),
                Path('auth/data/blocked_domains.json'),
            ]
            for path in default_paths:
                if path.exists():
                    blocklist_path = path
                    break

        _verifier_instance = EmailVerifier(
            code_length=code_length,
            expiry_seconds=expiry_seconds,
            max_attempts=max_attempts,
            blocklist_path=blocklist_path,
            require_email_validation=require_email_validation
        )
    return _verifier_instance


def reset_email_verifier():
    """Reset the singleton instance (for testing)"""
    global _verifier_instance
    _verifier_instance = None
