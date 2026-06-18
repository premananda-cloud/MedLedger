# modules/totp.py
import pyotp
import time
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum


class TOTPAlgorithm(Enum):
    """Supported TOTP algorithms"""
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


@dataclass
class TOTPSetupResult:
    """Result of TOTP secret generation"""
    secret: str
    qr_code_uri: str
    manual_key: str
    issuer: str
    email: str


class TOTPManager:
    """
    Time-based One-Time Password manager

    Features:
    - Secret generation (160-bit = 20 bytes)
    - QR code URI generation (for frontend QR display)
    - Token verification with time window
    - Manual key entry support
    """

    def __init__(self, issuer: str = "AuthSystem", window: int = 1):
        """
        Initialize TOTP Manager

        Args:
            issuer: Name of the issuing organization (shown in authenticator app)
            window: Number of time steps to check before/after current (1 = ±30 seconds)
        """
        self.issuer = issuer
        self.window = window
        self.secrets: Dict[str, str] = {}  # email -> base32_secret

    def generate_secret(self, email: str) -> TOTPSetupResult:
        """
        Generate a new TOTP secret for an email address

        Args:
            email: User's email address

        Returns:
            TOTPSetupResult with secret, QR URI, and manual key
        """
        normalized_email = email.lower()

        # Generate a random base32 secret (pyotp uses 32 chars by default = 160 bits)
        secret = pyotp.random_base32()

        # Store the secret
        self.secrets[normalized_email] = secret

        # Create TOTP instance for URI generation
        totp = pyotp.TOTP(
            secret,
            issuer=self.issuer,
            name=email  # pyotp uses 'name' instead of 'label'
        )

        return TOTPSetupResult(
            secret=secret,
            qr_code_uri=totp.provisioning_uri(
                name=email,
                issuer_name=self.issuer
            ),
            manual_key=secret,
            issuer=self.issuer,
            email=email
        )

    def verify_token(self, email: str, token: str) -> Dict:
        """
        Verify a TOTP token for an email address

        Args:
            email: User's email address
            token: 6-digit TOTP code to verify

        Returns:
            Dict with verification result
        """
        normalized_email = email.lower()
        secret = self.secrets.get(normalized_email)

        if not secret:
            return {
                'verified': False,
                'remaining': 0,
                'message': 'TOTP not set up for this email'
            }

        # Create TOTP instance
        totp = pyotp.TOTP(
            secret,
            issuer=self.issuer,
            name=email
        )

        # Verify token with time window
        # pyotp.verify() returns True/False
        # We use the window parameter to check adjacent time steps
        is_valid = totp.verify(token, valid_window=self.window)

        if is_valid:
            return {
                'verified': True,
                'remaining': self.window,
                'message': 'TOTP verified successfully'
            }

        return {
            'verified': False,
            'remaining': 0,
            'message': 'Invalid TOTP token'
        }

    def verify_token_with_delta(self, email: str, token: str) -> Dict:
        """
        Verify token and get time step delta (more detailed than verify_token)

        Args:
            email: User's email address
            token: 6-digit TOTP code to verify

        Returns:
            Dict with delta information (matching JS version closer)
        """
        normalized_email = email.lower()
        secret = self.secrets.get(normalized_email)

        if not secret:
            return {
                'verified': False,
                'delta': None,
                'message': 'TOTP not set up for this email'
            }

        totp = pyotp.TOTP(
            secret,
            issuer=self.issuer,
            name=email
        )

        # Check current and adjacent time windows manually for delta info
        current_time = int(time.time())
        for delta in range(-self.window, self.window + 1):
            check_time = current_time + (delta * 30)  # 30-second TOTP period
            expected_token = totp.at(check_time)
            if expected_token == token:
                return {
                    'verified': True,
                    'delta': delta,
                    'message': f'TOTP verified (delta: {delta})'
                }

        return {
            'verified': False,
            'delta': None,
            'message': 'Invalid TOTP token'
        }

    def get_current_token(self, email: str) -> Optional[str]:
        """
        Get the current valid TOTP token for an email

        Args:
            email: User's email address

        Returns:
            Current 6-digit token or None
        """
        normalized_email = email.lower()
        secret = self.secrets.get(normalized_email)

        if not secret:
            return None

        totp = pyotp.TOTP(
            secret,
            issuer=self.issuer,
            name=email
        )

        return totp.now()

    def get_token_at_time(self, email: str, timestamp: float) -> Optional[str]:
        """
        Get TOTP token at a specific time (useful for testing)

        Args:
            email: User's email address
            timestamp: Unix timestamp

        Returns:
            Token at specified time or None
        """
        normalized_email = email.lower()
        secret = self.secrets.get(normalized_email)

        if not secret:
            return None

        totp = pyotp.TOTP(
            secret,
            issuer=self.issuer,
            name=email
        )

        return totp.at(int(timestamp))

    def has_secret(self, email: str) -> bool:
        """
        Check if a TOTP secret exists for an email

        Args:
            email: User's email address

        Returns:
            True if secret exists
        """
        if not email:
            return False
        return email.lower() in self.secrets

    def remove_secret(self, email: str) -> bool:
        """
        Remove TOTP secret for an email (e.g., when disabling 2FA)

        Args:
            email: User's email address

        Returns:
            True if secret was removed
        """
        normalized_email = email.lower()
        if normalized_email in self.secrets:
            del self.secrets[normalized_email]
            return True
        return False

    def get_setup_info(self, email: str) -> Optional[Dict]:
        """
        Get existing setup info without regenerating secret

        Returns None if no secret exists
        """
        normalized_email = email.lower()
        secret = self.secrets.get(normalized_email)

        if not secret:
            return None

        totp = pyotp.TOTP(
            secret,
            issuer=self.issuer,
            name=email
        )

        return {
            'secret': secret,
            'qr_code_uri': totp.provisioning_uri(
                name=email,
                issuer_name=self.issuer
            ),
            'manual_key': secret,
            'issuer': self.issuer,
            'email': email
        }

    def get_status(self) -> Dict:
        """Get current TOTP manager status"""
        return {
            'active_secrets': len(self.secrets),
            'issuer': self.issuer,
            'window': self.window,
            'users_with_totp': list(self.secrets.keys())
        }

    def reset(self):
        """Reset all stored secrets (for testing)"""
        self.secrets.clear()


# Alternative implementation with more granular control
class AdvancedTOTPManager(TOTPManager):
    """
    Extended TOTP manager with support for different algorithms and digits
    """

    def __init__(
        self,
        issuer: str = "AuthSystem",
        window: int = 1,
        digits: int = 6,
        interval: int = 30,
        algorithm: str = "sha1"
    ):
        super().__init__(issuer, window)
        self.digits = digits
        self.interval = interval
        self.algorithm = algorithm

    def generate_secret(self, email: str) -> TOTPSetupResult:
        """Override to support custom parameters"""
        normalized_email = email.lower()
        secret = pyotp.random_base32()
        self.secrets[normalized_email] = secret

        totp = pyotp.TOTP(
            secret,
            digits=self.digits,
            interval=self.interval,
            digest=self.algorithm,
            issuer=self.issuer,
            name=email
        )

        return TOTPSetupResult(
            secret=secret,
            qr_code_uri=totp.provisioning_uri(
                name=email,
                issuer_name=self.issuer
            ),
            manual_key=secret,
            issuer=self.issuer,
            email=email
        )


# Singleton pattern
_totp_instance: Optional[TOTPManager] = None


def get_totp_manager(
    issuer: str = "AuthSystem",
    window: int = 1
) -> TOTPManager:
    """
    Get or create the singleton TOTPManager instance

    Args:
        issuer: Organization name for authenticator apps
        window: Time window tolerance (±window periods of 30 seconds)
    """
    global _totp_instance
    if _totp_instance is None:
        _totp_instance = TOTPManager(issuer=issuer, window=window)
    return _totp_instance


def reset_totp_manager():
    """Reset the singleton instance (for testing)"""
    global _totp_instance
    _totp_instance = None


# Utility functions for FastAPI integration
def generate_totp_qr_svg(email: str, issuer: str = "AuthSystem") -> Optional[str]:
    """
    Generate QR code as SVG string (optional, if you want server-side QR)
    Requires: pip install qrcode
    """
    try:
        import qrcode
        import qrcode.image.svg
        from io import BytesIO

        manager = get_totp_manager()
        result = manager.generate_secret(email)

        factory = qrcode.image.svg.SvgImage
        img = qrcode.make(result.qr_code_uri, image_factory=factory)

        # Save to bytes IO
        buffered = BytesIO()
        img.save(buffered)
        return buffered.getvalue().decode()
    except ImportError:
        return None  # QR code generation not available, use frontend
