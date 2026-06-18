# orchestrator/auth_flow.py
import secrets
from typing import Dict, Optional, Any
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum

# Import all modules
from ..modules.pow import PoW, get_pow, reset_pow
from ..modules.email import EmailVerifier, get_email_verifier, reset_email_verifier
from ..modules.totp import TOTPManager, get_totp_manager, reset_totp_manager
from ..modules.user import UserManager, get_user_manager, reset_user_manager
from ..modules.storage import Storage


class AuthStep(Enum):
    """Authentication flow steps"""
    POW_CHALLENGE = "pow_challenge"
    POW_VERIFIED = "pow_verified"
    EMAIL_CODE_SENT = "email_code_sent"
    EMAIL_VERIFIED = "email_verified"
    TOTP_VERIFIED = "totp_verified"
    ACCOUNT_CREATED = "account_created"
    ERROR = "error"


class NextAction(Enum):
    """Actions the client should take next"""
    RESTART = "restart"
    RETRY = "retry"
    RETRY_CODE = "retry_code"
    RETRY_TOTP = "retry_totp"
    CONTINUE = "continue"


@dataclass
class SessionData:
    """Session state for an auth flow"""
    step: str = AuthStep.POW_CHALLENGE.value
    pow_verified: bool = False
    email_verified: bool = False
    totp_verified: bool = False
    email: Optional[str] = None
    totp_secret: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuthResponse:
    """Standard response from auth flow steps"""
    step: str
    data: Dict[str, Any]
    next_action: Optional[str] = None
    session_token: Optional[str] = None


class AuthFlow:
    """
    Complete authentication flow orchestrator

    Flow:
    1. POW Challenge → Prove you're not a bot
    2. Email Verification → Verify email ownership
    3. TOTP Setup → Set up 2FA
    4. Account Creation → Create the account

    Features:
    - Session management with expiry
    - Step-by-step state machine
    - Automatic cleanup of expired sessions
    - Comprehensive error handling
    - Email masking for security
    """

    def __init__(
        self,
        session_expiry_minutes: int = 30,
        pow_difficulty: int = 4,
        pow_expiry_seconds: int = 300,
        email_code_length: int = 6,
        email_expiry_seconds: int = 600,
        email_max_attempts: int = 3,
        totp_window: int = 1,
        blocklist_path: Optional[str] = None
    ):
        """
        Initialize AuthFlow orchestrator

        Args:
            session_expiry_minutes: How long auth sessions last
            pow_difficulty: Proof of Work difficulty
            pow_expiry_seconds: PoW challenge expiry
            email_code_length: Email verification code length
            email_expiry_seconds: Email code expiry
            email_max_attempts: Max email verification attempts
            totp_window: TOTP time window tolerance
            blocklist_path: Path to blocked domains list
        """
        self.session_expiry = timedelta(minutes=session_expiry_minutes)

        # Initialize all modules as fresh instances (not singletons)
        # so each AuthFlow gets the exact parameters it was configured with.
        self.pow = PoW(
            difficulty=pow_difficulty,
            expiry_seconds=pow_expiry_seconds
        )

        self.email_verifier = EmailVerifier(
            code_length=email_code_length,
            expiry_seconds=email_expiry_seconds,
            max_attempts=email_max_attempts,
            blocklist_path=blocklist_path
        )

        self.totp_manager = TOTPManager(
            window=totp_window
        )

        # Give this AuthFlow its own isolated in-memory Storage
        import tempfile
        _storage = Storage(data_dir=tempfile.mkdtemp(), auto_save=False)
        _storage.init_sync()
        self.user_manager = UserManager(_storage=_storage)

        # Session storage
        self.sessions: Dict[str, SessionData] = {}

    def _create_session(self) -> str:
        """Create a new session and return token"""
        session_token = secrets.token_hex(32)
        self.sessions[session_token] = SessionData()
        return session_token

    def _get_session(self, session_token: str) -> Optional[SessionData]:
        """
        Get and validate a session

        Returns None if session is invalid or expired
        """
        session = self.sessions.get(session_token)
        if not session:
            return None

        # Check expiry
        if datetime.now(timezone.utc) - session.created_at > self.session_expiry:
            self.sessions.pop(session_token, None)
            return None

        # Update last activity
        session.last_activity = datetime.now(timezone.utc)
        return session

    def _mask_email(self, email: str) -> str:
        """
        Mask email for display

        Example: john@example.com → joh***@example.com
        """
        if not email or '@' not in email:
            return email

        local, domain = email.split('@')
        if len(local) > 3:
            masked_local = local[:3] + "***"
        elif len(local) > 0:
            masked_local = local[0] + "***"
        else:
            masked_local = "***"

        return f"{masked_local}@{domain}"

    def cleanup_sessions(self) -> int:
        """
        Remove expired sessions

        Returns:
            Number of sessions removed
        """
        now = datetime.now(timezone.utc)
        expired_tokens = [
            token for token, session in self.sessions.items()
            if now - session.created_at > self.session_expiry
        ]

        for token in expired_tokens:
            self.sessions.pop(token, None)

        return len(expired_tokens)

    # ============================================================
    # Step 1: Proof of Work
    # ============================================================

    def init_pow(self) -> AuthResponse:
        """
        Start the auth flow with a Proof of Work challenge

        Returns:
            AuthResponse with challenge data
        """
        challenge = self.pow.generate_challenge()

        return AuthResponse(
            step=AuthStep.POW_CHALLENGE.value,
            data=challenge.to_dict()
        )

    def verify_pow(self, challenge_id: str, nonce: str) -> AuthResponse:
        """
        Verify Proof of Work solution

        Args:
            challenge_id: The challenge ID from init_pow
            nonce: The nonce solution from client

        Returns:
            AuthResponse with session token or error
        """
        result = self.pow.verify(challenge_id, nonce)

        if not result.success:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={
                    'message': result.message,
                    'status': result.status.value
                },
                next_action=NextAction.RESTART.value
            )

        # Create session
        session_token = self._create_session()
        session = self.sessions[session_token]
        session.step = AuthStep.POW_VERIFIED.value
        session.pow_verified = True

        return AuthResponse(
            step=AuthStep.POW_VERIFIED.value,
            data={
                'message': result.message,
                'session_token': session_token
            },
            session_token=session_token
        )

    # ============================================================
    # Step 2: Email Verification
    # ============================================================

    def submit_email(self, session_token: str, email: str) -> AuthResponse:
        """
        Submit email for verification

        Args:
            session_token: Session token from verify_pow
            email: Email address to verify

        Returns:
            AuthResponse with verification code info
        """
        session = self._get_session(session_token)
        if not session:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Invalid or expired session'},
                next_action=NextAction.RESTART.value
            )

        if not session.pow_verified:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Complete Proof of Work first'},
                next_action=NextAction.RESTART.value
            )

        # Validate email format
        if not email or '@' not in email:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Valid email required'},
                next_action=NextAction.RETRY.value
            )

        # Validate email (check disposable/spam domains)
        validation = self.email_verifier.validate_email(email)
        if not validation.is_valid:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={
                    'message': validation.message,
                    'status': validation.status.value
                },
                next_action=NextAction.RETRY.value
            )

        # Generate verification code
        result, _ = self.email_verifier.generate_code(email)

        if result.get('error'):
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': result.get('message', 'Failed to generate code')},
                next_action=NextAction.RETRY.value
            )

        # Update session
        session.email = email.lower()
        session.step = AuthStep.EMAIL_CODE_SENT.value

        # Mask email for response
        masked_email = self._mask_email(email)

        return AuthResponse(
            step=AuthStep.EMAIL_CODE_SENT.value,
            data={
                'message': 'Verification code sent',
                'expires_in_seconds': result['expires_in_seconds'],
                'expires_at': result['expires_at'],
                'email': masked_email
            },
            session_token=session_token
        )

    def verify_email_code(self, session_token: str, code: str) -> AuthResponse:
        """
        Verify email verification code and generate TOTP secret

        Args:
            session_token: Session token
            code: Verification code from email

        Returns:
            AuthResponse with TOTP setup info
        """
        session = self._get_session(session_token)
        if not session:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Invalid or expired session'},
                next_action=NextAction.RESTART.value
            )

        if not session.email:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'No email submitted'},
                next_action=NextAction.RESTART.value
            )

        # Verify the code
        result = self.email_verifier.verify_code(session.email, code)

        if not result['verified']:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={
                    'message': result['message'],
                    'attempts_left': result.get('attempts_left', 0)
                },
                next_action=NextAction.RETRY_CODE.value if result.get('attempts_left', 0) > 0 else NextAction.RESTART.value
            )

        # Email verified - generate TOTP secret
        session.email_verified = True
        session.step = AuthStep.EMAIL_VERIFIED.value

        # Generate TOTP secret for this email
        totp_setup = self.totp_manager.generate_secret(session.email)
        session.totp_secret = totp_setup.secret

        return AuthResponse(
            step=AuthStep.EMAIL_VERIFIED.value,
            data={
                'message': 'Email verified successfully',
                'totp': {
                    'qr_code_uri': totp_setup.qr_code_uri,
                    'manual_key': totp_setup.manual_key,
                    # REMOVED: 'secret': totp_setup.secret
                }
            },
            session_token=session_token
        )

    # ============================================================
    # Step 3: TOTP Verification
    # ============================================================

    def verify_totp(self, session_token: str, totp_token: str) -> AuthResponse:
        """
        Verify TOTP token

        Args:
            session_token: Session token
            totp_token: 6-digit TOTP code from authenticator app

        Returns:
            AuthResponse with verification status
        """
        session = self._get_session(session_token)
        if not session:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Invalid or expired session'},
                next_action=NextAction.RESTART.value
            )

        if not session.email_verified:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Complete email verification first'},
                next_action=NextAction.RESTART.value
            )

        if not session.email:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'No email associated with session'},
                next_action=NextAction.RESTART.value
            )

        # Verify TOTP token
        result = self.totp_manager.verify_token(session.email, totp_token)

        if not result['verified']:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': result['message']},
                next_action=NextAction.RETRY_TOTP.value
            )

        # TOTP verified
        session.totp_verified = True
        session.step = AuthStep.TOTP_VERIFIED.value

        return AuthResponse(
            step=AuthStep.TOTP_VERIFIED.value,
            data={
                'message': 'TOTP verified successfully',
                'ready_for_registration': True
            },
            session_token=session_token
        )

    # ============================================================
    # Step 4: Account Creation
    # ============================================================

    async def create_account(
        self,
        session_token: str,
        username: str,
        password: str
    ) -> AuthResponse:
        """
        Create user account after completing all verifications

        Args:
            session_token: Session token
            username: Desired username
            password: Password

        Returns:
            AuthResponse with account creation status
        """
        session = self._get_session(session_token)
        if not session:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Invalid or expired session'},
                next_action=NextAction.RESTART.value
            )

        if not session.totp_verified:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Complete TOTP verification first'},
                next_action=NextAction.RESTART.value
            )

        if not session.email:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'No email associated with session'},
                next_action=NextAction.RESTART.value
            )

        # Create the user
        result = await self.user_manager.create_user_async(
            username=username,
            password=password,
            email=session.email
        )

        if not result.created:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': result.message},
                next_action=NextAction.RETRY.value
            )

        # Enable TOTP for the user
        if session.totp_secret:
            self.user_manager.enable_totp(username, session.totp_secret)

        # Mark email as verified
        self.user_manager.verify_email(username)

        # Clean up session
        self.sessions.pop(session_token, None)

        return AuthResponse(
            step=AuthStep.ACCOUNT_CREATED.value,
            data={
                'message': result.message,
                'user_id': result.user_id,
                'username': username.lower(),
                'email': self._mask_email(session.email)
            }
        )

    def create_account_sync(
        self,
        session_token: str,
        username: str,
        password: str
    ) -> AuthResponse:
        """
        Synchronous version of create_account

        Args:
            session_token: Session token
            username: Desired username
            password: Password

        Returns:
            AuthResponse with account creation status
        """
        session = self._get_session(session_token)
        if not session:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Invalid or expired session'},
                next_action=NextAction.RESTART.value
            )

        if not session.totp_verified:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Complete TOTP verification first'},
                next_action=NextAction.RESTART.value
            )

        if not session.email:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'No email associated with session'},
                next_action=NextAction.RESTART.value
            )

        # Create user synchronously
        result = self.user_manager.create_user(
            username=username,
            password=password,
            email=session.email
        )

        if not result.created:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': result.message},
                next_action=NextAction.RETRY.value
            )

        # Enable TOTP and verify email
        if session.totp_secret:
            self.user_manager.enable_totp(username, session.totp_secret)
        self.user_manager.verify_email(username)

        # Clean up session
        self.sessions.pop(session_token, None)

        return AuthResponse(
            step=AuthStep.ACCOUNT_CREATED.value,
            data={
                'message': result.message,
                'user_id': result.user_id,
                'username': username.lower(),
                'email': self._mask_email(session.email)
            }
        )

    # ============================================================
    # Login Flow
    # ============================================================

    def login(self, username: str, password: str, totp_token: str) -> AuthResponse:
        """
        Complete login flow: password + TOTP verification

        Args:
            username: Username
            password: Password
            totp_token: Current TOTP token

        Returns:
            AuthResponse with login result
        """
        # Verify password
        if not self.user_manager.verify_password(username, password):
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'Invalid username or password'},
                next_action=NextAction.RETRY.value
            )

        # Get user info
        user = self.user_manager.get_full_user(username)
        if not user:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'User not found'},
                next_action=NextAction.RETRY.value
            )

        # Check if TOTP is enabled
        if user.get('totpEnabled'):
            if not totp_token:
                return AuthResponse(
                    step="totp_required",
                    data={'message': 'TOTP token required for 2FA'},
                    next_action=NextAction.CONTINUE.value
                )

            # Verify TOTP
            totp_result = self.totp_manager.verify_token(
                user.get('email', username),
                totp_token
            )

            if not totp_result['verified']:
                return AuthResponse(
                    step=AuthStep.ERROR.value,
                    data={'message': 'Invalid TOTP token'},
                    next_action=NextAction.RETRY_TOTP.value
                )

        # Generate session token for logged-in user
        session_token = self._create_session()
        session = self.sessions[session_token]
        session.step = "logged_in"
        session.pow_verified = True
        session.email_verified = True
        session.totp_verified = True
        session.email = user.get('email')

        return AuthResponse(
            step="logged_in",
            data={
                'message': 'Login successful',
                'user': self.user_manager.get_user_info(username),
                'session_token': session_token
            },
            session_token=session_token
        )

    # ============================================================
    # Password Reset Flow
    # ============================================================

    def initiate_password_reset(self, email: str) -> AuthResponse:
        """Send password reset code to email"""
        user = self.user_manager.storage.get_user_by_email(email)
        if not user:
            # Don't reveal if email exists (prevent enumeration)
            return AuthResponse(
                step="reset_code_sent",
                data={'message': 'If this email is registered, a reset code has been sent'}
            )

        # Generate and send reset code
        result, _ = self.email_verifier.generate_code(email)

        return AuthResponse(
            step="reset_code_sent",
            data={
                'message': 'Password reset code sent to your email',
                'expires_in_seconds': result.get('expires_in_seconds', 600)
            }
        )

    def complete_password_reset(self, email: str, code: str, new_password: str) -> AuthResponse:
        """Complete password reset with code and new password"""
        # Verify reset code
        result = self.email_verifier.verify_code(email, code)
        if not result['verified']:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': result['message']},
                next_action=NextAction.RETRY.value
            )

        # Get user
        user = self.user_manager.storage.get_user_by_email(email)
        if not user:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': 'User not found'},
                next_action=NextAction.RESTART.value
            )

        # Validate new password
        password_valid = self.user_manager.validate_password(new_password)
        if not password_valid.valid:
            return AuthResponse(
                step=AuthStep.ERROR.value,
                data={'message': password_valid.message},
                next_action=NextAction.RETRY.value
            )

        # Hash and update password
        new_hash, new_salt = self.user_manager.hash_password(new_password)
        success = self.user_manager.storage.update_user_sync(user['username'].lower(), {
            'passwordHash': new_hash,
            'salt': new_salt,
            'updatedAt': datetime.now(timezone.utc).isoformat()
        })

        if success:
            return AuthResponse(
                step="password_reset_complete",
                data={'message': 'Password reset successfully'}
            )

        return AuthResponse(
            step=AuthStep.ERROR.value,
            data={'message': 'Failed to reset password'},
            next_action=NextAction.RETRY.value
        )

    # ============================================================
    # Session Management
    # ============================================================

    def get_session_status(self, session_token: str) -> Dict:
        """
        Get current session status

        Args:
            session_token: Session token

        Returns:
            Dict with session status info
        """
        session = self._get_session(session_token)
        if not session:
            return {'exists': False}

        masked_email = None
        if session.email:
            masked_email = self._mask_email(session.email)

        return {
            'exists': True,
            'step': session.step,
            'pow_verified': session.pow_verified,
            'email_verified': session.email_verified,
            'totp_verified': session.totp_verified,
            'email': masked_email,
            'created_at': session.created_at.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'expires_at': (session.created_at + self.session_expiry).isoformat()
        }

    def invalidate_session(self, session_token: str) -> bool:
        """
        Invalidate/delete a session

        Args:
            session_token: Session token to invalidate

        Returns:
            True if session was found and deleted
        """
        if session_token in self.sessions:
            self.sessions.pop(session_token)
            return True
        return False

    def get_active_sessions_count(self) -> int:
        """Get count of active sessions"""
        self.cleanup_sessions()
        return len(self.sessions)

    def get_status(self) -> Dict:
        """
        Get overall auth flow status

        Returns:
            Dict with system status
        """
        return {
            'active_sessions': len(self.sessions),
            'session_expiry_minutes': self.session_expiry.total_seconds() / 60,
            'pow': self.pow.get_status(),
            'email': self.email_verifier.get_status(),
            'totp': self.totp_manager.get_status(),
            'users': self.user_manager.get_stats()
        }

    # ============================================================
    # Reset/Cleanup
    # ============================================================

    def reset(self):
        """Reset all modules and sessions"""
        self.sessions.clear()
        self.pow.reset()
        self.email_verifier.reset()
        self.totp_manager.reset()

    async def full_reset(self):
        """Complete reset including user data"""
        self.reset()
        await reset_user_manager()

    def destroy(self):
        """Clean up resources"""
        self.pow.destroy()
        self.sessions.clear()


# Singleton pattern
_auth_flow_instance: Optional[AuthFlow] = None


def get_auth_flow(
    session_expiry_minutes: int = 30,
    pow_difficulty: int = 4,
    blocklist_path: Optional[str] = None
) -> AuthFlow:
    """
    Get or create the singleton AuthFlow instance

    Args:
        session_expiry_minutes: Session timeout in minutes
        pow_difficulty: Proof of Work difficulty level
        blocklist_path: Path to blocked email domains JSON

    Returns:
        AuthFlow instance
    """
    global _auth_flow_instance
    if _auth_flow_instance is None:
        _auth_flow_instance = AuthFlow(
            session_expiry_minutes=session_expiry_minutes,
            pow_difficulty=pow_difficulty,
            blocklist_path=blocklist_path
        )
    return _auth_flow_instance


def reset_auth_flow():
    """Reset the singleton instance (for testing)"""
    global _auth_flow_instance
    if _auth_flow_instance:
        _auth_flow_instance.reset()
        _auth_flow_instance.destroy()
    _auth_flow_instance = None
