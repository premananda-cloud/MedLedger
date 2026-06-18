# tests/test_auth_flow.py
"""
Unit tests for AuthFlow orchestrator

Run with: pytest tests/test_auth_Flow.py -v
With coverage: pytest tests/test_auth_flow.py --cov=orchestrator --cov=modules -v
"""

import pytest
import time
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from freezegun import freeze_time

# Import the orchestrator
# Line 18 in tests/test_auth_flow.py
from orchestrator.authFlow import (  # Changed from auth_flow to authFlow
    AuthFlow, AuthStep, NextAction, AuthResponse, SessionData,
    get_auth_flow, reset_auth_flow
)

# Import modules for direct testing when needed
from modules.pow import PoW, Challenge, VerificationResult, PoWStatus
from modules.email import EmailVerifier, EmailValidator, EmailStatus
from modules.totp import TOTPManager
from modules.user import UserManager, CreateUserResult, ValidationResult, PasswordStrength
from modules.storage import Storage


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def auth_flow():
    """Create a fresh AuthFlow instance for each test"""
    flow = AuthFlow(
        session_expiry_minutes=30,
        pow_difficulty=2,  # Low difficulty for testing
        pow_expiry_seconds=300,
        email_code_length=6,
        email_expiry_seconds=600,
        email_max_attempts=3,
        totp_window=1
    )
    yield flow
    flow.reset()


@pytest.fixture
def temp_data_dir(tmp_path):
    """Create temporary data directory for storage"""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def storage(temp_data_dir):
    """Create isolated storage for testing"""
    from modules.storage import Storage, _storage_instance, reset_storage_sync

    # Reset singleton first
    reset_storage_sync()

    store = Storage(data_dir=temp_data_dir, auto_save=True)
    store.init_sync()
    yield store
    store.clear_all()


@pytest.fixture
def user_manager(storage):
    """Create user manager with test storage"""
    from modules.user import UserManager, _user_manager_instance, reset_user_manager
    from modules.storage import _storage_instance

    # Reset singletons
    reset_user_manager()

    # Patch storage singleton
    import modules.user
    modules.user._storage_instance = storage

    manager = UserManager(
        min_username=3,
        max_username=30,
        min_password=8,
        pbkdf2_iterations=1000  # Fast iterations for testing
    )
    modules.user._user_manager_instance = manager
    yield manager
    reset_user_manager()


@pytest.fixture
def completed_registration_session(auth_flow):
    """Create a session that has completed all steps up to account creation"""
    # Step 1: POW
    pow_response = auth_flow.init_pow()
    challenge = auth_flow.pow.generate_challenge()
    nonce = solve_pow_challenge(challenge.challenge, challenge.difficulty)
    pow_result = auth_flow.verify_pow(challenge.challenge_id, nonce)
    session_token = pow_result.session_token

    # Step 2: Email
    auth_flow.submit_email(session_token, "test@example.com")
    code = auth_flow.email_verifier.get_code_for_testing("test@example.com")
    auth_flow.verify_email_code(session_token, code)

    # Step 3: TOTP
    totp_code = auth_flow.totp_manager.get_current_token("test@example.com")
    auth_flow.verify_totp(session_token, totp_code)

    return session_token


# ============================================================
# Helper Functions
# ============================================================

def solve_pow_challenge(challenge: str, difficulty: int) -> str:
    """Solve a PoW challenge for testing"""
    import hashlib

    prefix = "0" * difficulty
    nonce = 0

    while nonce < 1000000:  # Limit for tests
        nonce_str = str(nonce)
        input_string = challenge + nonce_str
        hash_result = hashlib.sha256(input_string.encode()).hexdigest()

        if hash_result.startswith(prefix):
            return nonce_str
        nonce += 1

    raise Exception("Could not solve PoW challenge in test")


# ============================================================
# Initialization Tests
# ============================================================

class TestAuthFlowInitialization:
    """Test AuthFlow initialization"""

    def test_create_instance_defaults(self):
        """Test creation with default parameters"""
        flow = AuthFlow()
        assert flow.session_expiry == timedelta(minutes=30)
        assert flow.pow.difficulty == 4
        assert flow.email_verifier.code_length == 6
        assert flow.totp_manager.window == 1
        assert len(flow.sessions) == 0

    def test_create_instance_custom(self):
        """Test creation with custom parameters"""
        flow = AuthFlow(
            session_expiry_minutes=15,
            pow_difficulty=3,
            email_code_length=8,
            email_expiry_seconds=300,
            email_max_attempts=5,
            totp_window=2
        )
        assert flow.session_expiry == timedelta(minutes=15)
        assert flow.pow.difficulty == 3
        assert flow.email_verifier.code_length == 8
        assert flow.email_verifier.expiry_seconds == 300
        assert flow.email_verifier.max_attempts == 5
        assert flow.totp_manager.window == 2
        flow.reset()

    def test_singleton_pattern(self):
        """Test singleton get_auth_flow"""
        flow1 = get_auth_flow()
        flow2 = get_auth_flow()
        assert flow1 is flow2
        reset_auth_flow()


# ============================================================
# Session Management Tests
# ============================================================

class TestSessionManagement:
    """Test session creation and validation"""

    def test_create_session(self, auth_flow):
        """Test session creation"""
        token = auth_flow._create_session()
        assert token is not None
        assert len(token) == 64  # 32 bytes hex = 64 chars
        assert token in auth_flow.sessions

        session = auth_flow.sessions[token]
        assert isinstance(session, SessionData)
        assert session.step == AuthStep.POW_CHALLENGE.value
        assert not session.pow_verified

    def test_get_valid_session(self, auth_flow):
        """Test retrieving a valid session"""
        token = auth_flow._create_session()
        session = auth_flow._get_session(token)
        assert session is not None
        assert session.step == AuthStep.POW_CHALLENGE.value

    def test_get_invalid_session(self, auth_flow):
        """Test retrieving a non-existent session"""
        session = auth_flow._get_session("nonexistent_token")
        assert session is None

    @freeze_time("2026-01-01 00:00:00")
    def test_session_expiry(self, auth_flow):
        """Test that sessions expire after timeout"""
        token = auth_flow._create_session()

        # Session should be valid immediately
        assert auth_flow._get_session(token) is not None

        # Move time forward past expiry
        with freeze_time("2026-01-01 00:31:00"):  # 31 minutes later
            session = auth_flow._get_session(token)
            assert session is None
            assert token not in auth_flow.sessions

    def test_cleanup_sessions(self, auth_flow):
        """Test cleanup of expired sessions"""
        # Create sessions at different times
        token1 = auth_flow._create_session()

        # Manually expire first session
        session1 = auth_flow.sessions[token1]
        session1.created_at = datetime.now(timezone.utc) - timedelta(minutes=60)

        token2 = auth_flow._create_session()  # Valid session

        cleaned = auth_flow.cleanup_sessions()
        assert cleaned == 1
        assert token1 not in auth_flow.sessions
        assert token2 in auth_flow.sessions

    def test_invalidate_session(self, auth_flow):
        """Test manual session invalidation"""
        token = auth_flow._create_session()
        assert auth_flow.invalidate_session(token) is True
        assert token not in auth_flow.sessions
        assert auth_flow.invalidate_session(token) is False  # Already gone

    def test_get_session_status_exists(self, auth_flow):
        """Test getting status of existing session"""
        token = auth_flow._create_session()
        status = auth_flow.get_session_status(token)
        assert status['exists'] is True
        assert status['step'] == AuthStep.POW_CHALLENGE.value
        assert status['pow_verified'] is False

    def test_get_session_status_not_exists(self, auth_flow):
        """Test getting status of non-existent session"""
        status = auth_flow.get_session_status("invalid")
        assert status == {'exists': False}

    def test_mask_email(self, auth_flow):
        """Test email masking"""
        assert auth_flow._mask_email("john@example.com") == "joh***@example.com"
        assert auth_flow._mask_email("a@example.com") == "a***@example.com"
        assert auth_flow._mask_email("ab@example.com") == "a***@example.com"
        assert auth_flow._mask_email("") == ""
        assert auth_flow._mask_email("invalid") == "invalid"


# ============================================================
# Proof of Work Tests
# ============================================================

class TestProofOfWorkFlow:
    """Test PoW flow through orchestrator"""

    def test_init_pow(self, auth_flow):
        """Test initiating PoW challenge"""
        response = auth_flow.init_pow()
        assert response.step == AuthStep.POW_CHALLENGE.value
        assert 'challenge_id' in response.data
        assert 'challenge' in response.data
        assert response.data['difficulty'] == 2

    def test_verify_pow_success(self, auth_flow):
        """Test successful PoW verification"""
        # Generate challenge
        challenge = auth_flow.pow.generate_challenge()

        # Solve it
        nonce = solve_pow_challenge(challenge.challenge, challenge.difficulty)

        # Verify
        response = auth_flow.verify_pow(challenge.challenge_id, nonce)
        assert response.step == AuthStep.POW_VERIFIED.value
        assert response.session_token is not None
        assert 'session_token' in response.data

        # Check session was created
        session = auth_flow._get_session(response.session_token)
        assert session is not None
        assert session.pow_verified is True

    def test_verify_pow_invalid_nonce(self, auth_flow):
        """Test PoW verification with wrong nonce"""
        challenge = auth_flow.pow.generate_challenge()
        response = auth_flow.verify_pow(challenge.challenge_id, "invalid_nonce")

        assert response.step == AuthStep.ERROR.value
        assert response.next_action == NextAction.RESTART.value

    def test_verify_pow_already_used(self, auth_flow):
        """Test PoW verification with already used challenge"""
        challenge = auth_flow.pow.generate_challenge()
        nonce = solve_pow_challenge(challenge.challenge, challenge.difficulty)

        # First use - succeeds
        response1 = auth_flow.verify_pow(challenge.challenge_id, nonce)
        assert response1.step == AuthStep.POW_VERIFIED.value

        # Second use - fails
        response2 = auth_flow.verify_pow(challenge.challenge_id, nonce)
        assert response2.step == AuthStep.ERROR.value

    def test_verify_pow_expired_challenge(self, auth_flow):
        """Test PoW verification with expired challenge"""
        challenge = auth_flow.pow.generate_challenge()
        nonce = solve_pow_challenge(challenge.challenge, challenge.difficulty)

        # Manually expire the challenge
        record = auth_flow.pow.challenges[challenge.challenge_id]
        record.timestamp = time.time() - 1000

        response = auth_flow.verify_pow(challenge.challenge_id, nonce)
        assert response.step == AuthStep.ERROR.value


# ============================================================
# Email Verification Tests
# ============================================================

class TestEmailVerificationFlow:
    """Test email verification flow through orchestrator"""

    def _complete_pow(self, auth_flow):
        """Helper to complete PoW step"""
        challenge = auth_flow.pow.generate_challenge()
        nonce = solve_pow_challenge(challenge.challenge, challenge.difficulty)
        result = auth_flow.verify_pow(challenge.challenge_id, nonce)
        return result.session_token

    def test_submit_email_success(self, auth_flow):
        """Test successful email submission"""
        session_token = self._complete_pow(auth_flow)

        response = auth_flow.submit_email(session_token, "test@example.com")
        assert response.step == AuthStep.EMAIL_CODE_SENT.value
        assert 'Verification code sent' in response.data['message']
        assert 'email' in response.data
        assert '@' in response.data['email']  # Masked email

        # Check code was generated
        code = auth_flow.email_verifier.get_code_for_testing("test@example.com")
        assert code is not None
        assert len(code) == 6

    def test_submit_email_invalid_session(self, auth_flow):
        """Test email submission with invalid session"""
        response = auth_flow.submit_email("invalid_token", "test@example.com")
        assert response.step == AuthStep.ERROR.value
        assert 'Invalid or expired session' in response.data['message']

    def test_submit_email_before_pow(self, auth_flow):
        """Test email submission without completing PoW"""
        token = auth_flow._create_session()
        # Session exists but POW not verified
        response = auth_flow.submit_email(token, "test@example.com")
        assert response.step == AuthStep.ERROR.value
        assert 'Proof of Work' in response.data['message']

    def test_submit_email_invalid_format(self, auth_flow):
        """Test submitting invalid email format"""
        session_token = self._complete_pow(auth_flow)

        response = auth_flow.submit_email(session_token, "invalid-email")
        assert response.step == AuthStep.ERROR.value

    def test_submit_email_disposable_domain(self, auth_flow):
        """Test submitting disposable email domain"""
        session_token = self._complete_pow(auth_flow)

        # mailinator.com is in the disposable list
        response = auth_flow.submit_email(session_token, "user@mailinator.com")
        assert response.step == AuthStep.ERROR.value
        assert 'Disposable' in response.data['message']

    def test_verify_email_code_success(self, auth_flow):
        """Test successful email code verification"""
        session_token = self._complete_pow(auth_flow)
        auth_flow.submit_email(session_token, "test@example.com")

        code = auth_flow.email_verifier.get_code_for_testing("test@example.com")
        response = auth_flow.verify_email_code(session_token, code)

        assert response.step == AuthStep.EMAIL_VERIFIED.value
        assert 'totp' in response.data
        assert 'qr_code_uri' in response.data['totp']
        assert 'manual_key' in response.data['totp']
        # Verify secret is NOT exposed
        assert 'secret' not in response.data['totp']

    def test_verify_email_code_invalid(self, auth_flow):
        """Test email verification with wrong code"""
        session_token = self._complete_pow(auth_flow)
        auth_flow.submit_email(session_token, "test@example.com")

        response = auth_flow.verify_email_code(session_token, "000000")
        assert response.step == AuthStep.ERROR.value
        assert response.next_action == NextAction.RETRY_CODE.value

    def test_verify_email_code_max_attempts(self, auth_flow):
        """Test email verification with max attempts exceeded"""
        session_token = self._complete_pow(auth_flow)
        auth_flow.submit_email(session_token, "test@example.com")

        # Use all attempts
        for _ in range(3):
            response = auth_flow.verify_email_code(session_token, "000000")

        # Should be out of attempts
        assert response.step == AuthStep.ERROR.value
        assert response.next_action == NextAction.RESTART.value
        assert response.data.get('attempts_left') == 0

    def test_verify_email_no_session(self, auth_flow):
        """Test email verification with invalid session"""
        response = auth_flow.verify_email_code("invalid", "123456")
        assert response.step == AuthStep.ERROR.value


# ============================================================
# TOTP Verification Tests
# ============================================================

class TestTOTPVerificationFlow:
    """Test TOTP verification through orchestrator"""

    def _complete_email(self, auth_flow):
        """Helper to complete PoW + Email steps"""
        # PoW
        challenge = auth_flow.pow.generate_challenge()
        nonce = solve_pow_challenge(challenge.challenge, challenge.difficulty)
        result = auth_flow.verify_pow(challenge.challenge_id, nonce)
        session_token = result.session_token

        # Email
        auth_flow.submit_email(session_token, "test@example.com")
        code = auth_flow.email_verifier.get_code_for_testing("test@example.com")
        auth_flow.verify_email_code(session_token, code)

        return session_token

    def test_verify_totp_success(self, auth_flow):
        """Test successful TOTP verification"""
        session_token = self._complete_email(auth_flow)

        # Get current valid TOTP token
        totp_code = auth_flow.totp_manager.get_current_token("test@example.com")

        response = auth_flow.verify_totp(session_token, totp_code)
        assert response.step == AuthStep.TOTP_VERIFIED.value
        assert response.data['ready_for_registration'] is True

    def test_verify_totp_invalid_token(self, auth_flow):
        """Test TOTP verification with wrong token"""
        session_token = self._complete_email(auth_flow)

        response = auth_flow.verify_totp(session_token, "000000")
        assert response.step == AuthStep.ERROR.value
        assert response.next_action == NextAction.RETRY_TOTP.value

    def test_verify_totp_before_email(self, auth_flow):
        """Test TOTP verification without completing email"""
        session_token = auth_flow._create_session()
        session = auth_flow.sessions[session_token]
        session.pow_verified = True
        session.email = "test@example.com"
        # email_verified is still False

        response = auth_flow.verify_totp(session_token, "000000")
        assert response.step == AuthStep.ERROR.value
        assert 'email verification' in response.data['message'].lower()

    def test_verify_totp_invalid_session(self, auth_flow):
        """Test TOTP verification with invalid session"""
        response = auth_flow.verify_totp("invalid", "000000")
        assert response.step == AuthStep.ERROR.value


# ============================================================
# Account Creation Tests
# ============================================================

class TestAccountCreation:
    """Test account creation through orchestrator"""

    def test_create_account_success(self, auth_flow, completed_registration_session):
        """Test successful account creation"""
        response = auth_flow.create_account_sync(
            completed_registration_session,
            "testuser",
            "SecurePass123!"
        )

        assert response.step == AuthStep.ACCOUNT_CREATED.value
        assert response.data['username'] == "testuser"
        assert response.data['user_id'] is not None

        # Verify session is cleaned up
        assert completed_registration_session not in auth_flow.sessions

        # Verify user exists in storage
        user = auth_flow.user_manager.get_full_user("testuser")
        assert user is not None
        assert user['email'] == "test@example.com"
        assert user['totpEnabled'] is True
        assert user['emailVerified'] is True

    def test_create_account_invalid_session(self, auth_flow):
        """Test account creation with invalid session"""
        response = auth_flow.create_account_sync(
            "invalid_token",
            "testuser",
            "password"
        )
        assert response.step == AuthStep.ERROR.value

    def test_create_account_before_totp(self, auth_flow):
        """Test account creation without TOTP verification"""
        # Only complete PoW
        challenge = auth_flow.pow.generate_challenge()
        nonce = solve_pow_challenge(challenge.challenge, challenge.difficulty)
        result = auth_flow.verify_pow(challenge.challenge_id, nonce)

        response = auth_flow.create_account_sync(
            result.session_token,
            "testuser",
            "password"
        )
        assert response.step == AuthStep.ERROR.value
        assert 'TOTP' in response.data['message']

    def test_create_account_duplicate_username(self, auth_flow, completed_registration_session):
        """Test account creation with duplicate username"""
        # Create first account
        auth_flow.create_account_sync(
            completed_registration_session,
            "testuser",
            "SecurePass123!"
        )

        # Setup new session for second account
        token2 = auth_flow._create_session()
        session2 = auth_flow.sessions[token2]
        session2.pow_verified = True
        session2.email_verified = True
        session2.totp_verified = True
        session2.email = "other@example.com"

        # Try same username
        response = auth_flow.create_account_sync(
            token2,
            "testuser",
            "SecurePass123!"
        )
        assert response.step == AuthStep.ERROR.value

    def test_create_account_weak_password(self, auth_flow, completed_registration_session):
        """Test account creation with weak password"""
        response = auth_flow.create_account_sync(
            completed_registration_session,
            "testuser",
            "short"  # Too short, no complexity
        )
        assert response.step == AuthStep.ERROR.value


# ============================================================
# Login Flow Tests
# ============================================================

class TestLoginFlow:
    """Test login flow"""

    def _create_test_user(self, auth_flow):
        """Helper to create a test user"""
        # Complete registration
        session_token = auth_flow._create_session()
        session = auth_flow.sessions[session_token]
        session.pow_verified = True
        session.email_verified = True
        session.totp_verified = True
        session.email = "test@example.com"
        session.totp_secret = auth_flow.totp_manager.generate_secret("test@example.com").secret

        auth_flow.create_account_sync(session_token, "testuser", "SecurePass123!")

    def test_login_success_without_totp(self, auth_flow):
        """Test login without TOTP (2FA not enabled)"""
        # Create user without TOTP
        session_token = auth_flow._create_session()
        session = auth_flow.sessions[session_token]
        session.pow_verified = True
        session.email_verified = True
        session.totp_verified = True
        session.email = "test@example.com"

        auth_flow.create_account_sync(session_token, "testuser", "SecurePass123!")

        # Disable TOTP for testing
        user = auth_flow.user_manager.get_full_user("testuser")
        user['totpEnabled'] = False

        # Login
        response = auth_flow.login("testuser", "SecurePass123!", "")
        assert response.step == "logged_in"
        assert response.session_token is not None

    def test_login_invalid_password(self, auth_flow):
        """Test login with wrong password"""
        self._create_test_user(auth_flow)

        response = auth_flow.login("testuser", "WrongPassword!", "")
        assert response.step == AuthStep.ERROR.value
        assert 'Invalid' in response.data['message']

    def test_login_totp_required(self, auth_flow):
        """Test login requiring TOTP"""
        self._create_test_user(auth_flow)

        response = auth_flow.login("testuser", "SecurePass123!", "")
        assert response.step == "totp_required"

    def test_login_totp_success(self, auth_flow):
        """Test login with valid TOTP"""
        self._create_test_user(auth_flow)

        totp_code = auth_flow.totp_manager.get_current_token("test@example.com")
        response = auth_flow.login("testuser", "SecurePass123!", totp_code)
        assert response.step == "logged_in"

    def test_login_totp_invalid(self, auth_flow):
        """Test login with invalid TOTP"""
        self._create_test_user(auth_flow)

        response = auth_flow.login("testuser", "SecurePass123!", "000000")
        assert response.step == AuthStep.ERROR.value
        assert 'TOTP' in response.data['message']


# ============================================================
# Password Reset Tests
# ============================================================

class TestPasswordReset:
    """Test password reset flow"""

    def _create_test_user(self, auth_flow):
        """Helper to create a test user"""
        session_token = auth_flow._create_session()
        session = auth_flow.sessions[session_token]
        session.pow_verified = True
        session.email_verified = True
        session.totp_verified = True
        session.email = "test@example.com"

        auth_flow.create_account_sync(session_token, "testuser", "SecurePass123!")

    def test_initiate_reset_existing_email(self, auth_flow):
        """Test initiating password reset for existing email"""
        self._create_test_user(auth_flow)

        response = auth_flow.initiate_password_reset("test@example.com")
        assert response.step == "reset_code_sent"

        # Verify code was generated
        code = auth_flow.email_verifier.get_code_for_testing("test@example.com")
        assert code is not None

    def test_initiate_reset_nonexistent_email(self, auth_flow):
        """Test initiating password reset for non-existent email"""
        response = auth_flow.initiate_password_reset("nonexistent@example.com")
        assert response.step == "reset_code_sent"
        # Should not reveal if email exists
        assert 'If this email' in response.data['message']

    def test_complete_reset_success(self, auth_flow):
        """Test completing password reset"""
        self._create_test_user(auth_flow)
        auth_flow.initiate_password_reset("test@example.com")

        code = auth_flow.email_verifier.get_code_for_testing("test@example.com")
        response = auth_flow.complete_password_reset(
            "test@example.com",
            code,
            "NewSecurePass456!"
        )

        assert response.step == "password_reset_complete"

        # Verify new password works
        login_response = auth_flow.login("testuser", "NewSecurePass456!", "")
        assert login_response.step == "logged_in"

    def test_complete_reset_invalid_code(self, auth_flow):
        """Test password reset with invalid code"""
        self._create_test_user(auth_flow)
        auth_flow.initiate_password_reset("test@example.com")

        response = auth_flow.complete_password_reset(
            "test@example.com",
            "000000",
            "NewSecurePass456!"
        )
        assert response.step == AuthStep.ERROR.value

    def test_complete_reset_weak_password(self, auth_flow):
        """Test password reset with weak new password"""
        self._create_test_user(auth_flow)
        auth_flow.initiate_password_reset("test@example.com")

        code = auth_flow.email_verifier.get_code_for_testing("test@example.com")
        response = auth_flow.complete_password_reset(
            "test@example.com",
            code,
            "short"
        )
        assert response.step == AuthStep.ERROR.value


# ============================================================
# Full Integration Tests
# ============================================================

class TestFullRegistrationFlow:
    """End-to-end registration flow tests"""

    def test_complete_registration_flow(self, auth_flow):
        """Test the entire registration flow from start to finish"""
        # Step 1: Get PoW challenge
        pow_response = auth_flow.init_pow()
        assert pow_response.step == AuthStep.POW_CHALLENGE.value
        challenge_id = pow_response.data['challenge_id']

        # Client solves PoW
        challenge_str = auth_flow.pow.challenges[challenge_id].challenge
        nonce = solve_pow_challenge(challenge_str, auth_flow.pow.difficulty)

        # Step 2: Verify PoW
        pow_verify = auth_flow.verify_pow(challenge_id, nonce)
        assert pow_verify.step == AuthStep.POW_VERIFIED.value
        session_token = pow_verify.session_token

        # Step 3: Submit email
        email_response = auth_flow.submit_email(session_token, "user@example.com")
        assert email_response.step == AuthStep.EMAIL_CODE_SENT.value

        # Get code from test helper
        code = auth_flow.email_verifier.get_code_for_testing("user@example.com")

        # Step 4: Verify email
        email_verify = auth_flow.verify_email_code(session_token, code)
        assert email_verify.step == AuthStep.EMAIL_VERIFIED.value
        assert 'qr_code_uri' in email_verify.data['totp']

        # Step 5: Verify TOTP
        totp_code = auth_flow.totp_manager.get_current_token("user@example.com")
        totp_verify = auth_flow.verify_totp(session_token, totp_code)
        assert totp_verify.step == AuthStep.TOTP_VERIFIED.value

        # Step 6: Create account
        create_response = auth_flow.create_account_sync(
            session_token,
            "newuser",
            "SecurePassword123!"
        )
        assert create_response.step == AuthStep.ACCOUNT_CREATED.value
        assert create_response.data['username'] == "newuser"

        # Verify session is cleaned up
        assert session_token not in auth_flow.sessions

        # Verify user can login
        login_response = auth_flow.login("newuser", "SecurePassword123!", "")
        # May need TOTP depending on setup
        assert login_response.step in ["logged_in", "totp_required"]

    def test_session_persistence_across_steps(self, auth_flow):
        """Test that session data persists across the flow"""
        # Start flow
        challenge = auth_flow.pow.generate_challenge()
        nonce = solve_pow_challenge(challenge.challenge, challenge.difficulty)
        result = auth_flow.verify_pow(challenge.challenge_id, nonce)
        session_token = result.session_token

        # Check session step 1
        status = auth_flow.get_session_status(session_token)
        assert status['pow_verified'] is True
        assert status['email_verified'] is False

        # Complete email
        auth_flow.submit_email(session_token, "test@example.com")
        code = auth_flow.email_verifier.get_code_for_testing("test@example.com")
        auth_flow.verify_email_code(session_token, code)

        # Check session step 2
        status = auth_flow.get_session_status(session_token)
        assert status['email_verified'] is True
        assert status['totp_verified'] is False

        # Complete TOTP
        totp_code = auth_flow.totp_manager.get_current_token("test@example.com")
        auth_flow.verify_totp(session_token, totp_code)

        # Check session step 3
        status = auth_flow.get_session_status(session_token)
        assert status['totp_verified'] is True


# ============================================================
# Error Handling Tests
# ============================================================

class TestErrorHandling:
    """Test error handling in various scenarios"""

    def test_get_status(self, auth_flow):
        """Test system status report"""
        status = auth_flow.get_status()
        assert 'active_sessions' in status
        assert 'session_expiry_minutes' in status
        assert 'pow' in status
        assert 'email' in status
        assert 'totp' in status
        assert 'users' in status

    def test_reset_clears_everything(self, auth_flow):
        """Test that reset clears all state"""
        # Create some state
        challenge = auth_flow.pow.generate_challenge()
        token = auth_flow._create_session()
        auth_flow.email_verifier.generate_code("test@example.com")
        auth_flow.totp_manager.generate_secret("test@example.com")

        # Reset
        auth_flow.reset()

        assert len(auth_flow.sessions) == 0
        # Note: reset on modules just clears their internal state

    def test_destroy_cleans_resources(self, auth_flow):
        """Test destroy method"""
        auth_flow._create_session()
        auth_flow.destroy()
        assert len(auth_flow.sessions) == 0

    def test_get_active_sessions_count(self, auth_flow):
        """Test active session counting"""
        assert auth_flow.get_active_sessions_count() == 0

        auth_flow._create_session()
        auth_flow._create_session()
        assert auth_flow.get_active_sessions_count() == 2


# ============================================================
# Concurrent Execution
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
