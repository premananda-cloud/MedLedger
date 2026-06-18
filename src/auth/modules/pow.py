# modules/pow.py
import hashlib
import secrets
import time
import threading
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict




class PoWStatus(Enum):
    """Proof of Work verification status"""
    SUCCESS = "success"
    INVALID_CHALLENGE = "invalid_challenge"
    EXPIRED = "expired"
    ALREADY_USED = "already_used"
    INVALID_PROOF = "invalid_proof"


@dataclass
class ChallengeRecord:
    """Stores challenge data for a single PoW request"""
    challenge: str
    timestamp: float
    used: bool = False


@dataclass
class Challenge:
    """Generated challenge to send to client"""
    challenge_id: str
    challenge: str
    difficulty: int
    timestamp: float

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON response"""
        return {
            'challenge_id': self.challenge_id,
            'challenge': self.challenge,
            'difficulty': self.difficulty,
            'timestamp': self.timestamp
        }


@dataclass
class VerificationResult:
    """Result of PoW verification"""
    success: bool
    message: str
    status: PoWStatus
    session_token: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON response"""
        result = {
            'success': self.success,
            'message': self.message,
            'status': self.status.value
        }
        if self.session_token:
            result['session_token'] = self.session_token
        return result


class PoW:
    """
    Proof of Work challenge system

    Used to prevent spam/bot attacks by requiring computational work.
    Client must find a nonce that produces a SHA-256 hash starting with
    a specified number of zeros.

    Features:
    - Challenge generation with unique IDs
    - Difficulty-based verification
    - Automatic cleanup of expired challenges
    - Session token generation on success
    - Thread-safe challenge storage
    """

    def __init__(
        self,
        difficulty: int = 4,
        expiry_seconds: int = 300,  # 5 minutes
        cleanup_interval: int = 60,  # Cleanup every 60 seconds
        rate_limit_per_minute: int = 30
    ):
        """
        Initialize PoW system

        Args:
            difficulty: Number of leading zeros required in hash
            expiry_seconds: Challenge expiry time in seconds
            cleanup_interval: How often to clean expired challenges (seconds)
            rate_limit_per_minute: Max challenges per IP per minute (0 = disabled)
        """
        self.difficulty = difficulty
        self.expiry_seconds = expiry_seconds
        self.cleanup_interval = cleanup_interval
        self.rate_limit_per_minute = rate_limit_per_minute
        self.challenges: Dict[str, ChallengeRecord] = {}
        self._lock = threading.Lock()  # Thread safety
        self._request_times: Dict[str, list] = defaultdict(list)
        self._rate_lock = threading.Lock()

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="PoW-Cleanup"
        )
        self._running = True
        self._cleanup_thread.start()

    def generate_challenge(self, client_ip: Optional[str] = None) -> Optional[Challenge]:
        """
        Generate a new PoW challenge

        Args:
            client_ip: Optional client IP for rate limiting

        Returns:
            Challenge object, or None if rate limited
        """
        # Rate limiting check
        if client_ip and self.rate_limit_per_minute > 0:
            with self._rate_lock:
                now = time.time()
                self._request_times[client_ip] = [
                    t for t in self._request_times[client_ip]
                    if now - t < 60
                ]
                if len(self._request_times[client_ip]) >= self.rate_limit_per_minute:
                    return None  # Rate limited
                self._request_times[client_ip].append(now)

        # Generate unique challenge ID (32 hex chars = 16 bytes)
        challenge_id = secrets.token_hex(16)

        # Generate random challenge string (base64-like, 32 bytes)
        challenge = secrets.token_urlsafe(32)

        timestamp = time.time()

        # Store challenge record (thread-safe)
        with self._lock:
            self.challenges[challenge_id] = ChallengeRecord(
                challenge=challenge,
                timestamp=timestamp,
                used=False
            )

        return Challenge(
            challenge_id=challenge_id,
            challenge=challenge,
            difficulty=self.difficulty,
            timestamp=timestamp
        )

    def verify(self, challenge_id: str, nonce: str) -> VerificationResult:
        """
        Verify a PoW solution

        Args:
            challenge_id: The challenge ID to verify against
            nonce: The nonce found by the client

        Returns:
            VerificationResult with success status and optional session token
        """
        # Get challenge record (thread-safe)
        with self._lock:
            record = self.challenges.get(challenge_id)

            # Check if challenge exists
            if not record:
                return VerificationResult(
                    success=False,
                    message="Invalid or expired challenge",
                    status=PoWStatus.INVALID_CHALLENGE
                )

            # Check if already used
            if record.used:
                return VerificationResult(
                    success=False,
                    message="Challenge already used",
                    status=PoWStatus.ALREADY_USED
                )

            # Check expiry
            if time.time() - record.timestamp > self.expiry_seconds:
                del self.challenges[challenge_id]
                return VerificationResult(
                    success=False,
                    message="Challenge expired",
                    status=PoWStatus.EXPIRED
                )

            # Verify the proof of work
            input_string = record.challenge + nonce
            hash_result = hashlib.sha256(input_string.encode()).hexdigest()
            prefix = "0" * self.difficulty

            if not hash_result.startswith(prefix):
                return VerificationResult(
                    success=False,
                    message="Invalid proof of work",
                    status=PoWStatus.INVALID_PROOF
                )

            # Mark as used and generate session token
            record.used = True
            session_token = secrets.token_hex(32)

        return VerificationResult(
            success=True,
            message="PoW verified successfully",
            status=PoWStatus.SUCCESS,
            session_token=session_token
        )

    def solve_challenge(self, challenge: str, difficulty: int) -> Optional[str]:
        """
        Solve a PoW challenge (for testing or client-side simulation)

        Args:
            challenge: The challenge string
            difficulty: Number of leading zeros required

        Returns:
            Valid nonce if found, None if not
        """
        prefix = "0" * difficulty
        nonce = 0

        # This is intentionally slow - that's the point of PoW
        while True:
            nonce_str = str(nonce)
            input_string = challenge + nonce_str
            hash_result = hashlib.sha256(input_string.encode()).hexdigest()

            if hash_result.startswith(prefix):
                return nonce_str

            nonce += 1

            # Safety limit to prevent infinite loops
            if nonce > 10_000_000:  # 10 million attempts max
                return None

    def estimate_solve_time(self, difficulty: Optional[int] = None) -> Dict:
        """
        Estimate the time needed to solve a challenge at given difficulty

        Args:
            difficulty: Difficulty level (defaults to current)

        Returns:
            Dict with estimated time and attempts
        """
        diff = difficulty or self.difficulty
        # Average attempts needed: 16^difficulty / 2
        # (since each hex digit has 16 possibilities)
        avg_attempts = (16 ** diff) / 2

        # Rough estimate: 100,000 hashes/second for JS client
        # Adjust based on your expected client performance
        hashes_per_second = 100000
        avg_seconds = avg_attempts / hashes_per_second

        return {
            'difficulty': diff,
            'estimated_attempts': int(avg_attempts),
            'estimated_seconds': round(avg_seconds, 2),
            'estimated_time': self._format_time(avg_seconds)
        }

    def _format_time(self, seconds: float) -> str:
        """Format seconds into human-readable time"""
        if seconds < 1:
            return f"{int(seconds * 1000)}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        else:
            minutes = int(seconds / 60)
            secs = seconds % 60
            return f"{minutes}m {secs:.0f}s"

    def is_challenge_valid(self, challenge_id: str) -> bool:
        """
        Check if a challenge is still valid (exists, not expired, not used)

        Args:
            challenge_id: Challenge ID to check

        Returns:
            True if challenge is valid
        """
        with self._lock:
            record = self.challenges.get(challenge_id)
            if not record:
                return False
            if record.used:
                return False
            if time.time() - record.timestamp > self.expiry_seconds:
                return False
            return True

    def get_status(self) -> Dict:
        """
        Get current PoW system status

        Returns:
            Dict with active challenges count and difficulty
        """
        with self._lock:
            total = len(self.challenges)
            active = sum(
                1 for r in self.challenges.values()
                if not r.used and (time.time() - r.timestamp) <= self.expiry_seconds
            )
            expired = total - active

        return {
            'active_challenges': active,
            'expired_challenges': expired,
            'total_challenges': total,
            'difficulty': self.difficulty,
            'expiry_seconds': self.expiry_seconds
        }

    def _cleanup_loop(self):
        """Background thread to periodically clean expired challenges"""
        while self._running:
            time.sleep(self.cleanup_interval)
            self._cleanup()

    def _cleanup(self):
        """Remove expired challenges"""
        with self._lock:
            now = time.time()
            expired_ids = [
                challenge_id
                for challenge_id, record in self.challenges.items()
                if now - record.timestamp > self.expiry_seconds
            ]

            for challenge_id in expired_ids:
                del self.challenges[challenge_id]

            if expired_ids:
                print(f"[PoW] Cleaned up {len(expired_ids)} expired challenges")

    def reset(self):
        """Reset all challenges (for testing)"""
        with self._lock:
            self.challenges.clear()

    def destroy(self):
        """
        Stop the cleanup thread and clean up resources

        Call this when shutting down the application
        """
        self._running = False
        if hasattr(self, '_cleanup_thread') and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)
        self.challenges.clear()

    def __del__(self):
        """Destructor to ensure cleanup"""
        self.destroy()


# Singleton pattern
_pow_instance: Optional[PoW] = None


def get_pow(
    difficulty: int = 4,
    expiry_seconds: int = 300
) -> PoW:
    """
    Get or create the singleton PoW instance

    Args:
        difficulty: Number of leading zeros required
        expiry_seconds: Challenge expiry time in seconds
    """
    global _pow_instance
    if _pow_instance is None:
        _pow_instance = PoW(
            difficulty=difficulty,
            expiry_seconds=expiry_seconds
        )
    return _pow_instance


def reset_pow():
    """Reset the singleton instance (for testing)"""
    global _pow_instance
    if _pow_instance:
        _pow_instance.destroy()
    _pow_instance = None
