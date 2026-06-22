"""
auth/pow.py — Pure Proof-of-Work logic.

Zero I/O. Zero background threads. Zero singletons.

Responsibilities:
  • Generate challenge data (the random string + difficulty)
  • Verify that a nonce satisfies the hash constraint

The caller (auth_service / infrastructure layer) is responsible for:
  • Persisting active challenges (in-memory dict, Redis, DB — your choice)
  • Enforcing expiry and replay protection
  • Rate-limiting per IP

This keeps PoW logic testable without any clock/thread mocking.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from typing import Optional

from .models import AuthChallenge, PoWStatus, PoWVerifyResult


class PoWService:
    """
    Stateless Proof-of-Work helper.

    Challenge *storage* lives outside this class — the caller passes the
    stored challenge string back in on verification.

    Example (auth_service):
        pow = PoWService(difficulty=4)

        # Issue challenge:
        challenge = pow.new_challenge()
        cache.set(challenge.challenge_id, challenge, ttl=300)
        return challenge.to_dict()

        # Verify solution:
        stored = cache.get(challenge_id)
        result = pow.verify(stored, nonce, now=time.time())
        if result.success:
            cache.delete(challenge_id)   # replay protection
    """

    def __init__(self, difficulty: int = 4, expiry_seconds: int = 300):
        """
        Args:
            difficulty:      Number of leading hex zeros required.
            expiry_seconds:  How long a challenge stays valid.
        """
        self.difficulty     = difficulty
        self.expiry_seconds = expiry_seconds
        self._prefix        = "0" * difficulty

    # ──────────────────────────────────────────
    # Challenge generation
    # ──────────────────────────────────────────

    def new_challenge(self) -> AuthChallenge:
        """
        Generate a fresh PoW challenge.

        Returns an AuthChallenge. The caller must persist it (keyed by
        challenge_id) before returning it to the client.
        """
        return AuthChallenge(
            challenge_id=secrets.token_hex(16),
            challenge=secrets.token_urlsafe(32),
            difficulty=self.difficulty,
            timestamp=time.time(),
        )

    # ──────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────

    def verify(
        self,
        challenge: AuthChallenge,
        nonce:     str,
        *,
        now:       Optional[float] = None,
    ) -> PoWVerifyResult:
        """
        Verify that `nonce` is a valid solution for `challenge`.

        Args:
            challenge: The AuthChallenge retrieved from storage.
            nonce:     The nonce submitted by the client.
            now:       Current unix timestamp (defaults to time.time()).
                       Pass an explicit value in tests to freeze time.

        Note: Replay protection (marking the challenge as used) is the
        caller's responsibility — delete the record from storage on success.
        """
        if now is None:
            now = time.time()

        if now - challenge.timestamp > self.expiry_seconds:
            return PoWVerifyResult(
                success=False,
                message="Challenge expired",
                status=PoWStatus.EXPIRED,
            )

        hash_result = hashlib.sha256(
            (challenge.challenge + nonce).encode()
        ).hexdigest()

        if not hash_result.startswith(self._prefix):
            return PoWVerifyResult(
                success=False,
                message="Invalid proof of work",
                status=PoWStatus.INVALID_PROOF,
            )

        session_token = secrets.token_hex(32)
        return PoWVerifyResult(
            success=True,
            message="Proof of work verified",
            status=PoWStatus.SUCCESS,
            session_token=session_token,
        )

    # ──────────────────────────────────────────
    # Utilities
    # ──────────────────────────────────────────

    def estimate_solve_time(self, difficulty: Optional[int] = None) -> dict:
        """
        Rough estimate of client solve time for a given difficulty.
        Assumes ~100 000 SHA-256 hashes/s in a browser JS environment.
        """
        diff = difficulty if difficulty is not None else self.difficulty
        avg_attempts   = (16 ** diff) / 2
        hashes_per_sec = 100_000
        avg_seconds    = avg_attempts / hashes_per_sec

        def fmt(s: float) -> str:
            if s < 1:
                return f"{int(s * 1000)}ms"
            if s < 60:
                return f"{s:.1f}s"
            return f"{int(s // 60)}m {s % 60:.0f}s"

        return {
            "difficulty":         diff,
            "estimated_attempts": int(avg_attempts),
            "estimated_seconds":  round(avg_seconds, 2),
            "estimated_time":     fmt(avg_seconds),
        }

    # ──────────────────────────────────────────
    # Test helper
    # ──────────────────────────────────────────

    @staticmethod
    def solve(challenge: str, difficulty: int, max_attempts: int = 10_000_000) -> Optional[str]:
        """
        Brute-force a PoW challenge (for tests and CLI tools only).

        Returns the nonce string, or None if not found within max_attempts.
        """
        prefix = "0" * difficulty
        for nonce in range(max_attempts):
            nonce_str = str(nonce)
            if hashlib.sha256((challenge + nonce_str).encode()).hexdigest().startswith(prefix):
                return nonce_str
        return None
