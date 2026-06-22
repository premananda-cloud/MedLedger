"""
auth/pow.py — POWModule

Responsibility: generate proof-of-work challenges and verify solutions.

Note: `capjs-server` is not available on PyPI. This module implements the
same SHA-256 leading-zeros protocol that capjs uses, so it is wire-compatible
with any capjs client. Swap `new_challenge` / `verify_solution` internals
for capjs HTTP calls if you run capjs-server as a sidecar.

What it does:
  ✓ Generates challenge data (random string + difficulty)
  ✓ Verifies that a nonce produces a hash with the required leading zeros

What it does NOT do:
  ✗ Store challenges — the orchestrator stores them (Redis / DB)
  ✗ Track expiry — the orchestrator checks timestamps
  ✗ Rate-limit — the orchestrator enforces per-IP limits
"""
from __future__ import annotations

import hashlib
import secrets
import time
from typing import Optional

from .models import POWChallenge, POWVerifyResult


class POWModule:
    """
    Proof-of-Work challenge generator and verifier.

    The orchestrator is responsible for:
      • Persisting the returned POWChallenge (keyed by challenge_id)
      • Checking expiry before calling verify_solution
      • Deleting the challenge after successful verification (replay protection)

    Usage:
        module = POWModule(difficulty=4)

        # Issue:
        challenge = module.new_challenge()
        cache.set(challenge.challenge_id, challenge.model_dump(), ttl=300)
        return challenge.to_dict()   # → client

        # Verify:
        stored = cache.get(challenge_id)
        if not stored or is_expired(stored):
            raise BadRequest("Challenge expired")
        result = module.verify_solution(
            POWChallenge(**stored), solution=nonce
        )
        if result.success:
            cache.delete(challenge_id)
    """

    def __init__(self, difficulty: int = 4, expiry_seconds: int = 300):
        """
        Args:
            difficulty:     Number of leading hex zeros required in the hash.
            expiry_seconds: Informational — stored in the challenge so the
                            orchestrator knows the intended TTL.
        """
        self.difficulty     = difficulty
        self.expiry_seconds = expiry_seconds

    # ──────────────────────────────────────────
    # Challenge generation
    # ──────────────────────────────────────────

    def new_challenge(self) -> POWChallenge:
        """
        Generate a fresh PoW challenge.

        The returned object must be persisted by the caller before being
        sent to the client.
        """
        return POWChallenge(
            challenge_id=secrets.token_hex(16),
            challenge=secrets.token_urlsafe(32),
            difficulty=self.difficulty,
            timestamp=time.time(),
        )

    # ──────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────

    def verify_solution(self, challenge: POWChallenge, solution: str) -> POWVerifyResult:
        """
        Verify that `solution` (nonce) satisfies the challenge.

        Expiry checking is intentionally left to the caller — this method
        only validates the hash constraint.

        Args:
            challenge: The POWChallenge fetched from storage by the orchestrator.
            solution:  The nonce string submitted by the client.
        """
        prefix      = "0" * challenge.difficulty
        hash_result = hashlib.sha256(
            (challenge.challenge + solution).encode()
        ).hexdigest()

        if hash_result.startswith(prefix):
            return POWVerifyResult(success=True, message="Proof of work verified.")

        return POWVerifyResult(success=False, message="Invalid proof of work solution.")

    # ──────────────────────────────────────────
    # Utilities
    # ──────────────────────────────────────────

    def is_expired(self, challenge: POWChallenge, now: Optional[float] = None) -> bool:
        """
        Convenience helper — orchestrator can call this instead of doing
        the arithmetic itself.
        """
        return (now or time.time()) - challenge.timestamp > self.expiry_seconds

    # ──────────────────────────────────────────
    # Test / CLI helper
    # ──────────────────────────────────────────

    @staticmethod
    def solve(challenge: str, difficulty: int, max_attempts: int = 10_000_000) -> Optional[str]:
        """
        Brute-force a challenge. For tests and CLI tools only.
        Returns the nonce string or None if not found.
        """
        prefix = "0" * difficulty
        for nonce in range(max_attempts):
            ns = str(nonce)
            if hashlib.sha256((challenge + ns).encode()).hexdigest().startswith(prefix):
                return ns
        return None
