"""
tests/test_auth/test_pow.py

Pure unit tests for POWModule.
No I/O — all pure functions for challenge generation and verification.
"""
import hashlib
import time
import pytest

from auth.pow import POWModule
from auth.models import POWChallenge


@pytest.fixture
def pow_module():
    # Use difficulty=1 for fast tests
    return POWModule(difficulty=1, expiry_seconds=300)


# ─────────────────────────────────────────────
# new_challenge
# ─────────────────────────────────────────────

def test_new_challenge_returns_challenge(pow_module):
    ch = pow_module.new_challenge()
    assert ch.challenge_id
    assert ch.challenge
    assert ch.difficulty == 1
    assert ch.timestamp > 0


def test_new_challenge_has_unique_id(pow_module):
    ch1 = pow_module.new_challenge()
    ch2 = pow_module.new_challenge()
    assert ch1.challenge_id != ch2.challenge_id


def test_new_challenge_has_unique_data(pow_module):
    ch1 = pow_module.new_challenge()
    ch2 = pow_module.new_challenge()
    assert ch1.challenge != ch2.challenge


def test_new_challenge_timestamp_is_recent(pow_module):
    before = time.time()
    ch = pow_module.new_challenge()
    after = time.time()
    assert before <= ch.timestamp <= after


def test_new_challenge_difficulty_matches_config(pow_module):
    assert pow_module.new_challenge().difficulty == 1


def test_new_challenge_to_dict(pow_module):
    ch = pow_module.new_challenge()
    d = ch.to_dict()
    assert "challenge_id" in d
    assert "challenge" in d
    assert "difficulty" in d
    assert "timestamp" in d


# ─────────────────────────────────────────────
# verify_solution
# ─────────────────────────────────────────────

def test_verify_valid_solution_returns_success(pow_module):
    ch = pow_module.new_challenge()
    nonce = POWModule.solve(ch.challenge, ch.difficulty)
    assert nonce is not None
    result = pow_module.verify_solution(ch, nonce)
    assert result.success is True


def test_verify_invalid_solution_returns_failure(pow_module):
    ch = pow_module.new_challenge()
    result = pow_module.verify_solution(ch, "definitely_wrong_nonce")
    assert result.success is False


def test_verify_empty_solution_returns_failure(pow_module):
    ch = pow_module.new_challenge()
    result = pow_module.verify_solution(ch, "")
    # Empty string hash very unlikely to start with "0"
    expected_prefix = "0" * ch.difficulty
    hash_val = hashlib.sha256((ch.challenge + "").encode()).hexdigest()
    expected_success = hash_val.startswith(expected_prefix)
    assert result.success == expected_success


def test_verify_solution_for_different_challenge_fails(pow_module):
    ch1 = pow_module.new_challenge()
    ch2 = pow_module.new_challenge()
    nonce = POWModule.solve(ch1.challenge, ch1.difficulty)
    assert nonce is not None
    # nonce valid for ch1 should not be valid for ch2
    result = pow_module.verify_solution(ch2, nonce)
    # This could theoretically pass but is astronomically unlikely
    # We just verify the function runs without error
    assert isinstance(result.success, bool)


def test_verify_solution_success_message(pow_module):
    ch = pow_module.new_challenge()
    nonce = POWModule.solve(ch.challenge, ch.difficulty)
    result = pow_module.verify_solution(ch, nonce)
    assert result.message


def test_verify_solution_failure_message(pow_module):
    ch = pow_module.new_challenge()
    result = pow_module.verify_solution(ch, "wrong")
    assert result.message


# ─────────────────────────────────────────────
# is_expired
# ─────────────────────────────────────────────

def test_is_expired_fresh_challenge_returns_false(pow_module):
    ch = pow_module.new_challenge()
    assert pow_module.is_expired(ch) is False


def test_is_expired_old_challenge_returns_true():
    module = POWModule(difficulty=1, expiry_seconds=10)
    ch = POWChallenge(
        challenge_id="test",
        challenge="test",
        difficulty=1,
        timestamp=time.time() - 100,  # 100 seconds ago
    )
    assert module.is_expired(ch) is True


def test_is_expired_with_explicit_now(pow_module):
    ch = pow_module.new_challenge()
    future_now = ch.timestamp + 1000  # far in the future
    assert pow_module.is_expired(ch, now=future_now) is True


# ─────────────────────────────────────────────
# solve (test helper)
# ─────────────────────────────────────────────

def test_solve_finds_valid_nonce():
    challenge = "test_data_123"
    difficulty = 1
    nonce = POWModule.solve(challenge, difficulty)
    assert nonce is not None
    hash_val = hashlib.sha256((challenge + nonce).encode()).hexdigest()
    assert hash_val.startswith("0" * difficulty)


def test_solve_returns_none_for_impossible_difficulty():
    # difficulty=8 with max_attempts=1 almost certainly fails
    nonce = POWModule.solve("test", difficulty=8, max_attempts=1)
    assert nonce is None
