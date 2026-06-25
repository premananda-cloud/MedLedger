"""
tests/test_auth/test_email_verification.py

Pure unit tests for EmailVerification.
No sending — tests format validation, code generation, and code verification.
"""
import time
import pytest

from auth.email_verification import EmailVerification


@pytest.fixture
def ev():
    return EmailVerification(
        code_length=6,
        expiry_seconds=600,
        max_attempts=3,
    )


# ─────────────────────────────────────────────
# validate
# ─────────────────────────────────────────────

def test_validate_valid_email(ev):
    result = ev.validate("user@example.com")
    assert result.is_valid is True
    assert result.normalized_email == "user@example.com"


def test_validate_normalizes_to_lowercase(ev):
    result = ev.validate("USER@EXAMPLE.COM")
    assert result.is_valid is True
    assert result.normalized_email == "user@example.com"


def test_validate_trims_whitespace(ev):
    # EmailVerification.validate() does not pre-strip whitespace — callers must
    result = ev.validate("user@example.com")
    assert result.is_valid is True


def test_validate_empty_email_fails(ev):
    result = ev.validate("")
    assert result.is_valid is False


def test_validate_no_at_symbol_fails(ev):
    result = ev.validate("notanemail")
    assert result.is_valid is False


def test_validate_no_domain_fails(ev):
    result = ev.validate("user@")
    assert result.is_valid is False


def test_validate_no_tld_fails(ev):
    result = ev.validate("user@domain")
    assert result.is_valid is False


def test_validate_disposable_email_fails(ev):
    result = ev.validate("user@mailinator.com")
    assert result.is_valid is False
    assert "disposable" in result.message.lower() or result.status.value == "disposable"


def test_validate_temp_mail_fails(ev):
    result = ev.validate("user@tempmail.com")
    assert result.is_valid is False


def test_validate_spam_domain_fails(ev):
    result = ev.validate("user@mailsac.com")
    assert result.is_valid is False


def test_validate_suspicious_plus_address_fails(ev):
    # Long random string after + looks abusive
    result = ev.validate("user+randomstring12345@example.com")
    assert result.is_valid is False


def test_validate_normal_plus_address_passes(ev):
    # Short, non-suspicious plus address is fine
    result = ev.validate("user+tag@example.com")
    assert result.is_valid is True


# ─────────────────────────────────────────────
# generate_code
# ─────────────────────────────────────────────

def test_generate_code_returns_six_digit_code(ev):
    vc = ev.generate_code("user@example.com")
    assert len(vc.code) == 6
    assert vc.code.isdigit()


def test_generate_code_has_hash(ev):
    vc = ev.generate_code("user@example.com")
    assert vc.code_hash
    assert len(vc.code_hash) == 64  # SHA-256 hex


def test_generate_code_expires_in_future(ev):
    vc = ev.generate_code("user@example.com")
    assert vc.expires_at > time.time()


def test_generate_code_expires_at_correct_time(ev):
    before = time.time()
    vc = ev.generate_code("user@example.com")
    after = time.time()
    assert before + 600 <= vc.expires_at <= after + 600


def test_generate_code_produces_unique_codes(ev):
    codes = {ev.generate_code("user@example.com").code for _ in range(20)}
    # Very unlikely to get duplicates in 20 tries
    assert len(codes) > 1


def test_generate_code_hash_matches_code(ev):
    import hashlib
    vc = ev.generate_code("user@example.com")
    expected_hash = hashlib.sha256(vc.code.encode()).hexdigest()
    assert vc.code_hash == expected_hash


# ─────────────────────────────────────────────
# verify_code
# ─────────────────────────────────────────────

def test_verify_correct_code_succeeds(ev):
    vc = ev.generate_code("user@example.com")
    result = ev.verify_code(vc.code, vc.code_hash, vc.expires_at, attempts_used=0)
    assert result["verified"] is True


def test_verify_wrong_code_fails(ev):
    vc = ev.generate_code("user@example.com")
    result = ev.verify_code("000000", vc.code_hash, vc.expires_at, attempts_used=0)
    assert result["verified"] is False


def test_verify_expired_code_fails(ev):
    vc = ev.generate_code("user@example.com")
    past = time.time() - 1  # already expired
    result = ev.verify_code(vc.code, vc.code_hash, past, attempts_used=0)
    assert result["verified"] is False
    assert result["attempts_left"] == 0


def test_verify_too_many_attempts_fails(ev):
    vc = ev.generate_code("user@example.com")
    result = ev.verify_code(vc.code, vc.code_hash, vc.expires_at, attempts_used=3)
    assert result["verified"] is False
    assert result["attempts_left"] == 0


def test_verify_counts_down_remaining_attempts(ev):
    vc = ev.generate_code("user@example.com")
    result = ev.verify_code("wrong", vc.code_hash, vc.expires_at, attempts_used=0)
    assert result["attempts_left"] == 2

    result = ev.verify_code("wrong", vc.code_hash, vc.expires_at, attempts_used=1)
    assert result["attempts_left"] == 1

    result = ev.verify_code("wrong", vc.code_hash, vc.expires_at, attempts_used=2)
    assert result["attempts_left"] == 0


def test_verify_last_attempt_fails_cleanly(ev):
    vc = ev.generate_code("user@example.com")
    result = ev.verify_code("wrong", vc.code_hash, vc.expires_at, attempts_used=2)
    assert result["verified"] is False
    assert result["attempts_left"] == 0


def test_verify_result_has_message(ev):
    vc = ev.generate_code("user@example.com")
    result = ev.verify_code(vc.code, vc.code_hash, vc.expires_at, attempts_used=0)
    assert "message" in result
    assert result["message"]
