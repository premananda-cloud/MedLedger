"""
tests/test_auth/test_totp.py

Pure unit tests for TOTPModule.
No I/O — all pure functions operating on secrets and codes.
"""
import pytest
import pyotp

from auth.totp import TOTPModule


@pytest.fixture
def totp():
    return TOTPModule(issuer="TestApp", window=1)


# ─────────────────────────────────────────────
# generate_secret
# ─────────────────────────────────────────────

def test_generate_secret_returns_secret_and_uri(totp):
    result = totp.generate_secret("user@example.com")
    assert result.secret
    assert result.uri
    assert result.issuer == "TestApp"
    assert result.email == "user@example.com"


def test_generate_secret_is_valid_base32(totp):
    result = totp.generate_secret("user@example.com")
    # pyotp should be able to create a TOTP with this secret
    t = pyotp.TOTP(result.secret)
    assert t.now()  # generates a code without raising


def test_generate_secret_uri_contains_issuer(totp):
    result = totp.generate_secret("user@example.com")
    assert "TestApp" in result.uri


def test_generate_secret_uri_contains_email(totp):
    result = totp.generate_secret("user@example.com")
    assert "user" in result.uri


def test_generate_secret_uri_starts_with_otpauth(totp):
    result = totp.generate_secret("user@example.com")
    assert result.uri.startswith("otpauth://totp/")


def test_generate_secret_produces_unique_secrets(totp):
    r1 = totp.generate_secret("user@example.com")
    r2 = totp.generate_secret("user@example.com")
    assert r1.secret != r2.secret


# ─────────────────────────────────────────────
# verify_code
# ─────────────────────────────────────────────

def test_verify_valid_code_returns_true(totp):
    result = totp.generate_secret("user@example.com")
    current_code = totp.current_token(result.secret)
    assert totp.verify_code(result.secret, current_code) is True


def test_verify_wrong_code_returns_false(totp):
    result = totp.generate_secret("user@example.com")
    assert totp.verify_code(result.secret, "000000") is False


def test_verify_empty_code_returns_false(totp):
    result = totp.generate_secret("user@example.com")
    assert totp.verify_code(result.secret, "") is False


def test_verify_empty_secret_returns_false(totp):
    assert totp.verify_code("", "123456") is False


def test_verify_code_wrong_secret_returns_false(totp):
    r1 = totp.generate_secret("user1@example.com")
    r2 = totp.generate_secret("user2@example.com")
    code_for_r1 = totp.current_token(r1.secret)
    # Code for r1 should not verify against r2's secret
    assert totp.verify_code(r2.secret, code_for_r1) is False


def test_verify_code_non_numeric_returns_false(totp):
    result = totp.generate_secret("user@example.com")
    assert totp.verify_code(result.secret, "abcdef") is False


# ─────────────────────────────────────────────
# generate_backup_codes
# ─────────────────────────────────────────────

def test_generate_backup_codes_default_count(totp):
    codes = totp.generate_backup_codes()
    assert len(codes) == 8


def test_generate_backup_codes_custom_count(totp):
    codes = totp.generate_backup_codes(count=5)
    assert len(codes) == 5


def test_backup_codes_are_unique(totp):
    codes = totp.generate_backup_codes(count=16)
    assert len(set(codes)) == 16


def test_backup_codes_format(totp):
    codes = totp.generate_backup_codes()
    for code in codes:
        # Format: XXXXXXXX-XXXXXXXX (two 8-hex-char groups with dash = 17 chars)
        assert len(code) == 17
        assert code[8] == "-"
        assert all(c in "0123456789ABCDEF-" for c in code)


def test_backup_codes_are_strings(totp):
    codes = totp.generate_backup_codes()
    assert all(isinstance(c, str) for c in codes)


# ─────────────────────────────────────────────
# current_token (test helper)
# ─────────────────────────────────────────────

def test_current_token_returns_six_digits(totp):
    result = totp.generate_secret("user@example.com")
    token = totp.current_token(result.secret)
    assert token is not None
    assert len(token) == 6
    assert token.isdigit()


def test_current_token_empty_secret_returns_none(totp):
    assert totp.current_token("") is None
