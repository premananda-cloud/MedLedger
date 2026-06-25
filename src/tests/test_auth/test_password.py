"""
tests/test_auth/test_password.py

Pure unit tests for PasswordModule.
No I/O, no mocks needed — all pure functions.
"""
import os
import pytest

os.environ["APP_ENV"] = "test"
os.environ["TESTING"] = "true"

from auth.password import PasswordModule


# ─────────────────────────────────────────────
# Hashing
# ─────────────────────────────────────────────

def test_hash_password_returns_hash_salt_iterations():
    module = PasswordModule()
    result = module.hash_password("MyP@ssw0rd!")
    assert result.hash_hex
    assert result.salt_hex
    assert result.iterations == 1000  # test mode
    assert len(result.hash_hex) == 128  # 64 bytes hex
    assert len(result.salt_hex) == 32   # 16 bytes hex


def test_hash_password_uses_test_iterations_in_test_mode():
    module = PasswordModule()
    result = module.hash_password("password")
    assert result.iterations == 1000


def test_hash_password_accepts_explicit_iterations():
    module = PasswordModule(iterations=500)
    result = module.hash_password("password")
    assert result.iterations == 500


def test_hash_password_with_explicit_salt():
    import secrets
    module = PasswordModule()
    salt = secrets.token_bytes(16)
    result1 = module.hash_password("password", salt=salt)
    result2 = module.hash_password("password", salt=salt)
    assert result1.hash_hex == result2.hash_hex
    assert result1.salt_hex == result2.salt_hex


def test_hash_password_different_salt_different_hash():
    module = PasswordModule()
    r1 = module.hash_password("password")
    r2 = module.hash_password("password")
    # random salts → different hashes (astronomically unlikely to collide)
    assert r1.salt_hex != r2.salt_hex
    assert r1.hash_hex != r2.hash_hex


def test_hash_password_accepts_hex_string_salt():
    module = PasswordModule()
    r1 = module.hash_password("password")
    # pass the salt back as hex string (as stored in DB)
    r2 = module.hash_password("password", salt=r1.salt_hex)
    assert r1.hash_hex == r2.hash_hex


# ─────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────

def test_verify_correct_password_returns_true():
    module = PasswordModule()
    ph = module.hash_password("MyP@ssw0rd!")
    assert module.verify_password("MyP@ssw0rd!", ph.hash_hex, ph.salt_hex, ph.iterations) is True


def test_verify_wrong_password_returns_false():
    module = PasswordModule()
    ph = module.hash_password("MyP@ssw0rd!")
    assert module.verify_password("WrongPassword", ph.hash_hex, ph.salt_hex, ph.iterations) is False


def test_verify_empty_password_returns_false():
    module = PasswordModule()
    ph = module.hash_password("MyP@ssw0rd!")
    assert module.verify_password("", ph.hash_hex, ph.salt_hex, ph.iterations) is False


def test_verify_wrong_hash_length_does_not_raise():
    """Timing-safe verify must not raise on malformed hash."""
    module = PasswordModule()
    result = module.verify_password("test", "a" * 10, "b" * 32, 1000)
    assert result is False


def test_verify_wrong_salt_returns_false():
    module = PasswordModule()
    ph = module.hash_password("MyP@ssw0rd!")
    bad_salt = "cc" * 16
    assert module.verify_password("MyP@ssw0rd!", ph.hash_hex, bad_salt, ph.iterations) is False


def test_verify_wrong_iterations_returns_false():
    module = PasswordModule()
    ph = module.hash_password("MyP@ssw0rd!")
    assert module.verify_password("MyP@ssw0rd!", ph.hash_hex, ph.salt_hex, 999) is False


def test_verify_does_not_raise_on_garbage_hash():
    """Must be safe even for non-hex garbage."""
    module = PasswordModule()
    result = module.verify_password("password", "not-hex!", "b" * 32, 1000)
    assert result is False


# ─────────────────────────────────────────────
# Strength validation
# ─────────────────────────────────────────────

def test_validate_strong_password_passes():
    module = PasswordModule()
    result = module.validate_strength("MyStr0ng!Pass")
    assert result.valid is True
    assert result.score >= 3


def test_validate_very_strong_password():
    module = PasswordModule()
    result = module.validate_strength("Sup3r$ecureP@ssw0rd!")
    assert result.valid is True
    assert result.score == 5
    assert result.strength in ("strong", "very_strong")


def test_validate_empty_password_fails():
    module = PasswordModule()
    result = module.validate_strength("")
    assert result.valid is False
    assert result.score == 0
    assert result.strength == "invalid"


def test_validate_common_password_fails():
    module = PasswordModule()
    result = module.validate_strength("password123")
    assert result.valid is False
    assert result.score == 0


def test_validate_keyboard_pattern_fails():
    module = PasswordModule()
    result = module.validate_strength("qwerty123ABC!")
    assert result.valid is False
    assert any("keyboard" in issue.lower() for issue in result.issues)


def test_validate_too_short_fails():
    module = PasswordModule(min_length=8)
    result = module.validate_strength("Ab1!")
    assert result.valid is False
    assert any(str(8) in issue for issue in result.issues)


def test_validate_missing_uppercase_reported():
    module = PasswordModule()
    result = module.validate_strength("nouppercase1!")
    assert any("uppercase" in i.lower() for i in result.issues)


def test_validate_missing_digit_reported():
    module = PasswordModule()
    result = module.validate_strength("NoDigitHere!")
    assert any("number" in i.lower() for i in result.issues)


def test_validate_missing_special_reported():
    module = PasswordModule()
    result = module.validate_strength("NoSpecialChar1")
    assert any("special" in i.lower() for i in result.issues)


def test_validate_score_is_bounded_0_to_5():
    module = PasswordModule()
    result = module.validate_strength("Sup3r$ecureP@ssw0rd!")
    assert 0 <= result.score <= 5


def test_validate_strength_labels():
    module = PasswordModule()
    valid_labels = {"invalid", "weak", "fair", "good", "strong", "very_strong"}
    for pw in ["", "abc", "Abc1!", "Abc123!Xyz", "Abc123!XyzVery", "Sup3r$ecureP@ssw0rd!"]:
        result = module.validate_strength(pw)
        assert result.strength in valid_labels
