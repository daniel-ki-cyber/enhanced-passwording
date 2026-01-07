"""Tests for breach detection module."""

import pytest
from breach_check import (
    get_password_hash,
    format_breach_warning,
    check_and_warn
)


class TestPasswordHashing:
    """Test password hash functions."""

    def test_hash_format(self):
        """Hash should be split into 5-char prefix and 35-char suffix."""
        prefix, suffix = get_password_hash("password")
        assert len(prefix) == 5
        assert len(suffix) == 35

    def test_hash_uppercase(self):
        """Hash should be uppercase."""
        prefix, suffix = get_password_hash("test")
        assert prefix == prefix.upper()
        assert suffix == suffix.upper()

    def test_hash_consistency(self):
        """Same password should produce same hash."""
        hash1 = get_password_hash("mypassword")
        hash2 = get_password_hash("mypassword")
        assert hash1 == hash2

    def test_hash_uniqueness(self):
        """Different passwords should produce different hashes."""
        hash1 = get_password_hash("password1")
        hash2 = get_password_hash("password2")
        assert hash1 != hash2

    def test_known_hash(self):
        """Test against known SHA-1 hash."""
        # SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        prefix, suffix = get_password_hash("password")
        assert prefix == "5BAA6"
        assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


class TestBreachWarning:
    """Test breach warning message formatting."""

    def test_zero_breaches(self):
        """Zero breaches should return empty string."""
        warning = format_breach_warning(0)
        assert warning == ""

    def test_few_breaches(self):
        """Few breaches should suggest different password."""
        warning = format_breach_warning(5)
        assert "different password" in warning.lower()

    def test_moderate_breaches(self):
        """Moderate breaches should show WARNING."""
        warning = format_breach_warning(50)
        assert "WARNING" in warning

    def test_many_breaches(self):
        """Many breaches should show DANGER."""
        warning = format_breach_warning(500)
        assert "DANGER" in warning

    def test_critical_breaches(self):
        """Critical breach count should show CRITICAL."""
        warning = format_breach_warning(10000)
        assert "CRITICAL" in warning

    def test_breach_count_in_message(self):
        """Breach count should appear in message."""
        warning = format_breach_warning(42)
        assert "42" in warning


class TestCheckAndWarn:
    """Test combined check and warn function."""

    def test_returns_tuple(self):
        """Should return tuple of (bool, str)."""
        result = check_and_warn("sometestpassword12345")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    def test_safe_password_result(self):
        """Unique password should be marked safe (if API available)."""
        # Use a random-ish password unlikely to be in breaches
        is_safe, message = check_and_warn("xK9#mL2$pQ7@nR4!")
        # Either safe or API unavailable
        assert is_safe == True or "offline" in message.lower() or "could not" in message.lower()
