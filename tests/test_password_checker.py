"""Tests for password strength checker."""

import pytest
from password_checker import check_password_strength, COMMON_PASSWORDS


class TestPasswordStrength:
    """Test cases for password strength analysis."""

    def test_strong_password(self):
        """Strong passwords should score 'Strong'."""
        password = "Tr0ub4dor&3#Xy9!"
        strength, feedback = check_password_strength(password)
        assert strength == "Strong"
        assert len(feedback) == 0

    def test_weak_short_password(self):
        """Short passwords should be marked weak."""
        password = "abc"
        strength, feedback = check_password_strength(password)
        assert strength == "Weak"
        assert any("12" in f for f in feedback)  # Mentions minimum length

    def test_medium_password(self):
        """Medium-complexity passwords should score 'Medium'."""
        password = "Password1"
        strength, feedback = check_password_strength(password)
        assert strength in ["Medium", "Weak"]  # Could be weak due to pattern

    def test_common_password_detection(self):
        """Common passwords should be flagged immediately."""
        for common_pwd in ["password", "123456", "qwerty", "admin"]:
            strength, feedback = check_password_strength(common_pwd)
            assert strength == "Weak"
            assert any("common" in f.lower() for f in feedback)

    def test_keyboard_pattern_detection(self):
        """Keyboard patterns should be penalized."""
        password = "myqwertypass"
        strength, feedback = check_password_strength(password)
        assert any("keyboard" in f.lower() for f in feedback)

    def test_repeated_characters_detection(self):
        """Repeated characters should be flagged."""
        password = "Paaaassword1!"
        strength, feedback = check_password_strength(password)
        assert any("repeated" in f.lower() for f in feedback)

    def test_missing_uppercase_feedback(self):
        """Missing uppercase should generate feedback."""
        password = "lowercase123!"
        strength, feedback = check_password_strength(password)
        assert any("uppercase" in f.lower() for f in feedback)

    def test_missing_lowercase_feedback(self):
        """Missing lowercase should generate feedback."""
        password = "UPPERCASE123!"
        strength, feedback = check_password_strength(password)
        assert any("lowercase" in f.lower() for f in feedback)

    def test_missing_digits_feedback(self):
        """Missing digits should generate feedback."""
        password = "NoDigitsHere!"
        strength, feedback = check_password_strength(password)
        assert any("number" in f.lower() for f in feedback)

    def test_missing_special_chars_feedback(self):
        """Missing special characters should generate feedback."""
        password = "NoSpecialChars123"
        strength, feedback = check_password_strength(password)
        assert any("special" in f.lower() for f in feedback)

    def test_long_password_bonus(self):
        """Passwords 16+ chars should get bonus points."""
        # Same complexity, different lengths
        short = "Abcd1234!"  # 9 chars
        long = "Abcd1234!Abcd1234!"  # 18 chars

        short_strength, _ = check_password_strength(short)
        long_strength, _ = check_password_strength(long)

        # Long password should be at least as strong
        strength_order = {"Weak": 0, "Medium": 1, "Strong": 2}
        assert strength_order[long_strength] >= strength_order[short_strength]

    def test_case_insensitive_common_check(self):
        """Common password check should be case-insensitive."""
        for variant in ["PASSWORD", "Password", "pAsSwOrD"]:
            strength, feedback = check_password_strength(variant)
            assert strength == "Weak"
            assert any("common" in f.lower() for f in feedback)

    def test_empty_password(self):
        """Empty password should be weak with feedback."""
        strength, feedback = check_password_strength("")
        assert strength == "Weak"
        assert len(feedback) > 0

    def test_common_passwords_set_not_empty(self):
        """Ensure common passwords list is populated."""
        assert len(COMMON_PASSWORDS) >= 50
