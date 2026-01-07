"""Tests for password generation."""

import string
import pytest
from cli.generator import generate_password
from core import MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH


class TestPasswordGenerator:
    """Test cases for secure password generation."""

    def test_default_password_length(self):
        """Default password should be 16 characters."""
        password = generate_password()
        assert len(password) == 16

    def test_custom_length(self):
        """Password should match requested length."""
        for length in [8, 12, 20, 32, 64]:
            password = generate_password(length=length)
            assert len(password) == length

    def test_minimum_length_validation(self):
        """Should raise error for length less than selected types."""
        with pytest.raises(ValueError):
            generate_password(length=2, use_upper=True, use_lower=True,
                            use_digits=True, use_special=True)

    def test_no_character_types_raises_error(self):
        """Should raise error if no character types selected."""
        with pytest.raises(ValueError):
            generate_password(use_upper=False, use_lower=False,
                            use_digits=False, use_special=False)

    def test_guaranteed_uppercase(self):
        """When uppercase selected, password must contain uppercase."""
        for _ in range(10):  # Run multiple times due to randomness
            password = generate_password(length=12, use_upper=True)
            assert any(c in string.ascii_uppercase for c in password)

    def test_guaranteed_lowercase(self):
        """When lowercase selected, password must contain lowercase."""
        for _ in range(10):
            password = generate_password(length=12, use_lower=True)
            assert any(c in string.ascii_lowercase for c in password)

    def test_guaranteed_digits(self):
        """When digits selected, password must contain digits."""
        for _ in range(10):
            password = generate_password(length=12, use_digits=True)
            assert any(c in string.digits for c in password)

    def test_guaranteed_special(self):
        """When special selected, password must contain special chars."""
        for _ in range(10):
            password = generate_password(length=12, use_special=True)
            assert any(c in string.punctuation for c in password)

    def test_only_uppercase(self):
        """Password with only uppercase should contain only uppercase."""
        password = generate_password(length=12, use_upper=True, use_lower=False,
                                    use_digits=False, use_special=False)
        assert all(c in string.ascii_uppercase for c in password)

    def test_only_digits(self):
        """Password with only digits should contain only digits."""
        password = generate_password(length=12, use_upper=False, use_lower=False,
                                    use_digits=True, use_special=False)
        assert all(c in string.digits for c in password)

    def test_randomness(self):
        """Generated passwords should be different each time."""
        passwords = [generate_password() for _ in range(100)]
        unique_passwords = set(passwords)
        # With 16 char passwords and full charset, collision is extremely unlikely
        assert len(unique_passwords) == 100

    def test_all_character_types(self):
        """Password with all types should contain all types."""
        for _ in range(10):
            password = generate_password(length=16, use_upper=True, use_lower=True,
                                        use_digits=True, use_special=True)
            assert any(c in string.ascii_uppercase for c in password)
            assert any(c in string.ascii_lowercase for c in password)
            assert any(c in string.digits for c in password)
            assert any(c in string.punctuation for c in password)

    def test_minimum_length_with_all_types(self):
        """Minimum length 4 should work with all 4 types."""
        password = generate_password(length=4, use_upper=True, use_lower=True,
                                    use_digits=True, use_special=True)
        assert len(password) == 4
        # Should have exactly one of each type
        assert sum(1 for c in password if c in string.ascii_uppercase) >= 1
        assert sum(1 for c in password if c in string.ascii_lowercase) >= 1
        assert sum(1 for c in password if c in string.digits) >= 1
        assert sum(1 for c in password if c in string.punctuation) >= 1
