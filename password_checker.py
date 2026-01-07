"""Password strength checker with common password detection and breach checking."""

import re
from typing import Optional

# Import breach checker (optional - gracefully handle if unavailable)
try:
    from breach_check import check_password_breach, format_breach_warning
    BREACH_CHECK_AVAILABLE = True
except ImportError:
    BREACH_CHECK_AVAILABLE = False

# Expanded common weak passwords list (top 100+ most common)
COMMON_PASSWORDS: set[str] = {
    # Top common passwords
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "shadow", "123123", "654321", "superman", "qazwsx",
    "michael", "football", "password1", "password123", "batman", "login",
    # More common passwords
    "admin", "welcome", "hello", "charlie", "donald", "password1234", "qwerty123",
    "admin123", "root", "toor", "pass", "test", "guest", "master123", "changeme",
    "123456789", "12345", "1234567890", "0987654321", "111111", "121212",
    "123321", "666666", "696969", "777777", "888888", "abcdef", "abcd1234",
    "qwertyuiop", "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "!qaz2wsx", "asdfgh",
    "zxcvbn", "zxcvbnm", "passw0rd", "p@ssw0rd", "p@ssword", "pa$$word",
    # Keyboard patterns
    "qwerty1", "asdf", "asdfasdf", "zxcv", "1234qwer", "qwer1234",
    # Names and words
    "jennifer", "hunter", "amanda", "jessica", "joshua", "andrew", "michelle",
    "nicole", "daniel", "maggie", "soccer", "hockey", "ranger", "thomas",
    "robert", "jordan", "lakers", "yankees", "thunder", "tigger", "killer",
    "pepper", "hammer", "summer", "winter", "spring", "orange", "banana",
    # Years and dates
    "2000", "2001", "2002", "2003", "2004", "2005", "2010", "2015", "2020",
    "2021", "2022", "2023", "2024", "2025",
    # Simple patterns
    "aaaaaa", "aaaaaaa", "aaaaaaaa", "abcabc", "abc1234", "a1b2c3",
}

# Minimum recommended password length
MIN_RECOMMENDED_LENGTH = 12


def check_password_strength(password: str) -> tuple[str, list[str]]:
    """Analyze password strength and return rating with improvement suggestions.

    Returns:
        Tuple of (strength_rating, list_of_feedback_suggestions)
    """
    score = 0
    feedback: list[str] = []

    # Check length
    if len(password) >= 16:
        score += 3
    elif len(password) >= MIN_RECOMMENDED_LENGTH:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append(f"Use at least {MIN_RECOMMENDED_LENGTH} characters.")

    # Check for different character types
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;\'`~]', password):
        score += 1
    else:
        feedback.append("Add special characters.")

    # Check for sequential characters (weak pattern)
    if re.search(r'(.)\1{2,}', password):
        feedback.append("Avoid repeated characters (e.g., 'aaa').")
        score -= 1

    # Check for common keyboard patterns
    keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', '4321', 'abcd']
    if any(pattern in password.lower() for pattern in keyboard_patterns):
        feedback.append("Avoid keyboard patterns.")
        score -= 1

    # Check if it's a common password (case-insensitive)
    if password.lower() in COMMON_PASSWORDS:
        feedback.insert(0, "This is a very common password!")
        score = 0

    # Ensure score doesn't go negative
    score = max(0, score)

    # Score rating
    if score >= 6:
        strength = "Strong"
    elif score >= 4:
        strength = "Medium"
    else:
        strength = "Weak"

    return strength, feedback


def check_password_with_breach(
    password: str,
    check_online: bool = True
) -> tuple[str, list[str], Optional[int]]:
    """Analyze password strength and check against breach databases.

    Args:
        password: The password to analyze
        check_online: Whether to check HaveIBeenPwned API (requires internet)

    Returns:
        Tuple of (strength_rating, feedback_list, breach_count)
        breach_count is None if check failed/skipped, 0 if safe, >0 if breached
    """
    strength, feedback = check_password_strength(password)
    breach_count: Optional[int] = None

    if check_online and BREACH_CHECK_AVAILABLE:
        breach_count = check_password_breach(password)

        if breach_count is not None and breach_count > 0:
            warning = format_breach_warning(breach_count)
            feedback.insert(0, warning)
            # Downgrade strength if breached
            strength = "Weak"

    return strength, feedback, breach_count
