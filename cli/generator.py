"""Password generation CLI flows.

Handles password generation, preview, and optional saving.
"""

import secrets
import string

from core import DEFAULT_PASSWORD_LENGTH
from password_checker import check_password_strength
from vault import save_password

from cli.prompts import prompt_for_password_length, prompt_for_character_types


def generate_password(
    length: int = DEFAULT_PASSWORD_LENGTH,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_special: bool = True
) -> str:
    """Generate secure password with guaranteed character type inclusion.

    Ensures at least one character from each selected type is present.

    Args:
        length: Password length
        use_upper: Include uppercase letters
        use_lower: Include lowercase letters
        use_digits: Include digits
        use_special: Include special characters

    Returns:
        Generated password string

    Raises:
        ValueError: If no character types selected or length too short
    """
    selected_types = sum([use_upper, use_lower, use_digits, use_special])

    if selected_types == 0:
        raise ValueError("At least one character type must be selected.")
    if length < selected_types:
        raise ValueError(
            f"Password length must be at least {selected_types} "
            "to include all selected character types."
        )

    # Build character pools
    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_special:
        pools.append(string.punctuation)

    # Guarantee at least one character from each selected type
    password_chars = [secrets.choice(pool) for pool in pools]

    # Fill remaining length from combined pool
    combined_pool = ''.join(pools)
    remaining_length = length - len(password_chars)
    password_chars.extend(secrets.choice(combined_pool) for _ in range(remaining_length))

    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars)


def preview_and_analyze(password: str) -> tuple[str, list[str]]:
    """Display password and analyze its strength.

    Args:
        password: Password to analyze

    Returns:
        Tuple of (strength, feedback_list)
    """
    print(f"\nGenerated Password: {password}")
    strength, feedback = check_password_strength(password)
    print(f"Password Strength: {strength}")

    if feedback:
        print("Suggestions:")
        for tip in feedback:
            print(f"  - {tip}")

    return strength, feedback


def prompt_save_password(password: str, strength: str, feedback: list[str]) -> bool:
    """Prompt user to save password with warnings for weak passwords.

    Args:
        password: Password to save
        strength: Strength rating
        feedback: Feedback messages

    Returns:
        True if saved, False otherwise
    """
    save = input("\nWould you like to save this password? (y/n): ").strip().lower()
    if save != 'y':
        print("Password not saved.")
        return False

    if strength == "Weak" or any("common" in f.lower() for f in feedback):
        warn = input(
            "Warning: This password may be weak or common. Proceed with saving? (y/n): "
        ).strip().lower()
        if warn != 'y':
            print("Save canceled due to weak password.")
            return False

    label = input("Enter a name or label for this password (e.g., 'Gmail'): ").strip()
    if not label:
        print("No label provided. Password not saved.")
        return False

    if save_password(label, password):
        print(f"Password saved as '{label}'.")
        return True
    else:
        print("Failed to save password.")
        return False


def generate_password_flow() -> None:
    """Full interactive flow for generating a password."""
    print("\n--- Password Generation ---")

    length = prompt_for_password_length()
    if length is None:
        print("Canceled password generation.")
        return

    char_types = prompt_for_character_types()
    if char_types is None:
        print("Canceled password generation.")
        return

    upper, lower, digits, special = char_types
    password = generate_password(length, upper, lower, digits, special)
    strength, feedback = preview_and_analyze(password)
    prompt_save_password(password, strength, feedback)
