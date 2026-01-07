"""Shared CLI prompt utilities.

Common input prompts and validation used across CLI flows.
"""

from typing import Optional

from core import MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH


def prompt_for_password_length() -> Optional[int]:
    """Prompt user for valid password length.

    Returns:
        Length as integer, or None to cancel
    """
    while True:
        val = input(
            f"Enter password length ({MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH}, or 'q' to cancel): "
        ).strip().lower()

        if val in ['q', 'exit']:
            return None

        try:
            length = int(val)
            if MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
                return length
            print(f"Please enter a number between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}.")
        except ValueError:
            print("Invalid input. Enter a number.")


def prompt_for_character_types() -> Optional[tuple[bool, bool, bool, bool]]:
    """Prompt user to choose character types for password generation.

    Returns:
        Tuple of (uppercase, lowercase, digits, special) as booleans,
        or None to cancel
    """
    def ask(part: str) -> Optional[bool]:
        while True:
            ans = input(f"Include {part}? (y/n or q to cancel): ").strip().lower()
            if ans in ['q', 'exit']:
                return None
            if ans in ['y', 'n']:
                return ans == 'y'
            print("Please enter 'y', 'n', or 'q' to cancel.")

    upper = ask("uppercase letters")
    if upper is None:
        return None

    lower = ask("lowercase letters")
    if lower is None:
        return None

    digits = ask("digits")
    if digits is None:
        return None

    special = ask("special characters")
    if special is None:
        return None

    if not any([upper, lower, digits, special]):
        print("At least one character type must be selected.\n")
        return prompt_for_character_types()

    return upper, lower, digits, special


def confirm_action(prompt: str, require_word: Optional[str] = None) -> bool:
    """Prompt for confirmation with optional keyword requirement.

    Args:
        prompt: Question to ask
        require_word: If set, user must type this word to confirm

    Returns:
        True if confirmed, False otherwise
    """
    if require_word:
        response = input(f"{prompt} Type {require_word} to confirm: ").strip()
        return response == require_word
    else:
        response = input(f"{prompt} (y/n): ").strip().lower()
        return response == 'y'


def double_confirm(action_desc: str) -> bool:
    """Require two confirmations for destructive actions.

    Args:
        action_desc: Description of the action

    Returns:
        True if both confirmations pass
    """
    confirm_1 = input(f"Are you sure you want to {action_desc}? (y/n): ").strip().lower()
    if confirm_1 != 'y':
        return False

    confirm_2 = input("Please confirm again. (y/n): ").strip().lower()
    return confirm_2 == 'y'
