"""Password generation CLI flows.

Handles password generation, preview, and optional saving.
Implements secure password display to prevent history leakage.
"""

import secrets
import string
import sys

from core import DEFAULT_PASSWORD_LENGTH
from password_checker import check_password_strength
from vault import save_password

from cli.prompts import prompt_for_password_length, prompt_for_character_types


def _try_copy_to_clipboard(text: str) -> bool:
    """Attempt to copy text to clipboard.

    Tries multiple clipboard methods for cross-platform support.

    Args:
        text: Text to copy to clipboard

    Returns:
        True if successfully copied, False otherwise
    """
    # Try pyperclip if available
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except ImportError:
        pass

    # Try Windows clipboard via ctypes
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            user32 = ctypes.windll.user32

            user32.OpenClipboard(0)
            user32.EmptyClipboard()

            # Allocate global memory
            text_bytes = text.encode('utf-8') + b'\x00'
            h_mem = kernel32.GlobalAlloc(0x0042, len(text_bytes))
            ptr = kernel32.GlobalLock(h_mem)
            ctypes.memmove(ptr, text_bytes, len(text_bytes))
            kernel32.GlobalUnlock(h_mem)

            user32.SetClipboardData(1, h_mem)  # CF_TEXT = 1
            user32.CloseClipboard()
            return True
        except Exception:
            pass

    # Try pbcopy on macOS
    if sys.platform == "darwin":
        try:
            import subprocess
            process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            process.communicate(text.encode('utf-8'))
            return process.returncode == 0
        except Exception:
            pass

    # Try xclip on Linux
    if sys.platform.startswith("linux"):
        try:
            import subprocess
            process = subprocess.Popen(
                ['xclip', '-selection', 'clipboard'],
                stdin=subprocess.PIPE
            )
            process.communicate(text.encode('utf-8'))
            return process.returncode == 0
        except Exception:
            pass

    return False


def _mask_password(password: str, show_chars: int = 4) -> str:
    """Create a masked version of password showing only first/last chars.

    Args:
        password: Password to mask
        show_chars: Number of characters to show at start and end

    Returns:
        Masked password string like "Ab12****xy9!"
    """
    if len(password) <= show_chars * 2:
        return "*" * len(password)

    return password[:show_chars] + "*" * (len(password) - show_chars * 2) + password[-show_chars:]


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


def preview_and_analyze(password: str, secure_display: bool = True) -> tuple[str, list[str]]:
    """Display password securely and analyze its strength.

    By default, copies password to clipboard instead of displaying in terminal
    to prevent exposure in shell history. Falls back to masked display if
    clipboard is unavailable.

    Args:
        password: Password to analyze
        secure_display: If True, use clipboard/masked display (default: True)

    Returns:
        Tuple of (strength, feedback_list)
    """
    if secure_display:
        # Try clipboard first (most secure - nothing in terminal history)
        if _try_copy_to_clipboard(password):
            print("\n[PASSWORD COPIED TO CLIPBOARD]")
            print(f"Preview (masked): {_mask_password(password)}")
            print("(Password has been copied to your clipboard - paste where needed)")
        else:
            # Clipboard unavailable - show masked with reveal option
            print(f"\nGenerated Password (masked): {_mask_password(password)}")
            reveal = input("Show full password? (y/n - WARNING: visible in terminal history): ").strip().lower()
            if reveal == 'y':
                print(f"Full Password: {password}")
                print("WARNING: This password is now in your terminal history!")
    else:
        # Legacy insecure display (not recommended)
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
