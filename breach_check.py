"""Breach detection using HaveIBeenPwned API.

Uses k-Anonymity model to check passwords without exposing them.
Only the first 5 characters of the SHA-1 hash are sent to the API.
"""

import hashlib
import urllib.request
import urllib.error
from typing import Optional


HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
REQUEST_TIMEOUT = 5  # seconds


def get_password_hash(password: str) -> tuple[str, str]:
    """Get SHA-1 hash of password split into prefix and suffix.

    Returns:
        Tuple of (prefix, suffix) where prefix is first 5 chars
        and suffix is remaining 35 chars (uppercase).
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1_hash[:5], sha1_hash[5:]


def check_password_breach(password: str) -> Optional[int]:
    """Check if password has been exposed in known data breaches.

    Uses HaveIBeenPwned API with k-Anonymity (only sends hash prefix).

    Args:
        password: The password to check

    Returns:
        Number of times password was found in breaches, or None if API error.
        Returns 0 if password was not found in any breach.
    """
    prefix, suffix = get_password_hash(password)

    try:
        url = f"{HIBP_API_URL}{prefix}"
        request = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'PasswordVault-BreachCheck/1.0',
                'Add-Padding': 'true'  # Helps prevent timing attacks
            }
        )

        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            hash_list = response.read().decode('utf-8')

        # Parse response - format is "SUFFIX:COUNT\r\n"
        for line in hash_list.splitlines():
            if ':' not in line:
                continue
            hash_suffix, count = line.split(':')
            if hash_suffix.upper() == suffix:
                return int(count)

        return 0  # Not found in any breach

    except urllib.error.URLError as e:
        print(f"Warning: Could not check breach database: {e.reason}")
        return None
    except urllib.error.HTTPError as e:
        print(f"Warning: Breach check API error: {e.code}")
        return None
    except Exception as e:
        print(f"Warning: Unexpected error during breach check: {e}")
        return None


def format_breach_warning(breach_count: int) -> str:
    """Format a warning message based on breach count."""
    if breach_count == 0:
        return ""
    elif breach_count < 10:
        return f"This password appeared in {breach_count} data breach(es). Consider using a different password."
    elif breach_count < 100:
        return f"WARNING: This password was found {breach_count} times in data breaches!"
    elif breach_count < 1000:
        return f"DANGER: This password was exposed {breach_count} times in breaches. Do NOT use it!"
    else:
        return f"CRITICAL: This password was found {breach_count:,} times in breaches. It is extremely compromised!"


def check_and_warn(password: str) -> tuple[bool, str]:
    """Check password and return safety status with message.

    Returns:
        Tuple of (is_safe, message) where is_safe is False if breached.
    """
    breach_count = check_password_breach(password)

    if breach_count is None:
        return True, "Could not verify against breach database (offline check only)"

    if breach_count == 0:
        return True, "Password not found in known data breaches"

    warning = format_breach_warning(breach_count)
    return False, warning


# CLI usage
if __name__ == "__main__":
    import getpass
    print("=== Password Breach Checker ===")
    print("Check if your password has been exposed in data breaches.")
    print("(Uses HaveIBeenPwned API with k-Anonymity - your password is never sent)\n")

    pwd = getpass.getpass("Enter password to check: ")
    if pwd:
        is_safe, message = check_and_warn(pwd)
        print(f"\nResult: {message}")
        if is_safe:
            print("Status: SAFE")
        else:
            print("Status: COMPROMISED - Choose a different password!")
