"""Master password authentication module.

Handles password hashing, verification, and credential management.
Uses PBKDF2-SHA256 with configurable iterations per OWASP guidelines.
"""

import getpass
import hashlib
import os
import time
from typing import Optional, Tuple

from core.config import (
    MASTER_FILE,
    MIN_MASTER_PASSWORD_LENGTH,
    MAX_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION_SECONDS,
    PBKDF2_ITERATIONS,
)
from core.storage import load_binary, save_binary, file_exists


def hash_password(password: str, salt: bytes) -> bytes:
    """Hash a password using PBKDF2-SHA256.

    Single source of truth for password hashing across the application.

    Args:
        password: Password to hash
        salt: Random salt bytes

    Returns:
        32-byte hash digest
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        PBKDF2_ITERATIONS
    )


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt.

    Returns:
        16-byte random salt
    """
    return os.urandom(16)


def save_master_hash(password: str) -> None:
    """Save master password hash with salt.

    Args:
        password: Master password to hash and store
    """
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    save_binary(MASTER_FILE, salt + password_hash)


def load_master_hash() -> Optional[Tuple[bytes, bytes]]:
    """Load stored master password salt and hash.

    Returns:
        Tuple of (salt, hash), or None if no master password set
    """
    data = load_binary(MASTER_FILE)
    if data is None:
        return None
    return data[:16], data[16:]


def verify_password_hash(password: str, salt: bytes, stored_hash: bytes) -> bool:
    """Verify a password against stored hash.

    Args:
        password: Password to verify
        salt: Salt used for hashing
        stored_hash: Previously stored hash to compare

    Returns:
        True if password matches, False otherwise
    """
    computed_hash = hash_password(password, salt)
    return computed_hash == stored_hash


def is_master_password_set() -> bool:
    """Check if a master password has been configured.

    Returns:
        True if master password exists
    """
    return file_exists(MASTER_FILE)


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate master password meets minimum requirements.

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        return False, f"Password too short. Use at least {MIN_MASTER_PASSWORD_LENGTH} characters."
    return True, ""


def prompt_new_password(prompt_text: str = "Enter new master password: ") -> str:
    """Prompt user for a new password with confirmation.

    Args:
        prompt_text: Custom prompt message

    Returns:
        Validated password string

    Note:
        Loops until valid password with matching confirmation is entered.
    """
    print(f"\n(Minimum {MIN_MASTER_PASSWORD_LENGTH} characters required)")

    while True:
        pw1 = getpass.getpass(prompt_text)
        pw2 = getpass.getpass("Confirm password: ")

        if pw1 != pw2:
            print("Passwords do not match. Try again.")
            continue

        is_valid, error = validate_password_strength(pw1)
        if not is_valid:
            print(error)
            continue

        return pw1


def prompt_password(prompt_text: str = "Enter master password: ") -> str:
    """Prompt user for password input.

    Args:
        prompt_text: Custom prompt message

    Returns:
        Password string (unvalidated)
    """
    return getpass.getpass(prompt_text)


def authenticate_with_lockout(
    on_success: callable = None,
    on_failure: callable = None,
    on_lockout: callable = None
) -> Tuple[bool, Optional[str]]:
    """Authenticate user with attempt limiting and lockout.

    Args:
        on_success: Callback for successful login (receives password)
        on_failure: Callback for failed attempt
        on_lockout: Callback for lockout trigger

    Returns:
        Tuple of (success, password) - password is None on failure
    """
    master_data = load_master_hash()
    if master_data is None:
        return False, None

    salt, stored_hash = master_data

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        password = prompt_password()

        if verify_password_hash(password, salt, stored_hash):
            if on_success:
                on_success()
            return True, password

        remaining = MAX_LOGIN_ATTEMPTS - attempt
        print(f"Incorrect password. {remaining} attempt(s) remaining.")
        if on_failure:
            on_failure()

    if on_lockout:
        on_lockout()

    print(f"Too many failed attempts. Locked out for {LOCKOUT_DURATION_SECONDS} seconds...")
    time.sleep(LOCKOUT_DURATION_SECONDS)
    return False, None
