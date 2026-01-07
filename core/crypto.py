"""Cryptographic operations for password vault.

Handles encryption key derivation and Fernet cipher management.
Uses PBKDF2 with SHA-256 per OWASP 2023 recommendations.
"""

import base64
import os
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.config import PBKDF2_ITERATIONS, SALT_FILE
from core.storage import load_binary, save_binary


# Module-level cached Fernet instance
_cached_fernet: Optional[Fernet] = None


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from password using PBKDF2.

    Args:
        password: Master password
        salt: Random salt for key derivation

    Returns:
        Base64-encoded 32-byte key suitable for Fernet
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def get_or_create_salt() -> bytes:
    """Get existing salt or create a new one for key derivation.

    Returns:
        16-byte salt for PBKDF2
    """
    existing_salt = load_binary(SALT_FILE)
    if existing_salt is not None:
        return existing_salt

    salt = os.urandom(16)
    save_binary(SALT_FILE, salt)
    return salt


def create_new_salt() -> bytes:
    """Create and save a new salt, replacing any existing one.

    Returns:
        New 16-byte salt
    """
    salt = os.urandom(16)
    save_binary(SALT_FILE, salt)
    return salt


def get_fernet(password: str) -> Fernet:
    """Get Fernet instance using key derived from master password.

    Also caches the instance for subsequent operations.

    Args:
        password: Master password

    Returns:
        Configured Fernet cipher instance
    """
    global _cached_fernet
    salt = get_or_create_salt()
    key = derive_key(password, salt)
    _cached_fernet = Fernet(key)
    return _cached_fernet


def get_cached_fernet() -> Optional[Fernet]:
    """Get the cached Fernet instance (after successful login).

    Returns:
        Cached Fernet instance, or None if not authenticated
    """
    return _cached_fernet


def clear_cached_fernet() -> None:
    """Clear the cached Fernet instance on logout."""
    global _cached_fernet
    _cached_fernet = None


def encrypt(plaintext: str) -> str:
    """Encrypt a string using the cached Fernet instance.

    Args:
        plaintext: String to encrypt

    Returns:
        Base64-encoded encrypted string

    Raises:
        RuntimeError: If not authenticated (no cached Fernet)
    """
    fernet = get_cached_fernet()
    if fernet is None:
        raise RuntimeError("Not authenticated. Please log in first.")
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a string using the cached Fernet instance.

    Args:
        ciphertext: Base64-encoded encrypted string

    Returns:
        Decrypted plaintext string

    Raises:
        RuntimeError: If not authenticated (no cached Fernet)
    """
    fernet = get_cached_fernet()
    if fernet is None:
        raise RuntimeError("Not authenticated. Please log in first.")
    return fernet.decrypt(ciphertext.encode()).decode()
