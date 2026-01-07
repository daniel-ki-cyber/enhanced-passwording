"""Centralized file I/O operations.

Provides consistent JSON and binary file handling with proper error management.
Implements secure file permissions for sensitive data on Unix systems.
"""

import json
import os
import stat
import sys
from typing import Any, Optional

from core.config import LOG_DIR, TICKET_DIR, REPORT_DIR, VAULT_FILE, MASTER_FILE, SALT_FILE


# Files that contain sensitive data and need restrictive permissions
SENSITIVE_FILES = {VAULT_FILE, MASTER_FILE, SALT_FILE}

# Secure file permission: owner read/write only (0600 in octal)
SECURE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600


class StorageError(Exception):
    """Base exception for storage operations."""
    pass


class FileNotFoundError(StorageError):
    """File does not exist."""
    pass


class FileCorruptedError(StorageError):
    """File exists but contains invalid data."""
    pass


def _is_sensitive_file(filepath: str) -> bool:
    """Check if a file path is a sensitive file requiring secure permissions.

    Args:
        filepath: Path to check

    Returns:
        True if file should have restrictive permissions
    """
    basename = os.path.basename(filepath)
    return basename in SENSITIVE_FILES or filepath in SENSITIVE_FILES


def _set_secure_permissions(filepath: str) -> None:
    """Set restrictive file permissions on sensitive files.

    On Unix systems: Sets file to mode 0600 (owner read/write only)
    On Windows: No-op (Windows uses ACLs, not Unix permissions)

    Args:
        filepath: Path to the file to secure
    """
    # Skip on Windows - permissions work differently
    if sys.platform == "win32":
        return

    try:
        os.chmod(filepath, SECURE_FILE_MODE)
    except OSError:
        # Best effort - don't fail if we can't set permissions
        pass


def ensure_directories() -> None:
    """Create required directories if they don't exist.

    On Unix systems, directories are created with mode 0700 (owner only).
    """
    for directory in [LOG_DIR, TICKET_DIR, REPORT_DIR]:
        if sys.platform != "win32":
            os.makedirs(directory, mode=0o700, exist_ok=True)
        else:
            os.makedirs(directory, exist_ok=True)


def load_json(filepath: str) -> Optional[dict]:
    """Load JSON data from file.

    Args:
        filepath: Path to JSON file

    Returns:
        Parsed JSON data as dict, or None if file doesn't exist

    Raises:
        FileCorruptedError: If file exists but contains invalid JSON
    """
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise FileCorruptedError(f"Invalid JSON in {filepath}: {e}")
    except IOError as e:
        raise StorageError(f"Failed to read {filepath}: {e}")


def save_json(filepath: str, data: dict, indent: int = 2) -> None:
    """Save data to JSON file with secure permissions for sensitive files.

    Args:
        filepath: Path to JSON file
        data: Dictionary to save
        indent: JSON indentation level

    Raises:
        StorageError: If write operation fails
    """
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)

        # Apply secure permissions to sensitive files
        if _is_sensitive_file(filepath):
            _set_secure_permissions(filepath)
    except IOError as e:
        raise StorageError(f"Failed to write {filepath}: {e}")


def load_binary(filepath: str) -> Optional[bytes]:
    """Load binary data from file.

    Args:
        filepath: Path to binary file

    Returns:
        Binary data, or None if file doesn't exist
    """
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath, "rb") as f:
            return f.read()
    except IOError as e:
        raise StorageError(f"Failed to read {filepath}: {e}")


def save_binary(filepath: str, data: bytes) -> None:
    """Save binary data to file with secure permissions for sensitive files.

    Args:
        filepath: Path to binary file
        data: Binary data to save
    """
    try:
        with open(filepath, "wb") as f:
            f.write(data)

        # Apply secure permissions to sensitive files
        if _is_sensitive_file(filepath):
            _set_secure_permissions(filepath)
    except IOError as e:
        raise StorageError(f"Failed to write {filepath}: {e}")


def append_line(filepath: str, line: str) -> None:
    """Append a line to a text file.

    Args:
        filepath: Path to text file
        line: Line to append (newline added automatically)
    """
    ensure_directories()
    try:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except IOError as e:
        raise StorageError(f"Failed to append to {filepath}: {e}")


def file_exists(filepath: str) -> bool:
    """Check if file exists."""
    return os.path.exists(filepath)


def delete_file(filepath: str) -> bool:
    """Delete a file if it exists.

    Returns:
        True if file was deleted, False if it didn't exist
    """
    if os.path.exists(filepath):
        os.remove(filepath)
        return True
    return False


def list_json_files(directory: str) -> list[str]:
    """List all JSON files in a directory.

    Returns:
        List of full file paths
    """
    if not os.path.exists(directory):
        return []

    return [
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.endswith(".json")
    ]
