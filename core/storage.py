"""Centralized file I/O operations.

Provides consistent JSON and binary file handling with proper error management.
"""

import json
import os
from typing import Any, Optional

from core.config import LOG_DIR, TICKET_DIR, REPORT_DIR


class StorageError(Exception):
    """Base exception for storage operations."""
    pass


class FileNotFoundError(StorageError):
    """File does not exist."""
    pass


class FileCorruptedError(StorageError):
    """File exists but contains invalid data."""
    pass


def ensure_directories() -> None:
    """Create required directories if they don't exist."""
    for directory in [LOG_DIR, TICKET_DIR, REPORT_DIR]:
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
    """Save data to JSON file.

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
    """Save binary data to file.

    Args:
        filepath: Path to binary file
        data: Binary data to save
    """
    try:
        with open(filepath, "wb") as f:
            f.write(data)
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
