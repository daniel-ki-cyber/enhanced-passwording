"""Secure memory handling for sensitive data.

Provides utilities to minimize sensitive data exposure in memory.
Python strings are immutable and garbage-collected, making true secure
erasure challenging. This module provides best-effort protections:

1. SecureBytes: Mutable bytearray wrapper with explicit zeroing
2. secure_zero: Overwrites bytearray/memoryview contents
3. Context managers for automatic cleanup

SECURITY NOTES:
- Python strings CANNOT be securely erased (immutable, copied by GC)
- Convert sensitive strings to SecureBytes as early as possible
- Use SecureBytes for passwords, keys, and other secrets
- Call clear() explicitly or use context managers
- This is defense-in-depth, not a guarantee against memory forensics
"""

import ctypes
import gc
from contextlib import contextmanager
from typing import Optional, Generator


def secure_zero(data: bytearray | memoryview) -> None:
    """Securely overwrite a bytearray or memoryview with zeros.

    Uses multiple overwrites to help defeat memory analysis:
    1. Random pattern (optional, skipped for performance)
    2. All zeros

    Args:
        data: Mutable bytes object to zero out

    Raises:
        TypeError: If data is not a mutable bytes type
    """
    if isinstance(data, memoryview):
        if data.readonly:
            raise TypeError("Cannot zero readonly memoryview")
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    else:
        raise TypeError(f"Cannot securely zero type: {type(data)}")


def force_gc() -> None:
    """Force garbage collection to clean up dereferenced sensitive data.

    Calls gc.collect() multiple times to help ensure objects are freed.
    This is not a guarantee but helps reduce exposure window.
    """
    for _ in range(3):
        gc.collect()


class SecureBytes:
    """A secure wrapper around bytearray that can be explicitly zeroed.

    Use this for sensitive data like passwords and encryption keys.
    The data is stored in a bytearray which can be overwritten with zeros.

    Usage:
        # Context manager (recommended - auto-clears on exit)
        with SecureBytes(password.encode()) as secure_pwd:
            process(secure_pwd.get())

        # Manual management
        secure_pwd = SecureBytes(password.encode())
        try:
            process(secure_pwd.get())
        finally:
            secure_pwd.clear()

    Attributes:
        _data: Internal bytearray holding the sensitive data
        _cleared: Flag indicating if data has been cleared
    """

    __slots__ = ('_data', '_cleared')

    def __init__(self, data: bytes | bytearray | None = None):
        """Initialize with sensitive data.

        Args:
            data: Initial data (will be copied into internal bytearray)
        """
        if data is None:
            self._data = bytearray()
        elif isinstance(data, bytearray):
            self._data = data
        else:
            self._data = bytearray(data)
        self._cleared = False

    def get(self) -> bytes:
        """Get the data as bytes (creates an immutable copy).

        WARNING: The returned bytes object cannot be securely erased.
        Minimize the scope where this copy exists.

        Returns:
            Copy of the data as bytes

        Raises:
            RuntimeError: If data has already been cleared
        """
        if self._cleared:
            raise RuntimeError("Secure data has already been cleared")
        return bytes(self._data)

    def get_bytearray(self) -> bytearray:
        """Get direct reference to internal bytearray.

        WARNING: Do not hold references to this bytearray.
        It will be zeroed when clear() is called.

        Returns:
            Reference to internal bytearray

        Raises:
            RuntimeError: If data has already been cleared
        """
        if self._cleared:
            raise RuntimeError("Secure data has already been cleared")
        return self._data

    def clear(self) -> None:
        """Securely zero and clear the internal data.

        After calling this, the data is gone and cannot be recovered.
        This method is idempotent (safe to call multiple times).
        """
        if not self._cleared:
            secure_zero(self._data)
            self._data = bytearray()  # Release reference
            self._cleared = True
            force_gc()

    @property
    def is_cleared(self) -> bool:
        """Check if data has been cleared."""
        return self._cleared

    def __len__(self) -> int:
        """Return length of data."""
        if self._cleared:
            return 0
        return len(self._data)

    def __enter__(self) -> 'SecureBytes':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - ensures data is cleared."""
        self.clear()

    def __del__(self) -> None:
        """Destructor - attempts to clear data if not already done."""
        if hasattr(self, '_cleared') and not self._cleared:
            self.clear()

    def __repr__(self) -> str:
        """Safe repr that doesn't expose data."""
        if self._cleared:
            return "SecureBytes(<cleared>)"
        return f"SecureBytes(<{len(self._data)} bytes>)"

    def __str__(self) -> str:
        """Safe str that doesn't expose data."""
        return repr(self)


class SecureString:
    """A secure wrapper for string data that can be cleared.

    Internally converts the string to SecureBytes for storage.
    Use this when you need to work with passwords as strings but
    want the ability to clear them from memory.

    Usage:
        with SecureString("my_password") as secure_pwd:
            # Work with secure_pwd.get() as needed
            result = verify(secure_pwd.get())
        # Data is automatically cleared here
    """

    __slots__ = ('_secure_bytes', '_encoding')

    def __init__(self, data: str | None = None, encoding: str = 'utf-8'):
        """Initialize with sensitive string data.

        Args:
            data: String to store securely
            encoding: Character encoding (default: utf-8)
        """
        self._encoding = encoding
        if data is None:
            self._secure_bytes = SecureBytes()
        else:
            self._secure_bytes = SecureBytes(data.encode(encoding))

    def get(self) -> str:
        """Get the string data.

        WARNING: The returned string cannot be securely erased.
        Minimize the scope where this copy exists.

        Returns:
            Copy of the data as string

        Raises:
            RuntimeError: If data has already been cleared
        """
        return self._secure_bytes.get().decode(self._encoding)

    def clear(self) -> None:
        """Securely clear the string data."""
        self._secure_bytes.clear()

    @property
    def is_cleared(self) -> bool:
        """Check if data has been cleared."""
        return self._secure_bytes.is_cleared

    def __len__(self) -> int:
        """Return length of string (in characters)."""
        if self._secure_bytes.is_cleared:
            return 0
        return len(self._secure_bytes.get().decode(self._encoding))

    def __enter__(self) -> 'SecureString':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - ensures data is cleared."""
        self.clear()

    def __del__(self) -> None:
        """Destructor - attempts to clear data."""
        if hasattr(self, '_secure_bytes'):
            self._secure_bytes.clear()

    def __repr__(self) -> str:
        """Safe repr that doesn't expose data."""
        if self._secure_bytes.is_cleared:
            return "SecureString(<cleared>)"
        return f"SecureString(<{len(self)} chars>)"


@contextmanager
def secure_scope(*secure_objects: SecureBytes | SecureString) -> Generator[None, None, None]:
    """Context manager to ensure multiple secure objects are cleared.

    Usage:
        pwd = SecureBytes(password_bytes)
        key = SecureBytes(key_bytes)

        with secure_scope(pwd, key):
            # Use pwd and key
            process(pwd.get(), key.get())
        # Both pwd and key are now cleared

    Args:
        *secure_objects: SecureBytes or SecureString objects to manage

    Yields:
        None
    """
    try:
        yield
    finally:
        for obj in secure_objects:
            obj.clear()


def try_clear_string_from_memory(string_ref: str) -> None:
    """Best-effort attempt to clear a string from memory.

    WARNING: This is NOT reliable due to Python's string interning
    and garbage collection. It's provided as defense-in-depth only.

    Uses ctypes to attempt to overwrite the string's internal buffer,
    but this may not work and could cause undefined behavior.

    Args:
        string_ref: String to attempt to clear
    """
    try:
        # This is a best-effort approach that may not work
        # Python strings are immutable and may be interned
        str_len = len(string_ref)
        if str_len == 0:
            return

        # Attempt to find and zero the string's buffer
        # This is very hacky and may not work on all Python implementations
        offset = id(string_ref) + 48  # Approximate offset to string data
        ctypes.memset(offset, 0, str_len)
    except Exception:
        # Silently fail - this is best-effort only
        pass
    finally:
        # Force garbage collection
        force_gc()
