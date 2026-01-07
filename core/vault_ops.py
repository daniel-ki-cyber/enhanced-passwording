"""Password vault CRUD operations.

Handles encrypted password storage, retrieval, updates, and deletion.
All operations require prior authentication via the auth module.
"""

from datetime import datetime
from typing import Optional

from core.config import VAULT_FILE, PASSWORD_AGE_WARNING_DAYS
from core.storage import load_json, save_json, file_exists
from core.crypto import encrypt, decrypt, get_cached_fernet


def _require_auth() -> bool:
    """Check if user is authenticated.

    Returns:
        True if authenticated

    Raises:
        RuntimeError: If not authenticated
    """
    if get_cached_fernet() is None:
        raise RuntimeError("Not authenticated. Please log in first.")
    return True


def _load_vault() -> dict:
    """Load vault data from file.

    Returns:
        Vault dictionary, empty if file doesn't exist
    """
    return load_json(VAULT_FILE) or {}


def _save_vault(data: dict) -> None:
    """Save vault data to file.

    Args:
        data: Vault dictionary to save
    """
    save_json(VAULT_FILE, data)


def save_password(name: str, password: str) -> bool:
    """Encrypt and store a new password entry.

    Args:
        name: Label/identifier for the password
        password: Plain text password to store

    Returns:
        True on success

    Raises:
        RuntimeError: If not authenticated
    """
    _require_auth()

    encrypted = encrypt(password)
    entry = {
        "password": encrypted,
        "created": datetime.now().isoformat(),
        "history": []
    }

    data = _load_vault()
    data[name] = entry
    _save_vault(data)

    return True


def get_password(name: str) -> Optional[dict]:
    """Retrieve a single password entry by name.

    Args:
        name: Entry identifier

    Returns:
        Dictionary with decrypted password and metadata, or None if not found

    Raises:
        RuntimeError: If not authenticated
    """
    _require_auth()

    data = _load_vault()
    if name not in data:
        return None

    entry = data[name]
    created_str = entry.get("created", "Unknown")

    # Check password age
    age_warning = None
    if created_str != "Unknown":
        try:
            created_date = datetime.fromisoformat(created_str)
            age_days = (datetime.now() - created_date).days
            if age_days > PASSWORD_AGE_WARNING_DAYS:
                age_warning = f"Password is {age_days} days old - consider updating"
        except ValueError:
            pass

    return {
        "password": decrypt(entry["password"]),
        "created": created_str,
        "age_warning": age_warning
    }


def load_all_passwords() -> dict[str, dict]:
    """Decrypt and return all password entries.

    Returns:
        Dictionary mapping names to decrypted entries with metadata

    Raises:
        RuntimeError: If not authenticated
    """
    _require_auth()

    if not file_exists(VAULT_FILE):
        return {}

    raw_data = _load_vault()
    output = {}

    for name, entry in raw_data.items():
        created_str = entry.get("created", "Unknown")

        # Check password age
        age_warning = None
        if created_str != "Unknown":
            try:
                created_date = datetime.fromisoformat(created_str)
                age_days = (datetime.now() - created_date).days
                if age_days > PASSWORD_AGE_WARNING_DAYS:
                    age_warning = f"Password is {age_days} days old - consider updating"
            except ValueError:
                pass

        output[name] = {
            "password": decrypt(entry["password"]),
            "created": created_str,
            "age_warning": age_warning
        }

    return output


def update_password(name: str, new_password: str) -> bool:
    """Update a password and archive the old one to history.

    Args:
        name: Entry identifier
        new_password: New plain text password

    Returns:
        True on success, False if entry not found

    Raises:
        RuntimeError: If not authenticated
    """
    _require_auth()

    if not file_exists(VAULT_FILE):
        return False

    data = _load_vault()
    if name not in data:
        return False

    entry = data[name]

    # Archive old password to history
    old_encrypted = entry.get("password")
    if "history" not in entry:
        entry["history"] = []

    if old_encrypted:
        entry["history"].append({
            "password": old_encrypted,
            "timestamp": entry.get("created", datetime.now().isoformat())
        })

    # Update current password
    entry["password"] = encrypt(new_password)
    entry["created"] = datetime.now().isoformat()

    _save_vault(data)
    return True


def delete_password(name: str) -> bool:
    """Delete a password entry.

    Args:
        name: Entry identifier to delete

    Returns:
        True on success, False if entry not found
    """
    if not file_exists(VAULT_FILE):
        return False

    data = _load_vault()
    if name not in data:
        return False

    del data[name]
    _save_vault(data)
    return True


def get_password_history(name: str) -> list[str]:
    """Get decrypted password history for an entry.

    Args:
        name: Entry identifier

    Returns:
        List of previously used passwords (decrypted)

    Raises:
        RuntimeError: If not authenticated
    """
    _require_auth()

    if not file_exists(VAULT_FILE):
        return []

    data = _load_vault()
    if name not in data:
        return []

    history = data[name].get("history", [])
    return [decrypt(h["password"]) for h in history]


def password_exists(name: str) -> bool:
    """Check if a password entry exists.

    Args:
        name: Entry identifier

    Returns:
        True if entry exists
    """
    data = _load_vault()
    return name in data


def list_password_names() -> list[str]:
    """Get list of all password entry names.

    Returns:
        List of entry names/identifiers
    """
    data = _load_vault()
    return list(data.keys())
