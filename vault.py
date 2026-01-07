"""Password Vault - Backward Compatible Facade.

This module provides backward compatibility while the codebase migrates
to the new modular structure in the core/ package.

For new code, import directly from core:
    from core import save_password, load_all_passwords
    from core.auth import verify_password_hash
    from core.crypto import get_fernet
"""

import os
from typing import Optional

# Re-export configuration constants
from core.config import (
    VAULT_FILE,
    MASTER_FILE,
    SALT_FILE,
    SIEM_LOG_FILE,
    TICKET_DIR,
    REPORT_DIR,
    LOG_DIR,
    MIN_MASTER_PASSWORD_LENGTH,
    MAX_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION_SECONDS,
    PBKDF2_ITERATIONS,
    PASSWORD_AGE_WARNING_DAYS,
)

# Re-export crypto functions
from core.crypto import (
    get_fernet,
    get_cached_fernet,
    clear_cached_fernet,
    get_or_create_salt,
    create_new_salt,
)

# Re-export auth functions
from core.auth import (
    hash_password,
    verify_password_hash,
    save_master_hash,
    load_master_hash,
    is_master_password_set,
    prompt_new_password,
    prompt_password,
)

# Re-export SIEM functions
from core.siem import (
    log_login_attempt as log_attempt,
    log_siem_event,
    review_login_activity,
)

# Re-export ticket functions
from core.tickets import (
    generate_tickets_from_logs,
    list_open_tickets,
    resolve_ticket,
    ticket_menu,
    export_resolved_tickets_report,
)

# Re-export vault operations
from core.vault_ops import (
    save_password,
    load_all_passwords,
    update_password,
    delete_password,
    get_password_history,
)

from core.storage import ensure_directories


def set_master_password() -> str:
    """Create and save a new master password.

    Returns:
        The password so it can be used to initialize encryption.
    """
    print("\nSet up a new master password.")
    password = prompt_new_password("Enter new master password: ")
    save_master_hash(password)

    # Initialize encryption with the new password
    get_fernet(password)

    print("Master password set successfully.")
    return password


def change_master_password() -> bool:
    """Change the master password and re-encrypt all vault entries.

    Returns:
        True on success, False on failure
    """
    if not is_master_password_set():
        print("No master password set. Use set_master_password() first.")
        return False

    # Verify current password
    print("\nTo change your master password, first verify your current password.")
    current_pw = prompt_password("Enter current master password: ")

    master_data = load_master_hash()
    if master_data is None:
        return False

    salt, stored_hash = master_data
    if not verify_password_hash(current_pw, salt, stored_hash):
        print("Current password incorrect.")
        log_siem_event("password_change_attempt", "FAILURE")
        return False

    # Get new password
    print(f"\nEnter new master password (minimum {MIN_MASTER_PASSWORD_LENGTH} characters):")

    while True:
        new_pw = prompt_new_password("New master password: ")
        if new_pw == current_pw:
            print("New password must be different from current password.")
            continue
        break

    # Re-encrypt vault with new password
    if os.path.exists(VAULT_FILE):
        import json
        from core.crypto import encrypt, decrypt

        # Load and decrypt all passwords with old key
        old_fernet = get_fernet(current_pw)

        with open(VAULT_FILE, "r") as f:
            vault_data = json.load(f)

        # Decrypt all passwords
        for name, entry in vault_data.items():
            entry["password"] = old_fernet.decrypt(entry["password"].encode()).decode()
            for hist in entry.get("history", []):
                hist["password"] = old_fernet.decrypt(hist["password"].encode()).decode()

        # Create new salt for key derivation
        create_new_salt()

        # Get new fernet with new password
        new_fernet = get_fernet(new_pw)

        # Re-encrypt all passwords
        for name, entry in vault_data.items():
            entry["password"] = new_fernet.encrypt(entry["password"].encode()).decode()
            for hist in entry.get("history", []):
                hist["password"] = new_fernet.encrypt(hist["password"].encode()).decode()

        # Save re-encrypted vault
        with open(VAULT_FILE, "w") as f:
            json.dump(vault_data, f, indent=2)
    else:
        # No vault yet, just update the salt
        create_new_salt()
        get_fernet(new_pw)

    # Save new master password hash
    save_master_hash(new_pw)

    log_siem_event("password_change", "SUCCESS")
    print("Master password changed successfully.")
    return True


def verify_master_password() -> bool:
    """Prompt for master password and verify against stored hash.

    Returns:
        True if password is correct, False otherwise.
    """
    if not is_master_password_set():
        print("No master password set.")
        set_master_password()
        return True

    master_data = load_master_hash()
    if master_data is None:
        return False

    salt, stored_hash = master_data

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        pw = prompt_password("Enter master password: ")

        if verify_password_hash(pw, salt, stored_hash):
            log_siem_event("login_attempt", "SUCCESS")
            print("Access granted.")
            log_attempt(True)
            # Initialize encryption with verified password
            get_fernet(pw)
            return True

        remaining = MAX_LOGIN_ATTEMPTS - attempt
        print(f"Incorrect password. {remaining} attempt(s) remaining.")
        log_siem_event("login_attempt", "FAILURE")
        log_attempt(False)

    log_siem_event("login_attempt", "LOCKOUT")
    print(f"Too many failed attempts. Locked out for {LOCKOUT_DURATION_SECONDS} seconds...")
    log_attempt(False)

    import time
    time.sleep(LOCKOUT_DURATION_SECONDS)
    return False


# Backward compatibility aliases
_ensure_directories = ensure_directories
_derive_key_from_password = lambda pw, salt: __import__('core.crypto', fromlist=['derive_key']).derive_key(pw, salt)
_get_or_create_salt = get_or_create_salt
