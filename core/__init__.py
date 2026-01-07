"""Password Vault Core Package.

Provides modular components for secure password management:
- config: Centralized configuration constants
- storage: File I/O operations
- crypto: Encryption and key derivation
- auth: Master password authentication
- siem: Security event logging
- tickets: Incident ticket management
- vault_ops: Password CRUD operations
"""

# Configuration constants
from core.config import (
    VAULT_FILE,
    MASTER_FILE,
    SALT_FILE,
    SIEM_LOG_FILE,
    TICKET_DIR,
    REPORT_DIR,
    LOG_DIR,
    LOGIN_LOG_FILE,
    MIN_MASTER_PASSWORD_LENGTH,
    MAX_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION_SECONDS,
    PBKDF2_ITERATIONS,
    PASSWORD_AGE_WARNING_DAYS,
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    DEFAULT_PASSWORD_LENGTH,
)

# Crypto operations
from core.crypto import (
    derive_key,
    get_fernet,
    get_cached_fernet,
    clear_cached_fernet,
    encrypt,
    decrypt,
)

# Authentication
from core.auth import (
    hash_password,
    verify_password_hash,
    save_master_hash,
    load_master_hash,
    is_master_password_set,
    validate_password_strength,
    prompt_new_password,
    prompt_password,
    authenticate_with_lockout,
)

# SIEM logging
from core.siem import (
    log_login_attempt,
    log_siem_event,
    review_login_activity,
    get_siem_events,
)

# Ticket management
from core.tickets import (
    create_ticket,
    get_ticket,
    list_tickets,
    list_open_tickets,
    resolve_ticket,
    generate_tickets_from_logs,
    export_resolved_tickets_report,
    ticket_menu,
)

# Vault operations
from core.vault_ops import (
    save_password,
    get_password,
    load_all_passwords,
    update_password,
    delete_password,
    get_password_history,
    password_exists,
    list_password_names,
)

# Storage utilities
from core.storage import ensure_directories

__all__ = [
    # Config
    "VAULT_FILE",
    "MASTER_FILE",
    "SALT_FILE",
    "SIEM_LOG_FILE",
    "TICKET_DIR",
    "REPORT_DIR",
    "LOG_DIR",
    "LOGIN_LOG_FILE",
    "MIN_MASTER_PASSWORD_LENGTH",
    "MAX_LOGIN_ATTEMPTS",
    "LOCKOUT_DURATION_SECONDS",
    "PBKDF2_ITERATIONS",
    "PASSWORD_AGE_WARNING_DAYS",
    "MIN_PASSWORD_LENGTH",
    "MAX_PASSWORD_LENGTH",
    "DEFAULT_PASSWORD_LENGTH",
    # Crypto
    "derive_key",
    "get_fernet",
    "get_cached_fernet",
    "clear_cached_fernet",
    "encrypt",
    "decrypt",
    # Auth
    "hash_password",
    "verify_password_hash",
    "save_master_hash",
    "load_master_hash",
    "is_master_password_set",
    "validate_password_strength",
    "prompt_new_password",
    "prompt_password",
    "authenticate_with_lockout",
    # SIEM
    "log_login_attempt",
    "log_siem_event",
    "review_login_activity",
    "get_siem_events",
    # Tickets
    "create_ticket",
    "get_ticket",
    "list_tickets",
    "list_open_tickets",
    "resolve_ticket",
    "generate_tickets_from_logs",
    "export_resolved_tickets_report",
    "ticket_menu",
    # Vault
    "save_password",
    "get_password",
    "load_all_passwords",
    "update_password",
    "delete_password",
    "get_password_history",
    "password_exists",
    "list_password_names",
    # Storage
    "ensure_directories",
]
