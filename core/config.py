"""Centralized configuration constants.

All configurable values in one place for easy maintenance.
Security-sensitive settings can be overridden via environment variables.
"""

import os

# Base directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

# File paths
VAULT_FILE = os.environ.get("VAULT_FILE", "vault.json")
MASTER_FILE = os.environ.get("MASTER_FILE", "master.hash")
SALT_FILE = os.environ.get("SALT_FILE", "vault.salt")
LOGIN_LOG_FILE = os.environ.get("LOGIN_LOG_FILE", "login.log")

# Directories
LOG_DIR = os.environ.get("LOG_DIR", "logs")
TICKET_DIR = os.environ.get("TICKET_DIR", "tickets")
REPORT_DIR = os.environ.get("REPORT_DIR", "reports")
SIEM_LOG_FILE = os.path.join(LOG_DIR, "siem_events.jsonl")

# Security constants - OWASP 2023 recommendations
MIN_MASTER_PASSWORD_LENGTH = 12
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 60
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 for SHA-256
PASSWORD_AGE_WARNING_DAYS = 90

# Password generation
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
DEFAULT_PASSWORD_LENGTH = 16

# Trusted proxy configuration
# SECURITY: Only trust X-Forwarded-For headers from these IP addresses
# Set TRUSTED_PROXIES environment variable to comma-separated list of IPs
# Example: TRUSTED_PROXIES=10.0.0.1,10.0.0.2,172.17.0.1
_trusted_proxies_env = os.environ.get("TRUSTED_PROXIES", "")
TRUSTED_PROXIES: set[str] = set(
    ip.strip() for ip in _trusted_proxies_env.split(",") if ip.strip()
)

# HTTPS enforcement
# Set REQUIRE_HTTPS=true in production to reject non-HTTPS requests
REQUIRE_HTTPS = os.environ.get("REQUIRE_HTTPS", "false").lower() == "true"

# Label validation
# Maximum length and allowed characters for password entry labels
MAX_LABEL_LENGTH = 100
# Alphanumeric, spaces, hyphens, underscores, dots, and common symbols
LABEL_ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@# ")

# JWT Configuration
# SECURITY: In production, set JWT_SECRET_KEY via environment variable
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", None)
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
JWT_REFRESH_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours
