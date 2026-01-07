"""Centralized configuration constants.

All configurable values in one place for easy maintenance.
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
