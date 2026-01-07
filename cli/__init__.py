"""CLI package for Password Vault.

Provides modular CLI flows for password management operations.
"""

from cli.generator import generate_password, generate_password_flow
from cli.tester import test_password_flow
from cli.manager import view_passwords_flow

__all__ = [
    "generate_password",
    "generate_password_flow",
    "test_password_flow",
    "view_passwords_flow",
]
