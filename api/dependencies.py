"""FastAPI dependencies for authentication and authorization.

Provides reusable dependency injection for protected endpoints.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from core import get_fernet, log_siem_event
from core.auth import load_master_hash, verify_password_hash


security = HTTPBasic()


def verify_master_password(password: str) -> bool:
    """Verify master password against stored hash.

    Args:
        password: Password to verify

    Returns:
        True if password is correct
    """
    master_data = load_master_hash()
    if master_data is None:
        return False

    salt, stored_hash = master_data
    return verify_password_hash(password, salt, stored_hash)


def get_current_user(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """Dependency to verify authentication and initialize encryption.

    Args:
        credentials: HTTP Basic credentials from request

    Returns:
        "authenticated" on success

    Raises:
        HTTPException: 401 if authentication fails
    """
    if not verify_master_password(credentials.password):
        log_siem_event("api_login_attempt", "FAILURE")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Initialize encryption key
    get_fernet(credentials.password)
    log_siem_event("api_login_attempt", "SUCCESS")
    return "authenticated"
