"""FastAPI dependencies for authentication and authorization.

Provides reusable dependency injection for protected endpoints.
Implements brute force protection with per-IP attempt tracking and lockout.
Includes trusted proxy validation to prevent X-Forwarded-For spoofing.
Supports both JWT Bearer tokens (preferred) and HTTP Basic Auth (legacy).
"""

import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Optional, Tuple

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials

from core import get_fernet, log_siem_event
from core.auth import load_master_hash, verify_password_hash
from core.config import MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION_SECONDS, TRUSTED_PROXIES


# Support both Bearer (JWT) and Basic auth
security_basic = HTTPBasic(auto_error=False)
security_bearer = HTTPBearer(auto_error=False)

# Thread-safe tracking of failed attempts per IP
# Structure: {ip: (failure_count, lockout_expiry_timestamp)}
_failed_attempts: Dict[str, Tuple[int, float]] = defaultdict(lambda: (0, 0.0))
_attempts_lock = Lock()


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request with trusted proxy validation.

    SECURITY: Only trusts X-Forwarded-For header if the direct connection
    comes from a configured trusted proxy. This prevents attackers from
    spoofing their IP address by setting the X-Forwarded-For header.

    Configure trusted proxies via TRUSTED_PROXIES environment variable.
    Example: TRUSTED_PROXIES=10.0.0.1,172.17.0.1

    Args:
        request: FastAPI request object

    Returns:
        Client IP address (from X-Forwarded-For if trusted proxy, else direct)
    """
    direct_ip = request.client.host if request.client else "unknown"

    # Only trust X-Forwarded-For if request comes from a trusted proxy
    if TRUSTED_PROXIES and direct_ip in TRUSTED_PROXIES:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP in the chain (original client)
            client_ip = forwarded.split(",")[0].strip()
            # Validate it looks like an IP (basic check)
            if client_ip and "." in client_ip or ":" in client_ip:
                return client_ip

    # No trusted proxy or not from trusted source - use direct connection IP
    return direct_ip


def _check_lockout(ip: str) -> Tuple[bool, int]:
    """Check if an IP is currently locked out.

    Returns:
        Tuple of (is_locked_out, seconds_remaining)
    """
    with _attempts_lock:
        failures, lockout_until = _failed_attempts[ip]

        if lockout_until > time.time():
            remaining = int(lockout_until - time.time())
            return True, remaining

        # Reset if lockout has expired
        if lockout_until > 0 and lockout_until <= time.time():
            _failed_attempts[ip] = (0, 0.0)

        return False, 0


def _record_failed_attempt(ip: str) -> Tuple[int, bool]:
    """Record a failed authentication attempt.

    Returns:
        Tuple of (remaining_attempts, triggered_lockout)
    """
    with _attempts_lock:
        failures, _ = _failed_attempts[ip]
        failures += 1

        if failures >= MAX_LOGIN_ATTEMPTS:
            # Trigger lockout
            lockout_until = time.time() + LOCKOUT_DURATION_SECONDS
            _failed_attempts[ip] = (failures, lockout_until)
            return 0, True
        else:
            _failed_attempts[ip] = (failures, 0.0)
            return MAX_LOGIN_ATTEMPTS - failures, False


def _clear_failed_attempts(ip: str) -> None:
    """Clear failed attempts after successful authentication."""
    with _attempts_lock:
        if ip in _failed_attempts:
            del _failed_attempts[ip]


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


def _authenticate_with_jwt(token: str, client_ip: str) -> str:
    """Authenticate using JWT Bearer token.

    Args:
        token: JWT access token
        client_ip: Client IP address for logging

    Returns:
        Master password from token (for vault decryption)

    Raises:
        HTTPException: If token is invalid or expired
    """
    # Import here to avoid circular imports
    from core.jwt_auth import (
        verify_access_token,
        TokenExpiredError,
        InvalidTokenError,
        MissingSecretKeyError,
    )

    try:
        master_password, payload = verify_access_token(token)
        # Initialize Fernet with the decrypted master password
        get_fernet(master_password)
        log_siem_event("jwt_access", "SUCCESS", source_ip=client_ip)
        return master_password
    except TokenExpiredError:
        log_siem_event("jwt_access", "EXPIRED", source_ip=client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired. Use /auth/refresh to get a new token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        log_siem_event("jwt_access", "INVALID", source_ip=client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except MissingSecretKeyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT authentication not configured"
        )


def _authenticate_with_basic(credentials: HTTPBasicCredentials, client_ip: str) -> str:
    """Authenticate using HTTP Basic Auth (legacy).

    Args:
        credentials: HTTP Basic credentials
        client_ip: Client IP address for logging/lockout

    Returns:
        "authenticated" on success

    Raises:
        HTTPException: If authentication fails or IP is locked out
    """
    # Check if IP is locked out
    is_locked, remaining_seconds = _check_lockout(client_ip)
    if is_locked:
        log_siem_event(
            "api_login_attempt",
            "LOCKOUT_ACTIVE",
            source_ip=client_ip,
            details={"remaining_seconds": remaining_seconds}
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {remaining_seconds} seconds.",
            headers={"Retry-After": str(remaining_seconds)},
        )

    # Verify password
    if not verify_master_password(credentials.password):
        remaining, triggered_lockout = _record_failed_attempt(client_ip)

        if triggered_lockout:
            log_siem_event(
                "api_login_attempt",
                "LOCKOUT_TRIGGERED",
                source_ip=client_ip,
                details={"lockout_duration": LOCKOUT_DURATION_SECONDS}
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed attempts. Locked out for {LOCKOUT_DURATION_SECONDS} seconds.",
                headers={"Retry-After": str(LOCKOUT_DURATION_SECONDS)},
            )

        log_siem_event(
            "api_login_attempt",
            "FAILURE",
            source_ip=client_ip,
            details={"remaining_attempts": remaining}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Success - clear any failed attempts for this IP
    _clear_failed_attempts(client_ip)

    # Initialize encryption key
    get_fernet(credentials.password)
    log_siem_event("api_login_attempt", "SUCCESS", source_ip=client_ip)
    return "authenticated"


def get_current_user(
    request: Request,
    bearer_credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    basic_credentials: Optional[HTTPBasicCredentials] = Depends(security_basic),
) -> str:
    """Dependency to verify authentication with brute force protection.

    Supports two authentication methods:
    1. JWT Bearer token (preferred): Authorization: Bearer <access_token>
    2. HTTP Basic Auth (legacy): Authorization: Basic <base64(user:password)>

    JWT Bearer is preferred as it doesn't transmit the master password with
    every request, reducing exposure window.

    Args:
        request: FastAPI request object (for IP extraction)
        bearer_credentials: JWT Bearer token (if provided)
        basic_credentials: HTTP Basic credentials (if provided)

    Returns:
        "authenticated" on success

    Raises:
        HTTPException: 401 if authentication fails
        HTTPException: 429 if IP is locked out
    """
    client_ip = _get_client_ip(request)

    # Prefer JWT Bearer token if provided
    if bearer_credentials and bearer_credentials.credentials:
        _authenticate_with_jwt(bearer_credentials.credentials, client_ip)
        return "authenticated"

    # Fall back to Basic Auth (legacy)
    if basic_credentials and basic_credentials.password:
        return _authenticate_with_basic(basic_credentials, client_ip)

    # No credentials provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Use Bearer token or Basic auth.",
        headers={"WWW-Authenticate": "Bearer, Basic"},
    )
