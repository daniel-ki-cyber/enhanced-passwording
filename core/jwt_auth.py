"""JWT token authentication module.

Provides secure token generation and validation for API authentication.
Replaces per-request password transmission with short-lived tokens.

SECURITY FEATURES:
- Short-lived access tokens (15 min default)
- Separate refresh tokens (24 hour default)
- Cryptographically secure secret key requirement
- Token type validation to prevent token confusion attacks
- Encrypted password stored in token for vault access
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import jwt
from cryptography.fernet import Fernet

from core.config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES,
)


class JWTError(Exception):
    """Base exception for JWT-related errors."""
    pass


class TokenExpiredError(JWTError):
    """Token has expired."""
    pass


class InvalidTokenError(JWTError):
    """Token is invalid or malformed."""
    pass


class MissingSecretKeyError(JWTError):
    """JWT_SECRET_KEY not configured."""
    pass


def _get_secret_key() -> str:
    """Get JWT secret key with validation.

    SECURITY: Requires JWT_SECRET_KEY environment variable in production.
    Generates a temporary key for development (logs warning).

    Returns:
        Secret key for JWT signing

    Raises:
        MissingSecretKeyError: If no secret key is configured
    """
    if JWT_SECRET_KEY:
        return JWT_SECRET_KEY

    # For development only - in production, JWT_SECRET_KEY must be set
    raise MissingSecretKeyError(
        "JWT_SECRET_KEY environment variable not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )


def _get_token_encryption_key() -> bytes:
    """Derive a Fernet key from JWT secret for encrypting sensitive token data.

    Uses the JWT secret to create a deterministic Fernet key for encrypting
    the master password before storing it in tokens.
    """
    import hashlib
    import base64

    secret = _get_secret_key()
    # Derive a 32-byte key using SHA-256
    derived = hashlib.sha256(secret.encode()).digest()
    # Fernet requires base64-encoded 32-byte key
    return base64.urlsafe_b64encode(derived)


def _encrypt_for_token(data: str) -> str:
    """Encrypt sensitive data for storage in token."""
    key = _get_token_encryption_key()
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()


def _decrypt_from_token(encrypted_data: str) -> str:
    """Decrypt sensitive data from token."""
    key = _get_token_encryption_key()
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()


def create_access_token(
    master_password: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a short-lived access token.

    The master password is encrypted before being stored in the token,
    allowing the API to decrypt vault entries without re-authentication.

    Args:
        master_password: User's master password (will be encrypted in token)
        expires_delta: Custom expiration time (default: JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    Returns:
        Signed JWT access token
    """
    secret = _get_secret_key()

    if expires_delta is None:
        expires_delta = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    expire = datetime.now(timezone.utc) + expires_delta

    # Encrypt the master password for storage in token
    encrypted_password = _encrypt_for_token(master_password)

    payload = {
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16),  # Unique token ID
        "enc_key": encrypted_password,  # Encrypted master password
    }

    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def create_refresh_token(
    master_password: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a longer-lived refresh token.

    Refresh tokens are used to obtain new access tokens without
    re-entering the master password.

    Args:
        master_password: User's master password (will be encrypted in token)
        expires_delta: Custom expiration time (default: JWT_REFRESH_TOKEN_EXPIRE_MINUTES)

    Returns:
        Signed JWT refresh token
    """
    secret = _get_secret_key()

    if expires_delta is None:
        expires_delta = timedelta(minutes=JWT_REFRESH_TOKEN_EXPIRE_MINUTES)

    expire = datetime.now(timezone.utc) + expires_delta

    # Encrypt the master password for storage in token
    encrypted_password = _encrypt_for_token(master_password)

    payload = {
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16),
        "enc_key": encrypted_password,
    }

    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> Tuple[str, dict]:
    """Verify and decode an access token.

    Args:
        token: JWT access token

    Returns:
        Tuple of (decrypted_master_password, token_payload)

    Raises:
        TokenExpiredError: If token has expired
        InvalidTokenError: If token is invalid or wrong type
    """
    secret = _get_secret_key()

    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError("Access token has expired")
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Invalid token: {e}")

    # Verify token type to prevent token confusion attacks
    if payload.get("type") != "access":
        raise InvalidTokenError("Invalid token type - expected access token")

    # Decrypt the master password
    try:
        encrypted_password = payload.get("enc_key")
        if not encrypted_password:
            raise InvalidTokenError("Token missing encryption key")
        master_password = _decrypt_from_token(encrypted_password)
    except Exception:
        raise InvalidTokenError("Failed to decrypt token data")

    return master_password, payload


def verify_refresh_token(token: str) -> Tuple[str, dict]:
    """Verify and decode a refresh token.

    Args:
        token: JWT refresh token

    Returns:
        Tuple of (decrypted_master_password, token_payload)

    Raises:
        TokenExpiredError: If token has expired
        InvalidTokenError: If token is invalid or wrong type
    """
    secret = _get_secret_key()

    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError("Refresh token has expired")
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Invalid token: {e}")

    # Verify token type
    if payload.get("type") != "refresh":
        raise InvalidTokenError("Invalid token type - expected refresh token")

    # Decrypt the master password
    try:
        encrypted_password = payload.get("enc_key")
        if not encrypted_password:
            raise InvalidTokenError("Token missing encryption key")
        master_password = _decrypt_from_token(encrypted_password)
    except Exception:
        raise InvalidTokenError("Failed to decrypt token data")

    return master_password, payload


def get_token_expiry_info(token: str) -> dict:
    """Get expiry information for a token without full validation.

    Useful for clients to check if they need to refresh.

    Args:
        token: JWT token (access or refresh)

    Returns:
        Dict with 'expires_at', 'expires_in_seconds', 'is_expired'
    """
    try:
        # Decode without verification to read expiry
        payload = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False}
        )
        exp_timestamp = payload.get("exp", 0)
        exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)

        return {
            "expires_at": exp_datetime.isoformat(),
            "expires_in_seconds": max(0, int((exp_datetime - now).total_seconds())),
            "is_expired": exp_datetime <= now,
            "token_type": payload.get("type", "unknown"),
        }
    except Exception:
        return {
            "expires_at": None,
            "expires_in_seconds": 0,
            "is_expired": True,
            "token_type": "invalid",
        }
