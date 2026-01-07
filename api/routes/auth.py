"""Authentication endpoints.

Provides JWT token-based authentication to replace per-request Basic Auth.
This improves security by:
1. Not transmitting the master password with every request
2. Using short-lived tokens that limit exposure window
3. Supporting token refresh without re-authentication
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from api.dependencies import (
    verify_master_password,
    _get_client_ip,
    _check_lockout,
    _record_failed_attempt,
    _clear_failed_attempts,
)
from core import log_siem_event, get_fernet
from core.jwt_auth import (
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
    get_token_expiry_info,
    TokenExpiredError,
    InvalidTokenError,
    MissingSecretKeyError,
)
from core.config import (
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES,
    LOCKOUT_DURATION_SECONDS,
)


router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBasic()


class TokenResponse(BaseModel):
    """Response containing JWT tokens."""
    access_token: str = Field(..., description="Short-lived access token")
    refresh_token: str = Field(..., description="Long-lived refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiry in seconds")


class RefreshRequest(BaseModel):
    """Request to refresh an access token."""
    refresh_token: str = Field(..., description="Valid refresh token")


class TokenInfoResponse(BaseModel):
    """Token information response."""
    expires_at: str | None
    expires_in_seconds: int
    is_expired: bool
    token_type: str


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security)
):
    """Authenticate and receive JWT tokens.

    Use HTTP Basic Auth to authenticate with your master password.
    Returns access and refresh tokens for subsequent API calls.

    The access token should be used in the Authorization header:
    `Authorization: Bearer <access_token>`

    When the access token expires, use the /auth/refresh endpoint
    with your refresh token to get a new access token.
    """
    client_ip = _get_client_ip(request)

    # Check if IP is locked out
    is_locked, remaining_seconds = _check_lockout(client_ip)
    if is_locked:
        log_siem_event(
            "jwt_login_attempt",
            "LOCKOUT_ACTIVE",
            source_ip=client_ip,
            details={"remaining_seconds": remaining_seconds}
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {remaining_seconds} seconds.",
            headers={"Retry-After": str(remaining_seconds)},
        )

    # Verify master password
    if not verify_master_password(credentials.password):
        remaining, triggered_lockout = _record_failed_attempt(client_ip)

        if triggered_lockout:
            log_siem_event(
                "jwt_login_attempt",
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
            "jwt_login_attempt",
            "FAILURE",
            source_ip=client_ip,
            details={"remaining_attempts": remaining}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Clear failed attempts on success
    _clear_failed_attempts(client_ip)

    # Generate tokens
    try:
        access_token = create_access_token(credentials.password)
        refresh_token = create_refresh_token(credentials.password)
    except MissingSecretKeyError as e:
        log_siem_event(
            "jwt_login_attempt",
            "CONFIG_ERROR",
            source_ip=client_ip,
            details={"error": "JWT_SECRET_KEY not configured"}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT authentication not configured. Set JWT_SECRET_KEY environment variable."
        )

    log_siem_event("jwt_login_attempt", "SUCCESS", source_ip=client_ip)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    request: Request,
    refresh_request: RefreshRequest
):
    """Refresh an access token using a valid refresh token.

    When your access token expires, call this endpoint with your
    refresh token to get a new access token without re-entering
    your master password.

    Note: A new refresh token is also issued. The old refresh token
    should be discarded.
    """
    client_ip = _get_client_ip(request)

    try:
        # Verify refresh token and extract master password
        master_password, payload = verify_refresh_token(refresh_request.refresh_token)

        # Generate new token pair
        access_token = create_access_token(master_password)
        refresh_token = create_refresh_token(master_password)

        log_siem_event(
            "jwt_token_refresh",
            "SUCCESS",
            source_ip=client_ip
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

    except TokenExpiredError:
        log_siem_event(
            "jwt_token_refresh",
            "EXPIRED",
            source_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please login again."
        )

    except InvalidTokenError:
        log_siem_event(
            "jwt_token_refresh",
            "INVALID",
            source_ip=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    except MissingSecretKeyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT authentication not configured"
        )


@router.post("/token-info", response_model=TokenInfoResponse)
async def get_token_info(token: str = ""):
    """Get information about a token's expiry.

    Useful for clients to check if they need to refresh their token.
    Does not validate the token signature - only reads expiry info.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token required"
        )

    info = get_token_expiry_info(token)
    return TokenInfoResponse(**info)
