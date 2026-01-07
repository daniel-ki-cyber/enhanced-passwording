"""FastAPI application configuration.

Main entry point for the Password Vault REST API.
Implements security best practices including rate limiting, security headers,
HTTPS enforcement, and restrictive CORS configuration.
"""

import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import clear_cached_fernet
from core.config import REQUIRE_HTTPS
from api.routes import auth_router, health_router, tools_router, vault_router


# Rate limiter configuration
# Uses client IP for rate limit tracking
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    yield
    clear_cached_fernet()


app = FastAPI(
    title="Password Vault API",
    description="""
    Secure password management API with:
    - AES-256 encryption (Fernet)
    - PBKDF2 key derivation (600K iterations)
    - HaveIBeenPwned breach detection
    - SIEM-compatible logging
    - Rate limiting for brute force protection
    """,
    version="1.0.0",
    lifespan=lifespan
)

# Attach rate limiter to app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# HTTPS enforcement middleware
@app.middleware("http")
async def enforce_https(request: Request, call_next) -> Response:
    """Enforce HTTPS connections when REQUIRE_HTTPS is enabled.

    When enabled (via REQUIRE_HTTPS=true environment variable), rejects
    all non-HTTPS requests to protected endpoints. Health checks are
    exempted to allow load balancer probes.

    SECURITY: HTTP Basic Auth sends credentials Base64-encoded (NOT encrypted).
    Without HTTPS, credentials are visible to anyone monitoring network traffic.
    Enable this in production by setting REQUIRE_HTTPS=true.
    """
    if REQUIRE_HTTPS:
        # Allow health checks over HTTP for load balancer probes
        if request.url.path in ["/", "/health"]:
            return await call_next(request)

        # Check if request is HTTPS
        # X-Forwarded-Proto is set by reverse proxies (nginx, traefik, etc.)
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
        is_https = (
            request.url.scheme == "https" or
            forwarded_proto.lower() == "https"
        )

        if not is_https:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "HTTPS required. This API requires secure connections.",
                    "error": "https_required"
                }
            )

    return await call_next(request)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    """Add security headers to all responses.

    Headers follow OWASP security recommendations:
    - X-Content-Type-Options: Prevents MIME-type sniffing
    - X-Frame-Options: Prevents clickjacking attacks
    - X-XSS-Protection: Legacy XSS protection for older browsers
    - Strict-Transport-Security: Enforces HTTPS (when deployed with TLS)
    - Content-Security-Policy: Restricts resource loading
    - Referrer-Policy: Controls referrer information leakage
    - Cache-Control: Prevents caching of sensitive data
    - Permissions-Policy: Restricts browser features
    """
    response = await call_next(request)

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # XSS protection for legacy browsers
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Enforce HTTPS (uncomment in production with TLS)
    # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Content Security Policy - restrictive default
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"

    # Control referrer information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Prevent caching of sensitive responses
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"

    # Restrict browser features
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    return response


# CORS configuration - explicitly restricted
# Only allows specific origins, methods, and headers needed by the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# Register routers
app.include_router(auth_router)
app.include_router(health_router)
app.include_router(tools_router)
app.include_router(vault_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
