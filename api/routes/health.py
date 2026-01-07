"""Health check endpoints.

Public endpoints for service health monitoring.
Note: Does not expose sensitive information about vault state.
"""

from datetime import datetime

from fastapi import APIRouter


router = APIRouter(tags=["Health"])


@router.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "healthy", "service": "Password Vault API"}


@router.get("/health")
async def health_check():
    """Detailed health check.

    Note: Intentionally does not expose vault existence or configuration
    to prevent information disclosure to unauthenticated users.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }
