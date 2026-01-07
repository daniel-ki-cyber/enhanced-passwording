"""Health check endpoints.

Public endpoints for service health monitoring.
"""

import os
from datetime import datetime

from fastapi import APIRouter

from core import MASTER_FILE


router = APIRouter(tags=["Health"])


@router.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "healthy", "service": "Password Vault API"}


@router.get("/health")
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "vault_exists": os.path.exists(MASTER_FILE)
    }
