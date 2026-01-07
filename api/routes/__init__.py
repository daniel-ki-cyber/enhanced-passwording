"""API route modules."""

from api.routes.health import router as health_router
from api.routes.tools import router as tools_router
from api.routes.vault import router as vault_router

__all__ = ["health_router", "tools_router", "vault_router"]
