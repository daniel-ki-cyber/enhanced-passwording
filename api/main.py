"""FastAPI application configuration.

Main entry point for the Password Vault REST API.
"""

import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import clear_cached_fernet
from api.routes import health_router, tools_router, vault_router


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
    """,
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health_router)
app.include_router(tools_router)
app.include_router(vault_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
