# Password Vault - Multi-stage Docker build
# Optimized for security and small image size
#
# SECURITY NOTES:
# - Runs as non-root user (vaultuser)
# - API binds to 127.0.0.1 by default (localhost only)
# - For external access, use a reverse proxy (nginx/traefik) with TLS
# - Set VAULT_BIND_HOST=0.0.0.0 only behind a secure reverse proxy

FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# --- Production image ---
FROM python:3.12-slim

WORKDIR /app

# Create non-root user for security (no login shell for security hardening)
RUN useradd --create-home --shell /usr/sbin/nologin vaultuser

# Copy installed packages from builder
COPY --from=builder /root/.local /home/vaultuser/.local

# Copy application code
COPY --chown=vaultuser:vaultuser . .

# Set environment variables
ENV PATH=/home/vaultuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Configurable bind host - defaults to localhost for security
# Override with -e VAULT_BIND_HOST=0.0.0.0 if behind reverse proxy
ENV VAULT_BIND_HOST=127.0.0.1

# Create directories for data persistence with secure permissions
RUN mkdir -p /app/logs /app/tickets /app/reports \
    && chown -R vaultuser:vaultuser /app \
    && chmod 700 /app/logs /app/tickets /app/reports

# Switch to non-root user
USER vaultuser

# Expose API port (documentation only - actual binding controlled by CMD)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command - run API server bound to localhost only
# SECURITY: Binds to 127.0.0.1 by default. Use reverse proxy for external access.
CMD ["sh", "-c", "python -m uvicorn api.main:app --host ${VAULT_BIND_HOST} --port 8000"]
