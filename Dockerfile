# Password Vault - Multi-stage Docker build
# Optimized for security and small image size

FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# --- Production image ---
FROM python:3.12-slim

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash vaultuser

# Copy installed packages from builder
COPY --from=builder /root/.local /home/vaultuser/.local

# Copy application code
COPY --chown=vaultuser:vaultuser . .

# Set environment variables
ENV PATH=/home/vaultuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Create directories for data persistence
RUN mkdir -p /app/logs /app/tickets /app/reports \
    && chown -R vaultuser:vaultuser /app

# Switch to non-root user
USER vaultuser

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command - run API server
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
