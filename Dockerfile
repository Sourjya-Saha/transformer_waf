# ==============================================================================
# Production Dockerfile for Web Application Firewall (WAF) Gateway
# ==============================================================================
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH="/app"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user and logs directory
RUN useradd -m -u 1000 wafuser && \
    mkdir -p /app/logs && \
    chown -R wafuser:wafuser /app

# Copy application source
COPY --chown=wafuser:wafuser web_firewall/ /app/web_firewall/

USER wafuser

EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

CMD ["python", "-m", "web_firewall.gateway.server"]
