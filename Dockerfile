# ==============================================================================
# Dockerfile for Transformer-Based Web Application Firewall (WAF)
# ==============================================================================
FROM python:3.11-slim AS base

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

# Install python dependencies (installing cpu-optimized torch for lean image)
COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# Create non-root user
RUN useradd -m -u 1000 wafuser && \
    mkdir -p /app/data && \
    chown -R wafuser:wafuser /app

# Copy WAF application code and model weights
COPY --chown=wafuser:wafuser waf/ /app/

USER wafuser

EXPOSE 8000

# Default environment variables
ENV WAF_HOST="0.0.0.0" \
    WAF_PORT="8000" \
    WAF_PROXY="http://backend:8080" \
    WAF_BLOCK="false"

# Healthcheck
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "waf.py", "serve"]
