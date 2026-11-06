# ==============================================================================
# Stage 1: Builder — Compile wheels and install pinned Python dependencies
# ==============================================================================
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# ==============================================================================
# Stage 2: Production Runtime — Minimal hardened image running FastAPI + Streamlit
# ==============================================================================
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app" \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r omniguard && useradd -r -g omniguard -d /app -s /sbin/nologin omniguard

COPY --from=builder /opt/venv /opt/venv
COPY src/ ./src/
COPY ui/ ./ui/
COPY data/ ./data/
COPY scripts/ ./scripts/

RUN printf '#!/bin/sh\nset -e\nuvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 2 &\nexec streamlit run ui/dashboard.py --server.port=8501 --server.address=0.0.0.0 --server.headless=true\n' > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh \
    && chown -R omniguard:omniguard /app

USER omniguard

EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
