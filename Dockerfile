# =============================================================================
# Project Raven — production container
# Multi-stage build: builder (compile deps) → runtime (slim, non-root)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Build deps for native wheels (paramiko, cryptography, scientific libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt \
    # optional tool-adapter python bindings (best-effort; errors are non-fatal)
    && pip install --user --no-cache-dir \
        openrouter \
        python-whois \
        r2pipe \
    || true

# -----------------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH=/home/raven/.local/bin:$PATH \
    RAVEN_ENVIRONMENT=prod

# Runtime-only system deps (no metasploit/empire in the API pod — those run in
# dedicated tool-runner pods per the production plan).
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        openssh-client \
        curl \
        ca-certificates \
        tini \
        whois \
        radare2 \
        git \
        wget \
        unzip \
        default-jdk-headless \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 raven \
    && useradd  --system --uid 10001 --gid raven --create-home --shell /usr/sbin/nologin raven \
    # Download jadx (Android decompiler)
    && JADX_VER=1.5.1 \
    && wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" -O /tmp/jadx.zip \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && chmod +x /opt/jadx/bin/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx

ENV JADX_HOME=/opt/jadx

# Copy Python deps from builder
COPY --from=builder /root/.local /home/raven/.local
RUN chown -R raven:raven /home/raven/.local

WORKDIR /app
COPY --chown=raven:raven raven/ ./raven/
COPY --chown=raven:raven RAVEN_SYSTEM_PROMPT.md ./
COPY --chown=raven:raven pyproject.toml ./

# Writable runtime dirs only — root FS stays read-only via K8s securityContext
RUN mkdir -p /var/log/raven /var/lib/raven /tmp/raven \
    && chown -R raven:raven /var/log/raven /var/lib/raven /tmp/raven

USER raven:raven

EXPOSE 8000 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# tini handles PID 1 / zombie reaping
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "raven.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--proxy-headers", \
     "--forwarded-allow-ips=*"]
