FROM python:3.12-slim AS base

LABEL maintainer="Gopala Rao Kambidi"
LABEL description="WebRTC to SIP Gateway"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY config/ config/
COPY web/ web/

# WebSocket signaling + REST API
EXPOSE 8765/tcp
# SIP signaling
EXPOSE 5060/udp
EXPOSE 5060/tcp
# RTP media relay range
EXPOSE 10000-10100/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8765/api/v1/health')" || exit 1

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--config", "/app/config/gateway.yaml"]
