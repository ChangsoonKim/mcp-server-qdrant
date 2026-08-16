FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS base

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*


FROM base AS builder

ARG UV_VERSION=0.9.17
ARG EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    EMBEDDING_CACHE_DIR=/opt/models

WORKDIR /app

RUN pip install --no-cache-dir "uv==${UV_VERSION}"

COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project \
    && .venv/bin/python -c "from fastembed import TextEmbedding; TextEmbedding('${EMBEDDING_MODEL}', cache_dir='/opt/models')"

COPY README.md LICENSE ./
COPY src ./src

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable


FROM base AS runtime

LABEL org.opencontainers.image.title="mcp-server-qdrant" \
      org.opencontainers.image.version="0.9.0" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EMBEDDING_CACHE_DIR=/opt/models \
    FASTMCP_HOME=/var/lib/mcp \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=8000 \
    SERVER_PATH=/mcp

WORKDIR /app

RUN groupadd --system --gid 10001 mcp \
    && useradd --system --uid 10001 --gid mcp --home-dir /var/lib/mcp --shell /usr/sbin/nologin mcp \
    && install -d -o mcp -g mcp /var/lib/mcp

COPY --from=builder /app/.venv /app/.venv
COPY --chown=10001:10001 --from=builder /opt/models /opt/models

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["mcp-server-qdrant", "--transport", "streamable-http"]
