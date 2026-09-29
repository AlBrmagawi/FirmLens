FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS frontend
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:python3.14-alpine@sha256:ea7c8f721b5042fb12f6eb051b63469edfeb61c7c00551dbe67d71f182810c66
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy
COPY security/zlib /opt/zlib-backport
RUN apk add --no-cache --virtual .zlib-build build-base patch \
    && sh /opt/zlib-backport/build.sh \
    && apk del .zlib-build
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv pip install --no-deps -e .
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts ./scripts
COPY --from=frontend /web/dist ./frontend/dist
ENV PATH="/app/.venv/bin:$PATH"
USER 10001:10001
CMD ["uvicorn", "firmwarelens.api:app", "--host", "0.0.0.0", "--port", "8080"]
