FROM ghcr.io/astral-sh/uv:0.12.13@sha256:b485bd65cc2cf1c9a93b3554012c9c3778cf7b1b5fd3d3096ce9e1226c97e1e6 AS uv

FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY apigateway ./apigateway

RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --gid 10001 apigateway \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin apigateway

COPY --from=builder /app/.venv /app/.venv
COPY alembic.ini wsgi.py ./
COPY apigateway ./apigateway
COPY migrations ./migrations
COPY scripts ./scripts

RUN install -d --owner=10001 --group=10001 --mode=0755 /app/apigateway/logs

USER 10001:10001

EXPOSE 8181

CMD ["gunicorn", "--bind=0.0.0.0:8181", "--access-logfile=-", "--error-logfile=-", "wsgi:application"]
