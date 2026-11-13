# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Single multi-arch image (linux/amd64 + linux/arm64). No arch-specific instructions:
# the base images below are multi-arch manifests, buildx picks the right variant.

# Pinned by tag AND index digest (multi-arch image index, amd64 + arm64), read 2026-11-13 with
# `docker buildx imagetools inspect python:3.12-slim-trixie`. Refresh rule: docs/DOCKER-PINS.md.
FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# uv install pattern and version pin: docs.astral.sh/uv/guides/integration/docker/
# (0.13.7 is the version shown there and the one used in development). Index digest read
# 2026-11-13 with `docker buildx imagetools inspect ghcr.io/astral-sh/uv:0.13.7`.
COPY --from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Dependencies first (cached layer). --frozen: install exactly what uv.lock says.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-dev --no-install-project

COPY pyproject.toml uv.lock ./
COPY app ./app
COPY locales ./locales
COPY seeds ./seeds
COPY profiles ./profiles
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Non-root runtime user; /data holds the SQLite file (named volume in compose).
RUN groupadd --system app && useradd --system --gid app --home-dir /app --no-create-home app \
    && mkdir /data && chown app:app /data
USER app

ENV DATABASE_URL=sqlite:////data/app.db
EXPOSE 8000
VOLUME ["/data"]

# No curl in python:slim: use the interpreter.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

# --no-proxy-headers (R1-30): uvicorn must not rewrite the client address from X-Forwarded-For
# (its default trusts 127.0.0.1 and ::1, or $FORWARDED_ALLOW_IPS); the app alone decides,
# from TRUSTED_PROXIES (app/web/auth.py resolve_client_ip).
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-proxy-headers"]
