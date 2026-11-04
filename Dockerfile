# syntax=docker/dockerfile:1
# Single multi-arch image (linux/amd64 + linux/arm64). No arch-specific instructions:
# the base images below are multi-arch manifests, buildx picks the right variant.

# Tag from Docker Hub "python" page (lists 3.12-slim-trixie, amd64 + arm64v8).
FROM python:3.12-slim-trixie

# uv install pattern and version pin: docs.astral.sh/uv/guides/integration/docker/
# (0.13.7 is the version shown there and the one used in development).
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /bin/

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

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
