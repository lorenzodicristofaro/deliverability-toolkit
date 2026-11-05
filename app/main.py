from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core.config import Settings
from app.core.csrf import CSRFMiddleware
from app.core.logging import RequestLoggingMiddleware, configure_logging
from app.core.security_headers import SecurityHeadersMiddleware
from app.web.health import router as health_router

_MIN_MASKED_LEN = 8  # same threshold as app.core.logging: shorter values are not masked


def log_secrets(cfg: Settings) -> list[str]:
    """Values the log formatter masks: both keys and the DATABASE_URL password (if long enough)."""
    secrets = [cfg.secret_key.get_secret_value(), cfg.encryption_key.get_secret_value()]
    try:
        password = make_url(cfg.database_url.get_secret_value()).password
    except ArgumentError:
        password = None
    if password and len(password) >= _MIN_MASKED_LEN:
        secrets.append(password)
    return secrets


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app. With explicit settings (tests) they are used as given; otherwise they are
    loaded from the environment at startup (lifespan), so a missing or invalid configuration
    raises ConfigError and the server does not serve. Nothing is read at import time."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings if settings is not None else Settings()
        cfg = app.state.settings
        configure_logging(cfg.log_level, log_secrets(cfg))
        yield

    # Interactive docs and the OpenAPI schema are disabled: they would be served unauthenticated.
    # M10 (Docs site, OpenAPI) re-exposes OpenAPI behind authentication.
    web_app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    # The last added middleware is the outermost: RequestLogging -> SecurityHeaders -> CSRF -> app,
    # so CSRF 403s are logged and carry the security headers too.
    web_app.add_middleware(CSRFMiddleware)
    web_app.add_middleware(SecurityHeadersMiddleware)
    web_app.add_middleware(RequestLoggingMiddleware)
    web_app.include_router(health_router)
    return web_app


app = create_app()
