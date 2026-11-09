import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import api_router
from app.core.config import Settings
from app.core.csrf import CSRFMiddleware
from app.core.i18n import validate_catalogues
from app.core.logging import RequestLoggingMiddleware, configure_logging
from app.core.security_headers import SecurityHeadersMiddleware
from app.services.seed_sync import SeedSyncError, run_seed_sync
from app.web.auth import router as auth_router
from app.web.authentication import router as authentication_router
from app.web.checks_stream import router as checks_stream_router
from app.web.content import router as content_router
from app.web.deps import _session_factory
from app.web.dns_tools import router as dns_tools_router
from app.web.domains import router as domains_router
from app.web.health import router as health_router
from app.web.landing import router as landing_router
from app.web.message import router as message_router
from app.web.rules import router as rules_router
from app.web.setup import SetupGateMiddleware, prepare_setup
from app.web.setup import router as setup_router
from app.web.templating import STATIC_DIR, render
from app.web.templating import router as language_router

logger = logging.getLogger("app.seed_sync")

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


def sync_seeds_at_startup(app: FastAPI) -> None:
    """Startup hook: sync the global knowledge rows. Any failure (invalid seed, database error) is
    logged and startup goes on with the previous database state. Only a seed validation message
    is logged verbatim; other exceptions are named by type, their text can carry query details."""
    try:
        results = run_seed_sync(_session_factory(Request({"type": "http", "app": app})))
    except Exception as exc:
        logger.error(
            "seed sync failed, keeping the previous database state (%s)",
            exc if isinstance(exc, SeedSyncError) else type(exc).__name__,
            extra={"event": "seed_sync.failed"},
        )
        return
    logger.info(
        "seed sync done (%s)",
        ", ".join(
            f"{name}: {'changed' if r.changed else 'unchanged'}" for name, r in results.items()
        ),
        extra={"event": "seed_sync.done"},
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app. With explicit settings (tests) they are used as given; otherwise they are
    loaded from the environment at startup (lifespan), so a missing or invalid configuration
    raises ConfigError and the server does not serve. Nothing is read at import time."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        validate_catalogues()  # a missing or invalid locale file aborts startup
        app.state.settings = settings if settings is not None else Settings()
        cfg = app.state.settings
        configure_logging(cfg.log_level, log_secrets(cfg))
        cfg.log_resolver_config()
        # First-run setup: logs the one-time setup token (WARNING) while no user exists.
        await run_in_threadpool(prepare_setup, app)
        await run_in_threadpool(sync_seeds_at_startup, app)
        yield

    # Interactive docs and the OpenAPI schema are disabled: they would be served unauthenticated.
    # M10 (Docs site, OpenAPI) re-exposes OpenAPI behind authentication.
    web_app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    # The last added middleware is the outermost:
    # RequestLogging -> SecurityHeaders -> CSRF -> SetupGate -> app, so CSRF 403s and setup
    # redirects are logged and carry the security headers too.
    web_app.add_middleware(SetupGateMiddleware)
    web_app.add_middleware(CSRFMiddleware)
    web_app.add_middleware(SecurityHeadersMiddleware)
    web_app.add_middleware(RequestLoggingMiddleware)
    web_app.include_router(health_router)
    web_app.include_router(language_router)
    web_app.include_router(auth_router)
    web_app.include_router(setup_router)
    web_app.include_router(landing_router)
    web_app.include_router(domains_router)
    web_app.include_router(authentication_router)
    web_app.include_router(dns_tools_router)
    web_app.include_router(message_router)
    web_app.include_router(content_router)
    web_app.include_router(rules_router)
    web_app.include_router(checks_stream_router)
    web_app.include_router(api_router)
    web_app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @web_app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        # Browsers get the translated 404 page; API clients keep the JSON error body.
        if exc.status_code == 404 and "text/html" in request.headers.get("accept", ""):
            return render(request, "errors/404.html", status_code=404)
        return await http_exception_handler(request, exc)

    return web_app


app = create_app()
