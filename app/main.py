from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import Settings
from app.web.health import router as health_router


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app. With explicit settings (tests) they are used as given; otherwise they are
    loaded from the environment at startup (lifespan), so a missing or invalid configuration
    raises ConfigError and the server does not serve. Nothing is read at import time."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings if settings is not None else Settings()
        yield

    web_app = FastAPI(lifespan=lifespan)
    web_app.include_router(health_router)
    return web_app


app = create_app()
