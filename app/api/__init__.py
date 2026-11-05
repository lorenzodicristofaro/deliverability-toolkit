"""REST API routers. `api_router` (prefix `/api/v1`) is registered by `app.main`.

Every API route is cookie-session authenticated for now (API keys arrive in M10); mutations
therefore need the CSRF header (`X-CSRF-Token`, enforced by `app.core.csrf.CSRFMiddleware`).
"""

from fastapi import APIRouter

from app.api.v1.dns_tools import router as dns_tools_router
from app.api.v1.domains import router as domains_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(domains_router)
api_router.include_router(dns_tools_router)

__all__ = ["api_router"]
