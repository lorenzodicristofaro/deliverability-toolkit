"""REST API routers. `api_router` (prefix `/api/v1`) is registered by `app.main`.

Every API route is cookie-session authenticated for now (API keys arrive in M10); mutations
therefore need the CSRF header (`X-CSRF-Token`, enforced by `app.core.csrf.CSRFMiddleware`).
"""

from fastapi import APIRouter

from app.api.v1.checks import router as checks_router
from app.api.v1.content import router as content_router
from app.api.v1.custom_checks import router as custom_checks_router
from app.api.v1.dkim_selectors import router as dkim_selectors_router
from app.api.v1.dns_tools import router as dns_tools_router
from app.api.v1.domain_esps import router as domain_esps_router
from app.api.v1.domains import router as domains_router
from app.api.v1.message import router as message_router
from app.api.v1.rules import router as rules_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(domains_router)
api_router.include_router(dns_tools_router)
api_router.include_router(checks_router)
api_router.include_router(message_router)
api_router.include_router(content_router)
api_router.include_router(rules_router)
api_router.include_router(dkim_selectors_router)
api_router.include_router(custom_checks_router)
api_router.include_router(domain_esps_router)

__all__ = ["api_router"]
