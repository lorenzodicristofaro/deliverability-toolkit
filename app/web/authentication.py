"""Domain page "Authentication" tab (M3-17): `GET /domains/{domain_id}/authentication`.

SPF and DMARC are run server-side through the single check runner (`run_checks`), so the page
shows the same `CheckResult` objects the API returns, rendered by `checks/_result.html`. DKIM rows
stream from the M3-16 SSE route, consumed by one same-origin static file (`dkim_stream.js`; CSP
is `script-src 'self'`, no inline script). Without JS a `<noscript>` note is shown.

Access (same order as the domain page): anonymous -> 303 /login; no tenant, or a domain that is
missing, foreign, malformed or (client viewer) unassigned -> 404; without `check.run` on the
domain -> 403 page. A DNS failure is an `error` result, never "missing".
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import APIRouter, Request
from fastapi.responses import Response

from app.api.v1.checks import ResolverDep
from app.checks.finding_text import display_params
from app.checks.models import CheckContext
from app.core.permissions import Action, DomainResource, can
from app.services.checks import run_checks
from app.services.domains import DomainServiceError, Forbidden
from app.web.deps import DbDep
from app.web.dns_tools import visible
from app.web.domains import WebDep, _denied, _domain_id
from app.web.templating import env, render

router = APIRouter()

CHECK_IDS: Final = ("spf", "dmarc")


def finding_params(params: Any, code: str | None = None, lang: str | None = None) -> dict[str, Any]:
    """Finding params for `t()`: with `code` and `lang`, known tokens become localized text
    (`app.checks.finding_text`, M6-06b); DNS-sourced strings are made visible-safe (control
    characters shown as escapes); Jinja autoescape still applies to the final text."""
    values = dict(params) if code is None or lang is None else display_params(code, params, lang)
    return {k: visible(v) if isinstance(v, str) else v for k, v in values.items()}


def https_only(url: object) -> bool:
    """A docs link is rendered only when it is an https URL."""
    return isinstance(url, str) and url.startswith("https://")


env.filters["finding_params"] = finding_params
env.tests["https_url"] = https_only


@router.get("/domains/{domain_id}/authentication", include_in_schema=False)
async def authentication_tab(
    request: Request, web: WebDep, db: DbDep, resolver: ResolverDep, domain_id: str
) -> Response:
    try:
        view = web.service.get(_domain_id(domain_id))
    except DomainServiceError as exc:
        return _denied(request, exc)
    finally:
        db.rollback()  # `view` holds plain values: no pooled connection is held during DNS
    principal = web.service.principal
    if not can(principal, Action.CHECK_RUN, DomainResource(web.ctx.tenant_id, view.id)):
        return _denied(request, Forbidden())
    ctx = CheckContext(resolver=resolver, tenant_id=str(web.ctx.tenant_id), domain_id=str(view.id))
    results = await run_checks(list(CHECK_IDS), view.name, ctx)
    return render(
        request,
        "domains/authentication.html",
        logged_in=True,
        domain_id=view.id,
        display_name=view.display_name,
        results=results,
    )
