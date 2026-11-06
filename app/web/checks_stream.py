"""DKIM probe as a Server-Sent Events stream (M3-16).

Routes (GET, `text/event-stream`):
- `/domains/{domain_id}/authentication/dkim/stream`: `check.run` on the domain;
- `/tools/dkim/stream?name=...`: `dns.tools`, no tenant data.

Access order is that of the M3-15 API: anonymous -> 401 (303 to /login for an HTML navigation),
no active tenant or a domain that is missing, foreign, malformed or (client viewer) unassigned ->
404, missing permission -> 403, invalid free name -> 422. All of these are decided BEFORE the
stream starts, so a denied caller never gets an event.

Events: one `selector` event per selector in completion order (data = an escaped HTML fragment of
`checks/_dkim_row.html`), then one `done` event with the summary and findings. A failed selector
is a row in the `error` state, never an empty or "not found" row. The whole stream has an overall
deadline (`STREAM_DEADLINE_S`); when it expires the probe is stopped and `done` says the result is
incomplete (status `error`, no aggregate findings). A client disconnect cancels the response task;
the `finally`
closes the probe generator, which cancels its in-flight lookups.

The client (M3-17) must close its EventSource on `done`, otherwise the browser reconnects.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Sequence
from typing import Annotated, Final, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.api.v1.checks import ResolverDep
from app.checks.dkim import SelectorResult, probe_selectors, summarize
from app.checks.dkim_selectors import list_selectors
from app.checks.models import CheckContext, CheckResult
from app.core.domain_names import InvalidDomainName, to_ascii_domain, to_dns_name
from app.core.i18n import t
from app.core.permissions import Action, DomainResource, TenantResource, can
from app.dns.types import Resolver
from app.services.domains import DomainService, DomainServiceError
from app.web.deps import CurrentSession, DbDep, tenant_ctx
from app.web.dns_tools import visible  # noqa: F401  (registers the `visible` Jinja filter)
from app.web.domains import _domain_id
from app.web.templating import env, request_language

router = APIRouter()

STREAM_DEADLINE_S: Final = 60.0
MAX_NAME_LEN: Final = 1024
TEMPLATE: Final = "checks/_dkim_row.html"
HEADERS: Final = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}


# --- access -------------------------------------------------------------------------------------


class _Target:
    __slots__ = ("domain", "domain_id", "tenant_id")

    def __init__(self, domain: str, tenant_id: int | None, domain_id: int | None) -> None:
        self.domain = domain
        self.tenant_id = tenant_id
        self.domain_id = domain_id


def _forbidden(request: Request) -> HTTPException:
    return HTTPException(403, t("api.error.forbidden", request_language(request.scope)))


def _domain_target(request: Request, auth: CurrentSession, db: DbDep, domain_id: str) -> _Target:
    """401 anonymous, 404 no tenant / invisible domain, 403 without `check.run` on it."""
    ctx = tenant_ctx(auth)
    try:
        view = DomainService(db, ctx, auth.principal).get(_domain_id(domain_id))
    except DomainServiceError as exc:
        raise HTTPException(exc.status, t(exc.key, request_language(request.scope))) from None
    if not can(auth.principal, Action.CHECK_RUN, DomainResource(ctx.tenant_id, view.id)):
        raise _forbidden(request)
    return _Target(view.name, ctx.tenant_id, view.id)


def _free_target(
    request: Request,
    auth: CurrentSession,
    name: Annotated[str, Query(max_length=MAX_NAME_LEN)] = "",
) -> _Target:
    """401 anonymous, 404 no tenant, 403 without `dns.tools`, 422 invalid name."""
    ctx = tenant_ctx(auth)
    if not can(auth.principal, Action.DNS_TOOLS, TenantResource(ctx.tenant_id)):
        raise _forbidden(request)
    try:
        to_dns_name(name, allow_underscore=False)
        return _Target(to_ascii_domain(name), None, None)
    except InvalidDomainName:
        raise HTTPException(
            422, t("tools.dns.invalid_name", request_language(request.scope))
        ) from None


DomainTarget = Annotated[_Target, Depends(_domain_target)]
FreeTarget = Annotated[_Target, Depends(_free_target)]


# --- stream -------------------------------------------------------------------------------------


def sse(event: str, html: str) -> str:
    """One SSE frame. `html` is split on line breaks so no raw newline can end the frame early."""
    lines = html.strip().splitlines() or [""]
    return f"event: {event}\n" + "".join(f"data: {line}\n" for line in lines) + "\n"


def _render(lang: str, **context: object) -> str:
    return env.get_template(TEMPLATE).render(
        lang=lang, t=lambda key, **params: t(key, lang, **params), **context
    )


def _row(res: SelectorResult) -> dict[str, object]:
    return {
        "selector": res.selector,
        "state": res.state,
        "reason": res.reason,
        "key_type": res.key_type,
        "bits": res.bits,
        "chain": res.chain,
        "records": res.records,
    }


async def dkim_events(
    ctx: CheckContext,
    domain: str,
    lang: str,
    *,
    selectors: Sequence[str] | None = None,
    deadline_s: float = STREAM_DEADLINE_S,
    on_result: Callable[[CheckResult], None] | None = None,
) -> AsyncIterator[str]:
    """SSE frames for one probe run. Closing this generator closes the probe."""
    names = tuple(selectors) if selectors is not None else tuple(s.name for s in list_selectors())
    results: list[SelectorResult] = []
    complete = True
    started = ctx.clock()
    t0 = time.monotonic()
    # `probe_selectors` is an async generator; it is typed as an iterator, we need `aclose`.
    probe = cast("AsyncGenerator[SelectorResult, None]", probe_selectors(ctx, domain, names))
    try:
        try:
            async with asyncio.timeout(deadline_s):
                async for res in probe:
                    results.append(res)
                    yield sse("selector", _render(lang, kind="row", row=_row(res)))
        except TimeoutError:
            complete = False
        summary = {
            "probed": len(results),
            "found": sum(r.state == "found" for r in results),
            "not_found": sum(r.state == "not_found" for r in results),
            "errors": sum(r.state == "error" for r in results),
        }
        result = summarize(
            domain,
            results,
            names,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
            complete=complete,
        )
        if on_result is not None:
            on_result(result)
        yield sse(
            "done",
            _render(
                lang,
                kind="done",
                summary=summary,
                findings=result.findings,
                complete=complete,
                status=result.status,
            ),
        )
    finally:
        await probe.aclose()


def _response(request: Request, resolver: Resolver, target: _Target) -> StreamingResponse:
    ctx = CheckContext(
        resolver=resolver,
        tenant_id=None if target.tenant_id is None else str(target.tenant_id),
        domain_id=None if target.domain_id is None else str(target.domain_id),
    )
    events = dkim_events(ctx, target.domain, request_language(request.scope))
    return StreamingResponse(events, media_type="text/event-stream", headers=HEADERS)


# --- routes -------------------------------------------------------------------------------------


@router.get("/domains/{domain_id}/authentication/dkim/stream", include_in_schema=False)
async def domain_dkim_stream(
    request: Request, target: DomainTarget, resolver: ResolverDep
) -> StreamingResponse:
    return _response(request, resolver, target)


@router.get("/tools/dkim/stream", include_in_schema=False)
async def free_dkim_stream(
    request: Request, target: FreeTarget, resolver: ResolverDep
) -> StreamingResponse:
    return _response(request, resolver, target)
