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
incomplete (status `error`, no aggregate findings). The selector list of a domain stream is resolved
and the database connection released before the stream starts, so no transaction is held during
the probe; the free route stays on the seed list. Each row shows the selector's provider when the
list has one (domain stream: tenant row, else global row; free stream: the seed), for every role
that can see the domain; selector notes never reach a row. A client disconnect cancels the
response task; the `finally` closes the probe generator, which cancels its in-flight lookups.

The client (M3-17) must close its EventSource on `done`, otherwise the browser reconnects.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Mapping, Sequence
from typing import Annotated, Final, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.api.v1.checks import ResolverDep
from app.checks.dkim import (
    DkimCheck,
    SelectorResult,
    probe_selectors,
    seed_providers,
    summarize,
)
from app.checks.dkim_selectors import KnowledgeError, list_selectors
from app.checks.models import CheckContext, CheckResult, finding
from app.core.domain_names import InvalidDomainName, to_ascii_domain, to_dns_name
from app.core.i18n import t
from app.core.permissions import Action, DomainResource, TenantResource, can
from app.dns.types import Resolver
from app.services.dkim_probe_selectors import ProbeSelectors, resolve_and_release
from app.services.domains import DomainService, DomainServiceError
from app.web.deps import CurrentSession, DbDep, tenant_ctx
from app.web.dns_tools import visible  # noqa: F401  (registers the `visible` Jinja filter)
from app.web.domains import _domain_id
from app.web.templating import env, request_language

router = APIRouter()
log = logging.getLogger(__name__)

STREAM_DEADLINE_S: Final = 60.0
MAX_NAME_LEN: Final = 1024
TEMPLATE: Final = "checks/_dkim_row.html"
HEADERS: Final = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}


# --- access -------------------------------------------------------------------------------------


class _Target:
    __slots__ = ("domain", "domain_id", "probe", "tenant_id")

    def __init__(
        self, domain: str, tenant_id: int | None, domain_id: int | None, probe: ProbeSelectors
    ) -> None:
        self.domain = domain
        self.tenant_id = tenant_id
        self.domain_id = domain_id
        self.probe = probe


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
    return _Target(view.name, ctx.tenant_id, view.id, resolve_and_release(ctx, db))


def _free_target(
    request: Request,
    auth: CurrentSession,
    db: DbDep,
    name: Annotated[str, Query()] = "",
) -> _Target:
    """401 anonymous, 404 no tenant, 403 without `dns.tools`, 422 invalid name."""
    ctx = tenant_ctx(auth)
    if not can(auth.principal, Action.DNS_TOOLS, TenantResource(ctx.tenant_id)):
        raise _forbidden(request)
    try:
        if len(name) > MAX_NAME_LEN:
            raise InvalidDomainName("too_long")
        to_dns_name(name, allow_underscore=False)
        target = _Target(to_ascii_domain(name), None, None, ProbeSelectors(None))
    except InvalidDomainName:
        raise HTTPException(
            422, t("tools.dns.invalid_name", request_language(request.scope))
        ) from None
    db.rollback()  # no tenant rows to read: just hold no transaction during the probe
    return target


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
        "provider": res.provider,
        "state": res.state,
        "reason": res.reason,
        "key_type": res.key_type,
        "bits": res.bits,
        "chain": res.chain,
        "records": res.records,
    }


def _done_frame(lang: str, result: CheckResult, *, complete: bool, deadline: bool) -> str:
    states = [sel["state"] for sel in result.data["selectors"]]
    summary = {
        "probed": result.data["probed"],
        "found": result.data["found"],
        "not_found": states.count("not_found"),
        "errors": states.count("error"),
    }
    return sse(
        "done",
        _render(
            lang,
            kind="done",
            summary=summary,
            findings=result.findings,
            complete=complete,
            deadline=deadline,
            status=result.status,
        ),
    )


def _not_evaluated(ctx: CheckContext, domain: str) -> CheckResult:
    """The selector list could not be loaded: same verdict as the runner gives on the API."""
    return CheckResult.build(
        check_id=DkimCheck.id,
        target=domain,
        findings=[finding("CHECK_INTERNAL_ERROR", "medium", remediation=False)],
        evaluated=False,
        started_at=ctx.clock(),
        duration_ms=0,
        data={"enumerable": False, "probed": 0, "found": 0, "selectors": []},
    )


async def dkim_events(
    ctx: CheckContext,
    domain: str,
    lang: str,
    *,
    selectors: Sequence[str] | None = None,
    dropped: int = 0,
    providers: Mapping[str, str] | None = None,
    deadline_s: float = STREAM_DEADLINE_S,
    on_result: Callable[[CheckResult], None] | None = None,
) -> AsyncIterator[str]:
    """SSE frames for one probe run. Closing this generator closes the probe. A seed file that
    cannot be read still ends with a `done` event, status `error`. `providers` None: the seed's."""
    try:
        names = (
            tuple(selectors) if selectors is not None else tuple(s.name for s in list_selectors())
        )
        known = dict(providers) if providers is not None else seed_providers()
    except KnowledgeError:
        log.warning("dkim selector seed unreadable", extra={"event": "checks.dkim.seed_unreadable"})
        failed = _not_evaluated(ctx, domain)
        if on_result is not None:
            on_result(failed)
        yield _done_frame(lang, failed, complete=False, deadline=False)
        return
    results: list[SelectorResult] = []
    complete = True
    started = ctx.clock()
    t0 = time.monotonic()
    # `probe_selectors` is an async generator; it is typed as an iterator, we need `aclose`.
    probe = cast("AsyncGenerator[SelectorResult, None]", probe_selectors(ctx, domain, names, known))
    try:
        deadline = asyncio.get_running_loop().time() + deadline_s
        while True:
            try:
                # Only the wait for the next selector is bounded; the yield below is outside
                # any timeout scope, so a slow consumer can never lose the `done` event.
                async with asyncio.timeout_at(deadline):
                    res = await anext(probe)
            except StopAsyncIteration:
                break
            except TimeoutError:
                complete = False
                await probe.aclose()
                break
            results.append(res)
            yield sse("selector", _render(lang, kind="row", row=_row(res)))
        result = summarize(
            domain,
            results,
            names,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
            complete=complete,
            dropped=dropped,
        )
        if on_result is not None:
            on_result(result)
        yield _done_frame(lang, result, complete=complete and not dropped, deadline=not complete)
    finally:
        await probe.aclose()


def _response(request: Request, resolver: Resolver, target: _Target) -> StreamingResponse:
    ctx = CheckContext(
        resolver=resolver,
        tenant_id=None if target.tenant_id is None else str(target.tenant_id),
        domain_id=None if target.domain_id is None else str(target.domain_id),
    )
    events = dkim_events(
        ctx,
        target.domain,
        request_language(request.scope),
        selectors=target.probe.names,
        dropped=target.probe.dropped,
        providers=target.probe.providers,
    )
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
