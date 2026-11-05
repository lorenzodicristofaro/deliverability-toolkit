"""DNS tools web UI (M2-13): `/tools/dns` shell, lookup and reverse (server-rendered, no JS).

Routes: GET `/tools/dns` (both forms), POST `/tools/dns/lookup`, POST `/tools/dns/reverse`
(each re-renders the page with the result). Same access rules as the M2-12 API, with the web
conventions of M1-19: anonymous GET -> 303 /login, anonymous POST -> 401 (after the CSRF
middleware); no active tenant -> 404 page; a principal without `dns.tools` (client viewers) ->
403 denied page. The nav link is rendered only when the principal holds the permission.

Every `ResultState` has its own translated label; a failure is rendered as "could not be
evaluated" with its reason code and never as an empty/absent result. All DNS data is
autoescaped by Jinja and additionally made visible-safe by `visible` (control characters are
shown as `\\xNN` / `\\uNNNN` escapes). Long values wrap (CSS), nothing is truncated. Invalid input
shows a translated key, never the validator text or the offending value.
"""

from __future__ import annotations

import asyncio
import unicodedata
from dataclasses import dataclass
from typing import Final

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

from app.api.v1.dns_tools import REQUEST_DEADLINE_S, Backend
from app.core.domain_names import InvalidDomainName, to_dns_name
from app.core.permissions import Action, Principal, TenantResource, can
from app.dns.knowledge import list_public_resolvers
from app.dns.trace import DEFAULT_LIMITS, TraceReport, trace
from app.dns.types import ALLOWED_RDTYPES, DnsQuestion
from app.services.dns_propagation import PropagationReport, check_propagation
from app.services.dns_tools import (
    ALL_TYPES,
    InvalidLookupInput,
    LookupReport,
    ReverseReport,
    lookup,
    reverse,
)
from app.web.deps import CurrentSession, tenant_ctx
from app.web.domains import clean_field
from app.web.templating import env, read_form, render

router = APIRouter(prefix="/tools/dns")

_CONTROL: Final = frozenset({"Cc", "Cs", "Cf", "Co", "Cn", "Zl", "Zp"})


def dns_tools_allowed(principal: Principal, tenant_id: int | None) -> bool:
    return tenant_id is not None and can(principal, Action.DNS_TOOLS, TenantResource(tenant_id))


def visible(value: object) -> str:
    """`value` with control/format/unassigned characters replaced by visible escapes."""
    out: list[str] = []
    for ch in str(value):
        if unicodedata.category(ch) in _CONTROL:
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


env.filters["visible"] = visible


@dataclass(frozen=True, slots=True)
class ResolverChoice:
    selector: str
    label: str
    unverified: bool


def resolver_choices() -> list[ResolverChoice]:
    return [
        ResolverChoice(f"public:{r.id}", r.name, r.status != "verified")
        for r in list_public_resolvers()
    ]


def _page(
    request: Request,
    *,
    status_code: int = 200,
    lookup_report: LookupReport | None = None,
    reverse_report: ReverseReport | None = None,
    deadline: str | None = None,
    error: str | None = None,
    error_form: str | None = None,
    values: dict[str, str] | None = None,
) -> HTMLResponse:
    return render(
        request,
        "dns/index.html",
        status_code=status_code,
        logged_in=True,
        types=sorted(ALLOWED_RDTYPES),
        resolvers=resolver_choices(),
        lookup_report=lookup_report,
        reverse_report=reverse_report,
        deadline=deadline,
        error=error,
        error_form=error_form,
        values=values or {},
    )


def _guard(request: Request, auth: CurrentSession) -> Response | None:
    """None if allowed; the 403 page for a principal without `dns.tools`; 404 (via tenant_ctx)
    without a valid active tenant."""
    ctx = tenant_ctx(auth)
    if not dns_tools_allowed(auth.principal, ctx.tenant_id):
        return render(request, "dns/denied.html", status_code=403, logged_in=True)
    return None


def _values(form: dict[str, list[str]]) -> dict[str, str] | None:
    """Cleaned values of the known fields, or None if any is repeated/over-long/has controls."""
    out: dict[str, str] = {}
    for field in ("name", "ip", "type", "resolver"):
        if field in form:
            value = clean_field(form, field)
            if value is None:
                return None
            out[field] = value
    out["no_cache"] = "1" if "no_cache" in form else ""
    return out


def _error_key(exc: InvalidLookupInput) -> str:
    if exc.field == "name":
        return "tools.dns.invalid_name"
    if exc.field == "ip":
        return "tools.dns.invalid_ip"
    return "api.error.invalid_request"


@router.get("", include_in_schema=False)
def dns_index(request: Request, auth: CurrentSession) -> Response:
    denied = _guard(request, auth)
    if denied is not None:
        return denied
    return _page(request, values={"type": ALL_TYPES, "resolver": "default"})


@router.post("/lookup", include_in_schema=False)
async def dns_lookup_form(request: Request, auth: CurrentSession, backend: Backend) -> Response:
    denied = _guard(request, auth)  # permission first: 403 whatever the body contains
    if denied is not None:
        return denied
    form = await read_form(request)
    if form is None:
        return Response(status_code=413)
    values = _values(form)
    if values is None or "name" not in values:
        return _page(
            request, status_code=422, error="api.error.invalid_request", error_form="lookup"
        )
    try:
        async with asyncio.timeout(REQUEST_DEADLINE_S):
            report = await lookup(
                values["name"],
                values.get("type", ALL_TYPES),
                values.get("resolver", "default"),
                resolvers=backend.lookup,
                bypass_cache=bool(values["no_cache"]),
            )
    except InvalidLookupInput as exc:
        return _page(
            request, status_code=422, error=_error_key(exc), error_form="lookup", values=values
        )
    except TimeoutError:
        return _page(request, deadline="lookup", values=values)
    return _page(request, lookup_report=report, values=values)


@router.post("/reverse", include_in_schema=False)
async def dns_reverse_form(request: Request, auth: CurrentSession, backend: Backend) -> Response:
    denied = _guard(request, auth)
    if denied is not None:
        return denied
    form = await read_form(request)
    if form is None:
        return Response(status_code=413)
    values = _values(form)
    if values is None or "ip" not in values:
        return _page(
            request, status_code=422, error="api.error.invalid_request", error_form="reverse"
        )
    try:
        async with asyncio.timeout(REQUEST_DEADLINE_S):
            report = await reverse(
                values["ip"],
                values.get("resolver", "default"),
                resolvers=backend.lookup,
                bypass_cache=bool(values["no_cache"]),
                forward_confirm=True,
            )
    except InvalidLookupInput as exc:
        return _page(
            request, status_code=422, error=_error_key(exc), error_form="reverse", values=values
        )
    except TimeoutError:
        return _page(request, deadline="reverse", values=values)
    return _page(request, reverse_report=report, values=values)


# --- trace and propagation (M2-14) --------------------------------------------------------------

_MAX_RESOLVER_IDS = 8  # same cap as the service; more is rejected there as well


def _tool_page(
    request: Request,
    template: str,
    *,
    status_code: int = 200,
    error: str | None = None,
    deadline: bool = False,
    values: dict[str, str] | None = None,
    selected: tuple[str, ...] = (),
    **extra: object,
) -> HTMLResponse:
    return render(
        request,
        template,
        status_code=status_code,
        logged_in=True,
        types=sorted(ALLOWED_RDTYPES),
        error=error,
        deadline=deadline,
        values=values or {},
        selected=selected,
        **extra,
    )


def _name_type(form: dict[str, list[str]]) -> dict[str, str] | None:
    out: dict[str, str] = {}
    for field in ("name", "type"):
        if field in form:
            value = clean_field(form, field)
            if value is None:
                return None
            out[field] = value
    return out


def _resolver_ids(form: dict[str, list[str]]) -> tuple[str, ...] | None:
    """The checked resolver ids; None if any is over-long, has controls or there are too many."""
    raw = form.get("resolver_ids", [])
    if len(raw) > _MAX_RESOLVER_IDS:
        return None
    out: list[str] = []
    for item in raw:
        value = clean_field({"x": [item]}, "x")
        if value is None or len(value) > 64:
            return None
        out.append(value)
    return tuple(out)


@router.get("/trace", include_in_schema=False)
def dns_trace_page(request: Request, auth: CurrentSession) -> Response:
    denied = _guard(request, auth)
    if denied is not None:
        return denied
    return _tool_page(request, "dns/trace.html", values={"type": "A"})


@router.post("/trace", include_in_schema=False)
async def dns_trace_form(request: Request, auth: CurrentSession, backend: Backend) -> Response:
    denied = _guard(request, auth)
    if denied is not None:
        return denied
    form = await read_form(request)
    if form is None:
        return Response(status_code=413)
    values = _name_type(form)
    if values is None or "name" not in values:
        return _tool_page(
            request, "dns/trace.html", status_code=422, error="api.error.invalid_request"
        )
    report: TraceReport
    try:
        name = to_dns_name(values["name"])
        rdtype = values.get("type", "A").strip().upper()
        if rdtype not in ALLOWED_RDTYPES:
            raise InvalidLookupInput("rdtype", "not_allowed")
        async with asyncio.timeout(REQUEST_DEADLINE_S):
            report = await trace(
                DnsQuestion(name, rdtype),
                query_server=backend.query_server,
                root_hints=backend.root_hints,
                policy=backend.policy,
                limits=DEFAULT_LIMITS,
                resolver=backend.default,
            )
    except InvalidDomainName:
        return _tool_page(
            request,
            "dns/trace.html",
            status_code=422,
            error="tools.dns.invalid_name",
            values=values,
        )
    except InvalidLookupInput as exc:
        return _tool_page(
            request, "dns/trace.html", status_code=422, error=_error_key(exc), values=values
        )
    except TimeoutError:
        return _tool_page(request, "dns/trace.html", deadline=True, values=values)
    return _tool_page(request, "dns/trace.html", report=report, values=values)


def _propagation_page(request: Request, **kw: object) -> HTMLResponse:
    catalog = {r.id: r for r in list_public_resolvers()}
    return _tool_page(request, "dns/propagation.html", catalog=catalog, **kw)  # type: ignore[arg-type]


@router.get("/propagation", include_in_schema=False)
def dns_propagation_page(request: Request, auth: CurrentSession) -> Response:
    denied = _guard(request, auth)
    if denied is not None:
        return denied
    return _propagation_page(request, values={"type": "A"})


@router.post("/propagation", include_in_schema=False)
async def dns_propagation_form(
    request: Request, auth: CurrentSession, backend: Backend
) -> Response:
    denied = _guard(request, auth)
    if denied is not None:
        return denied
    form = await read_form(request)
    if form is None:
        return Response(status_code=413)
    values = _name_type(form)
    ids = _resolver_ids(form)
    if values is None or ids is None or "name" not in values:
        return _propagation_page(request, status_code=422, error="api.error.invalid_request")
    report: PropagationReport
    try:
        async with asyncio.timeout(REQUEST_DEADLINE_S):
            report = await check_propagation(
                values["name"],
                values.get("type", "A"),
                list(ids) if ids else None,  # none checked: every verified public resolver
                default_resolver=backend.default,
                address_factory=backend.address_factory,
            )
    except InvalidLookupInput as exc:
        return _propagation_page(
            request, status_code=422, error=_error_key(exc), values=values, selected=ids
        )
    except TimeoutError:
        return _propagation_page(request, deadline=True, values=values, selected=ids)
    return _propagation_page(request, report=report, values=values, selected=ids)
