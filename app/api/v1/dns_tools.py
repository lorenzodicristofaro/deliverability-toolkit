"""`/api/v1/dns`: raw DNS tools of the session's active tenant (M2-12).

Endpoints (all POST with a JSON body, so the CSRF rules are those of `/api/v1/domains`):
`/lookup`, `/reverse`, `/trace`, `/propagation`.

Status codes (bodies are `{"detail": ...}`, never echoing user input):
- 401 anonymous (mutating requests first need a valid CSRF token, else the middleware answers 403);
- 404 no active tenant (a stale or foreign active tenant included);
- 403 the principal lacks `dns.tools` in the active tenant (client viewers, whatever toggles say);
- 413 body over MAX_BODY_BYTES; 415 not `application/json`;
- 422 malformed body or invalid input: `detail` is an object `{key, message, field, reason}` where
  `field` and `reason` are stable codes (from the validator), never the offending value;
- 200 whenever the query ran: a DNS failure (servfail, timeout, blocked, ...) is DATA in the body.
  Every result carries its `state` (a `ResultState` value) and an `evaluated` flag; a failure is
  never reported as absent or empty. If the per-request deadline expires the answer is still 200
  with `state: "timeout"`, `evaluated: false` and `detail_code: "request_deadline"`.

Resolvers are chosen by id only (`default` or `public:<id>` from the data file); the resolver
used comes from the `dns_backend` dependency (tests override it with fakes; no network).
Caps: body size, 8 public resolvers / 16 addresses for propagation, the service concurrency caps,
and `REQUEST_DEADLINE_S` for the whole request. No per-user rate limiting exists yet.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Sequence
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from app.api.v1._common import Body, _error, _parse, _Strict
from app.core.config import ResolverAddr
from app.core.domain_names import InvalidDomainName, to_dns_name
from app.core.i18n import t
from app.core.permissions import Action, TenantResource, can
from app.core.tenancy import TenantContext
from app.dns.cache import CachingResolver
from app.dns.egress import DEFAULT_POLICY
from app.dns.factory import build_resolver, build_resolver_for_target
from app.dns.knowledge import PublicResolver, RootHints, RootServer, root_hints
from app.dns.trace import (
    DEFAULT_LIMITS,
    AddressPolicy,
    HopKind,
    QueryServer,
    TraceHop,
    TraceOutcome,
    TraceReport,
    query_server_for,
    trace,
)
from app.dns.types import ALLOWED_RDTYPES, DnsQuestion, DnsRecord, Resolver, ResultState
from app.services.dns_propagation import (
    MAX_RESOLVERS,
    AddressFactory,
    PropagationReport,
    PropagationRow,
    Verdict,
    check_propagation,
)
from app.services.dns_tools import (
    FcrdnsState,
    InvalidLookupInput,
    LookupReport,
    LookupResolvers,
    ReverseReport,
    TypeResult,
    lookup,
    reverse,
)
from app.web.deps import CurrentSession, SettingsDep, tenant_ctx
from app.web.templating import request_language

router = APIRouter(prefix="/dns", tags=["dns-tools"])

REQUEST_DEADLINE_S = 20.0  # whole request; above the trace (15 s) and propagation (10 s) budgets
MAX_RESOLVER_ID_LEN = 64
MAX_NAME_LEN = 1024  # raw input; the validator enforces the real DNS limits
_UNLIMITED_FIELD = "body"


# --- backend (dependency) -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DnsBackend:
    """Everything the tools need from the network layer; tests replace it with fakes."""

    lookup: LookupResolvers
    address_factory: AddressFactory
    query_server: QueryServer
    root_hints: RootHints | Sequence[RootServer]
    policy: AddressPolicy

    @property
    def default(self) -> Resolver:
        return self.lookup.default


_backend_lock = threading.Lock()


def _public_address(entry: PublicResolver, address: str) -> Resolver:
    # Untrusted target: the egress policy runs in the factory (a rejected one answers `blocked`).
    return build_resolver_for_target(ResolverAddr(address, entry.port))


def dns_backend(request: Request, settings: SettingsDep) -> DnsBackend:
    """The production backend, built once from Settings and cached on `app.state`."""
    state = request.app.state
    backend = getattr(state, "dns_backend", None)
    if backend is None:
        with _backend_lock:
            backend = getattr(state, "dns_backend", None)
            if backend is None:
                inner = build_resolver(settings)
                backend = DnsBackend(
                    lookup=LookupResolvers(CachingResolver(inner)),
                    address_factory=_public_address,
                    query_server=query_server_for(inner),
                    root_hints=root_hints(),
                    policy=DEFAULT_POLICY,
                )
                state.dns_backend = backend
    assert isinstance(backend, DnsBackend)
    return backend


Backend = Annotated[DnsBackend, Depends(dns_backend)]


# --- access -------------------------------------------------------------------------------------


def _access(request: Request, auth: CurrentSession) -> TenantContext:
    """401 anonymous (via current_session), 404 no active tenant, 403 without `dns.tools`."""
    try:
        ctx = tenant_ctx(auth)
    except HTTPException:
        raise _error(request, 404, "api.error.not_found") from None
    if not can(auth.principal, Action.DNS_TOOLS, TenantResource(ctx.tenant_id)):
        raise _error(request, 403, "api.error.forbidden")
    return ctx


Access = Annotated[TenantContext, Depends(_access)]


# --- payloads -----------------------------------------------------------------------------------

_Name = Annotated[StrictStr, Field(max_length=MAX_NAME_LEN)]
_Selector = Annotated[StrictStr, Field(max_length=MAX_RESOLVER_ID_LEN)]
_Type = Annotated[StrictStr, Field(max_length=16)]


class LookupIn(_Strict):
    name: _Name
    type: _Type = "ALL"  # a record type or "all"
    resolver: _Selector = "default"
    no_cache: StrictBool = False


class ReverseIn(_Strict):
    ip: Annotated[StrictStr, Field(max_length=128)]
    resolver: _Selector = "default"
    no_cache: StrictBool = False
    forward_confirm: StrictBool = True


class TraceIn(_Strict):
    name: _Name
    type: _Type


class PropagationIn(_Strict):
    name: _Name
    type: _Type
    # None: every verified public resolver. Ids from the data file only (no free-form IPs).
    resolver_ids: (
        Annotated[
            list[Annotated[StrictStr, Field(max_length=MAX_RESOLVER_ID_LEN)]],
            Field(max_length=MAX_RESOLVERS),
        ]
        | None
    ) = None


def _invalid(request: Request, field: str, reason: str) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "key": "api.error.invalid_request",
            "message": t("api.error.invalid_request", request_language(request.scope)),
            "field": field,
            "reason": reason,
        },
    )


def _payload[M: _Strict](request: Request, model: type[M], body: Any) -> M:
    """Strict parse of the body. 415 stays as in the domains API; a body that fails validation
    is 422 with field `body` and reason `invalid_body` (the reason never echoes the input)."""
    try:
        return _parse(request, model, body)
    except HTTPException as exc:
        if exc.status_code == 422:
            raise _invalid(request, _UNLIMITED_FIELD, "invalid_body") from None
        raise


# --- JSON shapes --------------------------------------------------------------------------------


def _round(ms: float) -> float:
    return round(ms, 1)


def _record_json(r: DnsRecord) -> dict[str, Any]:
    return {"name": r.name, "rdtype": r.rdtype, "ttl": r.ttl, "rdata": r.rdata_text}


def _type_result_json(r: TypeResult) -> dict[str, Any]:
    return {
        "rdtype": r.rdtype,
        "state": r.state.value,
        "evaluated": r.evaluated,
        "records": [_record_json(x) for x in r.records],
        "ttl_min": r.ttl_min,
        "authenticated_data": r.authenticated_data,
        "elapsed_ms": _round(r.elapsed_ms),
        "server": r.server,
        "detail_code": r.detail_code,
    }


def _lookup_json(r: LookupReport) -> dict[str, Any]:
    return {
        "name": r.name,
        "resolver": r.resolver_selector,
        "resolver_identity": r.resolver_identity,
        "results": [_type_result_json(x) for x in r.results],
        "summary": {
            "evaluated": r.summary.evaluated,
            "found": list(r.summary.found),
            "absent": list(r.summary.absent),
            "failed": list(r.summary.failed),
        },
        "authenticated_data": r.authenticated_data,
        "elapsed_ms": _round(r.elapsed_ms),
    }


def _reverse_json(r: ReverseReport) -> dict[str, Any]:
    return {
        "ip": r.ip,
        "ptr_name": r.ptr_name,
        "resolver": r.resolver_selector,
        "resolver_identity": r.resolver_identity,
        "ptr": _type_result_json(r.ptr),
        "fcrdns": r.fcrdns.value,
        "forward": [
            {
                "ptr_name": f.ptr_name,
                "results": [_type_result_json(x) for x in f.results],
                "matches": f.matches,
            }
            for f in r.forward
        ],
        "detail_code": r.detail_code,
        "evaluated": r.evaluated,
        "elapsed_ms": _round(r.elapsed_ms),
    }


def _hop_json(h: TraceHop) -> dict[str, Any]:
    return {
        "kind": h.kind.value,
        "zone": h.zone,
        "name": h.question.name,
        "rdtype": h.question.rdtype,
        "state": h.state.value,
        "evaluated": not h.state.is_failure,
        "server_name": h.server_name,
        "server_addr": h.server_addr,
        "rcode": h.rcode,
        "detail_code": h.detail_code,
        "referral_zone": h.referral_zone,
        "referral_ns": list(h.referral_ns),
        "records": [_record_json(x) for x in h.records],
        "authenticated_data": h.authenticated_data,
        "elapsed_ms": _round(h.elapsed_ms),
    }


def _trace_json(r: TraceReport) -> dict[str, Any]:
    state = r.outcome.state
    return {
        "name": r.question.name,
        "rdtype": r.question.rdtype,
        "outcome": r.outcome.value,
        "state": state.value,
        "evaluated": not state.is_failure,
        "hops": [_hop_json(h) for h in r.hops],
        "answer": [_record_json(x) for x in r.answer],
        "final_zone": r.final_zone,
        "final_server": r.final_server,
        "queries_sent": r.queries_sent,
        "elapsed_ms": _round(r.elapsed_ms),
        "detail_code": r.detail_code,
        "cname_chain": [_record_json(x) for x in r.cname_chain],
        "cname_target": r.cname_target,
    }


def _row_json(r: PropagationRow) -> dict[str, Any]:
    return {
        "resolver": r.resolver_id,
        "address": r.address,
        "unverified": r.unverified,
        "state": r.state.value,
        "evaluated": r.evaluated,
        "records": [
            {"name": n, "rdtype": ty, "ttl": ttl, "rdata": rd} for n, ty, rd, ttl in r.records
        ],
        "ttl_min": r.ttl_min,
        "group": r.group,
        "elapsed_ms": _round(r.elapsed_ms),
        "detail_code": r.detail_code,
    }


def _propagation_json(r: PropagationReport) -> dict[str, Any]:
    return {
        "name": r.name,
        "rdtype": r.rdtype,
        "verdict": r.verdict.value,
        "evaluated": r.not_evaluated_count == 0,
        "rows": [_row_json(x) for x in r.rows],
        "groups": [
            {
                "index": g.index,
                "state": g.state.value,
                "rdata": [{"name": n, "rdtype": ty, "rdata": rd} for n, ty, rd in g.rdata],
                "members": list(g.members),
            }
            for g in r.groups
        ],
        "evaluated_count": r.evaluated_count,
        "not_evaluated_count": r.not_evaluated_count,
        "min_evaluated": r.min_evaluated,
        "includes_unverified": r.includes_unverified,
        "elapsed_ms": _round(r.elapsed_ms),
    }


def _deadline_json() -> dict[str, Any]:
    """The whole request ran out of time: not evaluated, never "empty"."""
    return {
        "state": ResultState.timeout.value,
        "evaluated": False,
        "detail_code": "request_deadline",
    }


async def _run(request: Request, work: Awaitable[dict[str, Any]]) -> dict[str, Any]:
    """Run the tool under the request deadline; invalid input becomes a 422 with codes only."""
    try:
        async with asyncio.timeout(REQUEST_DEADLINE_S):
            return await work
    except InvalidLookupInput as exc:
        raise _invalid(request, exc.field, exc.reason) from None
    except TimeoutError:
        return _deadline_json()


# --- response models (OpenAPI schemas; every ResultState is part of the contract) ---------------


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RecordOut(_Out):
    name: str
    rdtype: str
    ttl: int
    rdata: str


class TypeResultOut(_Out):
    rdtype: str
    state: ResultState
    evaluated: bool  # False for every failure state
    records: list[RecordOut]
    ttl_min: int | None
    authenticated_data: bool
    elapsed_ms: float
    server: str | None
    detail_code: str | None


class LookupSummaryOut(_Out):
    evaluated: bool
    found: list[str]
    absent: list[str]
    failed: list[str]


class LookupOut(_Out):
    name: str
    resolver: str
    resolver_identity: str
    results: list[TypeResultOut]
    summary: LookupSummaryOut
    authenticated_data: bool
    elapsed_ms: float


class ForwardCheckOut(_Out):
    ptr_name: str
    results: list[TypeResultOut]
    matches: bool | None  # None: could not be evaluated


class ReverseOut(_Out):
    ip: str
    ptr_name: str
    resolver: str
    resolver_identity: str
    ptr: TypeResultOut
    fcrdns: FcrdnsState
    forward: list[ForwardCheckOut]
    detail_code: str | None
    evaluated: bool
    elapsed_ms: float


class HopOut(_Out):
    kind: HopKind
    zone: str
    name: str
    rdtype: str
    state: ResultState
    evaluated: bool
    server_name: str | None
    server_addr: str | None
    rcode: int | None
    detail_code: str | None
    referral_zone: str | None
    referral_ns: list[str]
    records: list[RecordOut]
    authenticated_data: bool
    elapsed_ms: float


class TraceOut(_Out):
    name: str
    rdtype: str
    outcome: TraceOutcome
    state: ResultState  # ok (outcomes ok and cname)/nxdomain/nodata, else error
    evaluated: bool
    hops: list[HopOut]
    answer: list[RecordOut]
    final_zone: str | None
    final_server: str | None
    queries_sent: int
    elapsed_ms: float
    detail_code: str | None
    # R1-07, additive: outcome ``cname`` only, else [] / null. The CNAME records at the query
    # name, in chain order, and the last target (reported, never followed by the trace).
    cname_chain: list[RecordOut]
    cname_target: str | None


class PropagationRowOut(_Out):
    resolver: str
    address: str | None
    unverified: bool
    state: ResultState
    evaluated: bool
    records: list[RecordOut]
    ttl_min: int | None
    group: int | None
    elapsed_ms: float
    detail_code: str | None


class GroupRecordOut(_Out):
    name: str
    rdtype: str
    rdata: str


class AnswerGroupOut(_Out):
    index: int
    state: ResultState
    rdata: list[GroupRecordOut]
    members: list[int]


class PropagationOut(_Out):
    name: str
    rdtype: str
    verdict: Verdict
    evaluated: bool
    rows: list[PropagationRowOut]
    groups: list[AnswerGroupOut]
    evaluated_count: int
    not_evaluated_count: int
    min_evaluated: int
    includes_unverified: bool
    elapsed_ms: float


class DeadlineOut(_Out):
    """The whole request ran out of time: not evaluated."""

    state: ResultState
    evaluated: bool
    detail_code: str


class InvalidRequestDetail(_Out):
    key: str
    message: str
    field: str
    reason: str


class InvalidRequestOut(_Out):
    detail: InvalidRequestDetail


_ERRORS: dict[int | str, dict[str, Any]] = {
    422: {"model": InvalidRequestOut, "description": "Invalid input: codes only, no echo"},
}


# --- OpenAPI request bodies ---------------------------------------------------------------------
# Bodies are read and validated by `_payload` (strict JSON, no echo), not by FastAPI, so the
# handlers declare no body parameter; the request schema is documented through `openapi_extra`
# (generated from the same strict model, inline: FastAPI only registers components for models it
# parses itself).


def _body_doc(model: type[_Strict]) -> dict[str, Any]:
    schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
    return {"requestBody": {"required": True, "content": {"application/json": {"schema": schema}}}}


# --- routes -------------------------------------------------------------------------------------


@router.post(
    "/lookup",
    response_model=LookupOut | DeadlineOut,
    responses=_ERRORS,
    openapi_extra=_body_doc(LookupIn),
)
async def dns_lookup(
    request: Request, _ctx: Access, backend: Backend, body: Body
) -> dict[str, Any]:
    payload = _payload(request, LookupIn, body)

    async def work() -> dict[str, Any]:
        report = await lookup(
            payload.name,
            payload.type,
            payload.resolver,
            resolvers=backend.lookup,
            bypass_cache=payload.no_cache,
        )
        return _lookup_json(report)

    return await _run(request, work())


@router.post(
    "/reverse",
    response_model=ReverseOut | DeadlineOut,
    responses=_ERRORS,
    openapi_extra=_body_doc(ReverseIn),
)
async def dns_reverse(
    request: Request, _ctx: Access, backend: Backend, body: Body
) -> dict[str, Any]:
    payload = _payload(request, ReverseIn, body)

    async def work() -> dict[str, Any]:
        report = await reverse(
            payload.ip,
            payload.resolver,
            resolvers=backend.lookup,
            bypass_cache=payload.no_cache,
            forward_confirm=payload.forward_confirm,
        )
        return _reverse_json(report)

    return await _run(request, work())


@router.post(
    "/trace",
    response_model=TraceOut | DeadlineOut,
    responses=_ERRORS,
    openapi_extra=_body_doc(TraceIn),
)
async def dns_trace(request: Request, _ctx: Access, backend: Backend, body: Body) -> dict[str, Any]:
    payload = _payload(request, TraceIn, body)

    async def work() -> dict[str, Any]:
        try:
            name = to_dns_name(payload.name)
        except InvalidDomainName as exc:
            raise InvalidLookupInput("name", exc.reason) from None
        rdtype = payload.type.strip().upper()
        if rdtype not in ALLOWED_RDTYPES:  # "all" makes no sense for a trace
            raise InvalidLookupInput("rdtype", "not_allowed")
        report = await trace(
            DnsQuestion(name, rdtype),
            query_server=backend.query_server,
            root_hints=backend.root_hints,
            policy=backend.policy,
            limits=DEFAULT_LIMITS,
            resolver=backend.default,
        )
        return _trace_json(report)

    return await _run(request, work())


@router.post(
    "/propagation",
    response_model=PropagationOut | DeadlineOut,
    responses=_ERRORS,
    openapi_extra=_body_doc(PropagationIn),
)
async def dns_propagation(
    request: Request, _ctx: Access, backend: Backend, body: Body
) -> dict[str, Any]:
    payload = _payload(request, PropagationIn, body)

    async def work() -> dict[str, Any]:
        report = await check_propagation(
            payload.name,
            payload.type,
            payload.resolver_ids,
            default_resolver=backend.default,
            address_factory=backend.address_factory,
        )
        return _propagation_json(report)

    return await _run(request, work())
