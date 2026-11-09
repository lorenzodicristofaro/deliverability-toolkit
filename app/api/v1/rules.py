"""`/api/v1/rules`: administration of content rules (M5-18).

`?scope=tenant` (default) addresses the active tenant's path, `?scope=global` the global rows; the
rules and semantics are in `app.services.content_rules_admin`. The request never names a tenant.

Status codes (401, 403, 404, 409, 413 and 415 bodies are `{"detail": <i18n>}`):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 403 the principal lacks the permission for that scope, or a tenant-path write to a global rule;
- 404 no active tenant on the tenant path, or a rule that is missing/foreign/malformed id;
- 409 duplicate seed_key, or deleting a seeded global rule (disable it instead);
- 413 body over MAX_BODY_BYTES; 415 not `application/json`;
- 422 `{key, message, field, reason}`, never echoing the rejected value;
- `POST /test` answers 200 with an `outcome`, including `timed_out`, `busy`, `error` and `invalid`.

Permission (and, on an item, visibility) is decided before the body is read or parsed, so a denied
caller gets 403/404 whatever it sent. Dependencies are solved in parameter order: `ManageScope`
must stay before `Body`. `/test` can block for seconds, so it releases the database connection
and runs in a worker thread.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.v1._common import Body, RawBody, _error, _no_constant, _no_duplicate_keys, _raw_body
from app.api.v1.domains import _MAX_OFFSET, _page_value
from app.core.i18n import t
from app.core.permissions import RuleScope
from app.core.tenancy import TenantContext
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, parse_id
from app.repositories.content_rules import ContentRuleRecord
from app.services.content_rules_admin import (
    INVALID_FIELD_KEY,
    ContentRulesAdminService,
    RuleFieldInvalid,
    RulesAdminError,
    RuleTestOutcome,
)
from app.web.deps import CurrentSession, DbDep
from app.web.templating import request_language

router = APIRouter(prefix="/rules", tags=["rules"])


# --- errors -------------------------------------------------------------------------------------


def _problem(request: Request, key: str, field: str, reason: str) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "key": key,
            "message": t(key, request_language(request.scope)),
            "field": field,
            "reason": reason,
        },
    )


def _raise(request: Request, exc: RulesAdminError) -> NoReturn:
    if isinstance(exc, RuleFieldInvalid):
        raise _problem(request, exc.key, exc.field, exc.reason) from None
    raise _error(request, exc.status, exc.key) from None


# --- dependencies -------------------------------------------------------------------------------


def _service(db: DbDep, auth: CurrentSession) -> ContentRulesAdminService:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return ContentRulesAdminService(db, ctx, auth.principal)


Service = Annotated[ContentRulesAdminService, Depends(_service)]


def _scope(request: Request, _auth: Service, scope: str | None = None) -> RuleScope:
    """Authentication first (via `Service`), so an anonymous caller gets 401, not 422."""
    if scope is None:
        return RuleScope.TENANT
    if scope not in (RuleScope.TENANT.value, RuleScope.GLOBAL.value):
        raise _problem(request, INVALID_FIELD_KEY, "scope", "invalid_choice")
    return RuleScope(scope)


Scope = Annotated[RuleScope, Depends(_scope)]


def _manage(request: Request, service: Service, scope: Scope) -> RuleScope:
    try:
        service.check_manage(scope)
    except RulesAdminError as exc:
        _raise(request, exc)
    return scope


ManageScope = Annotated[RuleScope, Depends(_manage)]


def _json_object(request: Request, body: RawBody) -> dict[str, Any]:
    """Strict JSON (no duplicate keys, no NaN/Infinity). The field checks are the service's."""
    if not body.is_json:
        raise _error(request, 415, "api.error.invalid_request")
    try:
        data = json.loads(
            body.data.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_no_constant,
        )
    except (ValueError, RecursionError):  # includes UnicodeDecodeError and JSONDecodeError
        raise _problem(request, INVALID_FIELD_KEY, "body", "malformed_json") from None
    if not isinstance(data, dict):
        raise _problem(request, INVALID_FIELD_KEY, "body", "not_an_object")
    return data


# --- responses ----------------------------------------------------------------------------------


def _rule_json(record: ContentRuleRecord) -> dict[str, Any]:
    """The owning tenant and author stay out: a rule's reader needs neither."""
    return {
        "id": record.id,
        "scope": record.scope,
        "name": record.name,
        "kind": record.kind,
        "pattern": record.pattern,
        "flags": record.flags,
        "weight": record.weight,
        "category": record.category,
        "language": record.language,
        "enabled": record.enabled,
        "severity": record.severity,
        "title": record.title,
        "advice": record.advice,
        "sources": None if record.sources is None else list(record.sources),
        "verified_on": None if record.verified_on is None else record.verified_on.isoformat(),
        "status": record.status,
        "seed_key": record.seed_key,
        "locally_modified": record.locally_modified,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }


def _outcome_json(request: Request, outcome: RuleTestOutcome) -> dict[str, Any]:
    return {
        "outcome": outcome.status.value,
        "timed_out": outcome.timed_out,
        "truncated": outcome.truncated,
        "matches": [
            {"start": m.start, "end": m.end, "snippet": m.snippet} for m in outcome.matches
        ],
        "reason": outcome.reason,
        "key": outcome.key,
        "message": None if outcome.key is None else t(outcome.key, request_language(request.scope)),
    }


# --- routes -------------------------------------------------------------------------------------


@router.get("")
def list_rules(
    request: Request,
    service: Service,
    scope: Scope,
    limit: str | None = None,
    offset: str | None = None,
) -> dict[str, Any]:
    page_limit = _page_value(request, limit, DEFAULT_LIMIT, MAX_LIMIT)
    page_offset = _page_value(request, offset, 0, _MAX_OFFSET)
    try:
        records = service.list_rules(scope, limit=page_limit, offset=page_offset)
    except RulesAdminError as exc:
        _raise(request, exc)
    return {"items": [_rule_json(r) for r in records]}


@router.post("", status_code=201)
def create_rule(
    request: Request, scope: ManageScope, service: Service, body: Body
) -> dict[str, Any]:
    data = _json_object(request, body)
    try:
        return _rule_json(service.create(scope, data))
    except RulesAdminError as exc:
        _raise(request, exc)


# Declared before the `{rule_id}` routes so "test" is never read as an id.
@router.post("/test")
async def test_rule(
    request: Request, scope: ManageScope, service: Service, db: DbDep
) -> dict[str, Any]:
    # The auth dependency left a transaction open: end it so no pooled connection is held through
    # the body read and the search. The service keeps plain values only, and this path never
    # queries the database again.
    db.rollback()
    data = _json_object(request, await _raw_body(request))
    try:
        outcome = await run_in_threadpool(service.test_pattern, scope, data)
    except RulesAdminError as exc:
        _raise(request, exc)
    return _outcome_json(request, outcome)


@router.get("/{rule_id}")
def get_rule(request: Request, service: Service, scope: Scope, rule_id: str) -> dict[str, Any]:
    try:
        return _rule_json(service.get_rule(scope, parse_id(rule_id)))
    except RulesAdminError as exc:
        _raise(request, exc)


@router.patch("/{rule_id}")
def update_rule(
    request: Request, scope: ManageScope, service: Service, body: Body, rule_id: str
) -> dict[str, Any]:
    target = parse_id(rule_id)
    try:
        service.check_write(scope, target)
        return _rule_json(service.update(scope, target, _json_object(request, body)))
    except RulesAdminError as exc:
        _raise(request, exc)


@router.delete("/{rule_id}", status_code=204)
def delete_rule(request: Request, scope: ManageScope, service: Service, rule_id: str) -> Response:
    try:
        service.delete(scope, parse_id(rule_id))
    except RulesAdminError as exc:
        _raise(request, exc)
    return Response(status_code=204)
