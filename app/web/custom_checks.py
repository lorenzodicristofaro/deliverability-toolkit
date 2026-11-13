"""Custom checks admin UI (M5-24): `/custom-checks`, list, create, edit, enable/disable, delete and
the "Test on domain" dry run.

Every operation goes through `CustomChecksAdminService` (M5-23), the same service as the REST API:
this module holds no repository and repeats no authorization. The scope is the `?scope=` query
(`tenant`, the default, or `global`), never a form field, so the permission is decided before the
body is read. A denied principal gets a 403 page (404 for a missing tenant, a foreign or malformed
check id) and the service is not reached with the body.

Routes (all need a session; anonymous GET -> 303 /login, anonymous POST -> 401):
- GET  /custom-checks                    list (tenant tab: own rows, then global rows read-only)
- GET  /custom-checks/new                create form
- POST /custom-checks                    create
- POST /custom-checks/test               dry run on a domain of the active tenant (`rules.read` and
                                         `check.run`); the result is shown under the form, nothing
                                         is stored; `?check=<id>` keeps the edit form's action
- GET  /custom-checks/{id}/edit          edit form
- POST /custom-checks/{id}/edit          update
- POST /custom-checks/{id}/toggle        enable / disable (`enabled=1|0`)
- POST /custom-checks/{id}/delete        delete

The form builds the definition from flat fields (kind, record type, name template, pattern or
min/max); the validation is the service's, so a posted `http_fetch` is refused there
(`kind_unavailable`, 422) although the select shows it disabled. The remediation key exists on the
global form only (the service refuses it on the tenant path). Bodies are urlencoded and
size-capped by `_read_capped`; NUL and lone surrogates are refused before the service and never
echoed. Everything derived from stored or posted values is autoescaped (no `|safe`) and shown
through `visible`, except the multi-line remediation text, which is only autoescaped. Every
response is `Cache-Control: no-store`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.v1.checks import ResolverDep
from app.checks.models import CheckContext, CheckResult
from app.checks.registry import CheckRegistry
from app.core.custom_check_schema import RRTYPES, SEVERITIES
from app.core.permissions import RuleScope
from app.core.tenancy import TenantContext
from app.models.custom_check import KINDS, RESERVED_KINDS
from app.repositories.base import MAX_LIMIT, parse_id
from app.repositories.custom_checks import CustomCheckRecord
from app.services.checks import run_check
from app.services.custom_checks_admin import (
    CheckKeyConflict,
    CustomCheckFieldInvalid,
    CustomChecksAdminError,
    CustomChecksAdminService,
    DryRun,
)
from app.services.domains import DomainService, DomainServiceError
from app.web.authentication import finding_params  # noqa: F401  registers the filter and test
from app.web.deps import AuthSession, CurrentSession, DbDep
from app.web.dns_tools import visible  # registers the `visible` filter
from app.web.templating import render

router = APIRouter(prefix="/custom-checks")

_NO_STORE: Final = {"Cache-Control": "no-store"}
_FORM_OVERHEAD_BYTES: Final = 4096
# Worst case of the text fields (4 bytes per character), percent-encoded (3x).
MAX_SAVE_BYTES: Final = 3 * 4 * 8000 + _FORM_OVERHEAD_BYTES
_MAX_FIELDS: Final = 30
PAGE_SIZE: Final = 200
_TEXT_FIELDS: Final = (
    "check_key",
    "name",
    "description",
    "kind",
    "rrtype",
    "name_template",
    "pattern",
    "min",
    "max",
    "severity",
    "remediation_en",
    "remediation_it",
    "remediation_key",
)
_DEFAULT_KIND: Final = "dns_exists"
SELECTABLE_KINDS: Final = tuple(k for k in KINDS if k not in RESERVED_KINDS)

_FLASH: Final = {
    "created": "web.custom_checks.flash.created",
    "updated": "web.custom_checks.flash.updated",
    "deleted": "web.custom_checks.flash.deleted",
    "enabled": "web.custom_checks.flash.enabled",
    "disabled": "web.custom_checks.flash.disabled",
}
_FIELD_LABELS: Final = {
    "check_key": "web.custom_checks.field.check_key",
    "name": "web.custom_checks.field.name",
    "description": "web.custom_checks.field.description",
    "kind": "web.custom_checks.field.kind",
    "definition": "web.custom_checks.field.definition",
    "definition.name": "web.custom_checks.field.name_template",
    "definition.rrtype": "web.custom_checks.field.rrtype",
    "definition.pattern": "web.custom_checks.field.pattern",
    "definition.min": "web.custom_checks.field.min",
    "definition.max": "web.custom_checks.field.max",
    "severity": "web.custom_checks.field.severity",
    "remediation": "web.custom_checks.field.remediation",
    "remediation_text": "web.custom_checks.field.remediation",
    "remediation_key": "web.custom_checks.field.remediation_key",
    "enabled": "web.custom_checks.field.enabled",
    "domain_id": "web.custom_checks.test.domain",
}
INVALID_FORM_KEY: Final = "web.custom_checks.error.invalid_form"
INVALID_CHARS_KEY: Final = "web.custom_checks.error.invalid_chars"
TOO_LARGE_KEY: Final = "web.custom_checks.error.too_large"
NO_DOMAIN_KEY: Final = "web.custom_checks.error.no_domain"

__all__ = ["MAX_SAVE_BYTES", "PAGE_SIZE", "router", "visible"]


# --- helpers ------------------------------------------------------------------------------------


def _ctx(auth: AuthSession) -> TenantContext | None:
    return (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )


def _service(db: Session, auth: AuthSession) -> CustomChecksAdminService:
    return CustomChecksAdminService(db, _ctx(auth), auth.principal)


def _parse_scope(value: str | None) -> RuleScope | None:
    if value is None:
        return RuleScope.TENANT
    if value in (RuleScope.TENANT.value, RuleScope.GLOBAL.value):
        return RuleScope(value)
    return None


def _parse_page(value: str | None) -> int | None:
    return 1 if value is None else parse_id(value)


def _respond(
    request: Request, template: str, status_code: int = 200, **context: Any
) -> HTMLResponse:
    response = render(request, template, status_code=status_code, logged_in=True, **context)
    response.headers.update(_NO_STORE)
    return response


def _not_found(request: Request) -> HTMLResponse:
    response = render(request, "errors/404.html", status_code=404, logged_in=True)
    response.headers.update(_NO_STORE)
    return response


def _failure(request: Request, exc: CustomChecksAdminError) -> Response:
    """404 (missing, foreign, malformed id or no tenant) or the 403 denied page; any other error
    is a bug and is raised."""
    if exc.status == 404:
        return _not_found(request)
    if exc.status == 403:
        return _respond(request, "custom_checks/denied.html", 403)
    raise exc


def _allowed(check: Callable[[RuleScope], None], scope: RuleScope) -> bool:
    try:
        check(scope)
    except CustomChecksAdminError:
        return False
    return True


def _redirect(scope: RuleScope, notice: str) -> Response:
    return RedirectResponse(f"/custom-checks?scope={scope.value}&notice={notice}", status_code=303)


class _BodyTooLarge(Exception):
    pass


async def _read_capped(request: Request, cap: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (
        not (declared.isascii() and declared.isdigit()) or int(declared) > cap
    ):
        raise _BodyTooLarge
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > cap:
            raise _BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def _form(body: bytes) -> dict[str, list[str]] | None:
    """The urlencoded fields, or None if the body is not valid UTF-8 or has too many fields."""
    try:
        return parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            max_num_fields=_MAX_FIELDS,
            errors="strict",
        )
    except (UnicodeDecodeError, ValueError):
        return None


def _single(form: dict[str, list[str]], name: str) -> str | None:
    """The one value of `name` ("" if absent); None if the field is repeated."""
    values = form.get(name, [""])
    return values[0] if len(values) == 1 else None


def _lf(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _bad_chars(value: str) -> bool:
    return "\x00" in value or any("\ud800" <= ch <= "\udfff" for ch in value)


@dataclass(frozen=True, slots=True)
class _Row:
    record: CustomCheckRecord
    can_edit: bool


def _number_text(value: Any) -> str:
    return "" if value is None else str(value)


def _form_values(record: CustomCheckRecord | None) -> dict[str, Any]:
    if record is None:
        return {
            "check_key": "",
            "name": "",
            "description": "",
            "kind": _DEFAULT_KIND,
            "rrtype": "TXT",
            "name_template": "{domain}",
            "pattern": "",
            "min": "",
            "max": "",
            "severity": "medium",
            "remediation_en": "",
            "remediation_it": "",
            "remediation_key": "",
            "enabled": True,
            "domain_id": "",
        }
    text = record.remediation_text.as_dict() if record.remediation_text is not None else {}
    definition = record.definition
    return {
        "check_key": record.check_key,
        "name": record.name,
        "description": record.description or "",
        "kind": record.kind,
        "rrtype": definition.get("rrtype", "TXT"),
        "name_template": definition.get("name", "{domain}"),
        "pattern": definition.get("pattern", ""),
        "min": _number_text(definition.get("min")),
        "max": _number_text(definition.get("max")),
        "severity": record.severity,
        "remediation_en": text.get("en", ""),
        "remediation_it": text.get("it", ""),
        "remediation_key": record.remediation_key or "",
        "enabled": record.enabled,
        "domain_id": "",
    }


def _field_error(exc: CustomCheckFieldInvalid) -> dict[str, str | None]:
    return {"key": exc.key, "field_label": _FIELD_LABELS.get(exc.field), "reason": exc.reason}


_NUMBER: Final = re.compile(r"-?\d{1,40}(\.\d{1,40})?([eE][+-]?\d{1,4})?")


def _to_number(text: str) -> int | float | str:
    """A JSON number from the text, or the text itself, so the service refuses it as
    `not_a_number` (a bool, NaN or anything else that is no plain number never gets here as one)."""
    stripped = text.strip()
    if _NUMBER.fullmatch(stripped):
        return json.loads(stripped)  # type: ignore[no-any-return]
    return stripped


def _definition(texts: dict[str, str]) -> dict[str, Any]:
    """The definition of the posted kind from the flat fields. A value that is not a number is
    passed through as text so the service refuses it (`not_a_number`); an unknown kind (including
    `http_fetch`) gets an empty definition and is refused on the kind first."""
    kind = texts["kind"]
    if kind not in SELECTABLE_KINDS:
        return {}
    definition: dict[str, Any] = {"name": texts["name_template"], "rrtype": texts["rrtype"]}
    if kind == "dns_matches":
        definition["pattern"] = texts["pattern"]
    elif kind == "dns_value_range":
        definition["min"] = _to_number(texts["min"])
        definition["max"] = _to_number(texts["max"])
    return definition


def _remediation_text(texts: dict[str, str]) -> dict[str, str] | None:
    if not texts["remediation_en"].strip() and not texts["remediation_it"].strip():
        return None
    return {"en": texts["remediation_en"], "it": texts["remediation_it"]}


def _save_data(
    form: dict[str, list[str]], scope: RuleScope, *, test: bool
) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    """(service data, echo values, error key). For a dry run the data is the test body without the
    domain. The data holds every field of the form."""
    echo = _form_values(None)
    texts: dict[str, str] = {}
    for name in _TEXT_FIELDS:
        value = _single(form, name)
        if value is None:
            return {}, echo, INVALID_FORM_KEY
        texts[name] = _lf(value)
    enabled = _single(form, "enabled")
    domain = _single(form, "domain_id")
    if enabled is None or domain is None:
        return {}, echo, INVALID_FORM_KEY
    if any(_bad_chars(v) for v in (*texts.values(), enabled, domain)):
        return {}, echo, INVALID_CHARS_KEY
    echo.update({**texts, "enabled": enabled == "1", "domain_id": domain})
    if test:
        data: dict[str, Any] = {
            "kind": texts["kind"],
            "definition": _definition(texts),
            "severity": texts["severity"],
        }
        remediation = _remediation_text(texts)
        if remediation is not None:
            data["remediation_text"] = remediation
        return data, echo, None
    data = {
        "check_key": texts["check_key"].strip(),
        "name": texts["name"].strip(),
        "description": texts["description"].strip() or None,
        "kind": texts["kind"],
        "definition": _definition(texts),
        "severity": texts["severity"],
        "remediation_text": _remediation_text(texts),
        "enabled": enabled == "1",
    }
    key = texts["remediation_key"].strip()
    if scope is RuleScope.GLOBAL or key:  # a tenant-path key is the service's to refuse
        data["remediation_key"] = key or None
    return data, echo, None


# --- list ---------------------------------------------------------------------------------------


def _all_records(service: CustomChecksAdminService, scope: RuleScope) -> list[CustomCheckRecord]:
    """Every row visible in `scope`, read in batches until a short one, so nothing is cut off."""
    records: list[CustomCheckRecord] = []
    while True:
        batch = service.list_checks(scope, limit=MAX_LIMIT, offset=len(records))
        records.extend(batch)
        if len(batch) < MAX_LIMIT:
            return records


def _list_page(
    request: Request,
    service: CustomChecksAdminService,
    scope: RuleScope,
    *,
    page: int = 1,
    status_code: int = 200,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    try:
        records = _all_records(service, scope)
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    can_manage = {s: _allowed(service.check_manage, s) for s in RuleScope}
    own = [r for r in records if r.scope == RuleScope.TENANT.value]
    shared = [r for r in records if r.scope == RuleScope.GLOBAL.value]
    last_page = max(1, (len(records) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, last_page)
    rows = [
        _Row(record, can_edit=record.scope == scope.value and can_manage[scope])
        for record in [*own, *shared][(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
    ]
    return _respond(
        request,
        "custom_checks/index.html",
        status_code,
        scope=scope.value,
        tenant_rows=[r for r in rows if r.record.scope == RuleScope.TENANT.value],
        global_rows=[r for r in rows if r.record.scope == RuleScope.GLOBAL.value],
        has_tenant_rows=bool(own),
        has_global_rows=bool(shared),
        page=page,
        last_page=last_page,
        show_tenant_tab=_allowed(service.check_read, RuleScope.TENANT),
        show_global_tab=can_manage[RuleScope.GLOBAL],
        can_manage=can_manage[scope],
        error=error,
        flash=_FLASH.get(notice or ""),
    )


@router.get("", include_in_schema=False)
def checks_index(
    request: Request,
    auth: CurrentSession,
    db: DbDep,
    scope: str | None = None,
    notice: str | None = None,
    page: str | None = None,
) -> Response:
    parsed = _parse_scope(scope)
    page_number = _parse_page(page)
    if parsed is None or page_number is None:
        return _not_found(request)
    service = _service(db, auth)
    if (
        scope is None
        and not _allowed(service.check_read, RuleScope.TENANT)
        and _allowed(service.check_manage, RuleScope.GLOBAL)
    ):
        parsed = RuleScope.GLOBAL
    return _list_page(request, service, parsed, page=page_number, notice=notice)


# --- create / edit ------------------------------------------------------------------------------


def _test_domains(db: Session, auth: AuthSession) -> list[tuple[int, str]]:
    """The domains the dry run may name: the ones the caller sees in the active tenant."""
    ctx = _ctx(auth)
    if ctx is None:
        return []
    try:
        views = DomainService(db, ctx, auth.principal).list(limit=MAX_LIMIT)
    except DomainServiceError:
        return []
    return [(v.id, v.display_name) for v in views]


def _form_page(
    request: Request,
    service: CustomChecksAdminService,
    db: Session,
    auth: AuthSession,
    scope: RuleScope,
    check_id: int | None,
    *,
    values: dict[str, Any] | None = None,
    status_code: int = 200,
    error: dict[str, str | None] | None = None,
    plain_error: str | None = None,
    result: CheckResult | None = None,
) -> Response:
    record = None
    if check_id is not None:
        try:
            record = service.get_check(scope, check_id)
        except CustomChecksAdminError as exc:
            return _failure(request, exc)
    can_test = _allowed(lambda _s: service.check_test(), scope)
    return _respond(
        request,
        "custom_checks/form.html",
        status_code,
        scope=scope.value,
        record=record,
        form=values if values is not None else _form_values(record),
        kinds=SELECTABLE_KINDS,
        reserved_kinds=sorted(RESERVED_KINDS),
        rrtypes=sorted(RRTYPES),
        severities=SEVERITIES,
        domains=_test_domains(db, auth) if can_test else [],
        error=error,
        plain_error=plain_error,
        result=result,
    )


@router.get("/new", include_in_schema=False)
def checks_new(
    request: Request, auth: CurrentSession, db: DbDep, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    try:
        service.check_manage(parsed)
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    return _form_page(request, service, db, auth, parsed, None)


@router.get("/{custom_check_id}/edit", include_in_schema=False)
def checks_edit(
    request: Request,
    auth: CurrentSession,
    db: DbDep,
    custom_check_id: str,
    scope: str | None = None,
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(custom_check_id)
    try:
        service.check_write(parsed, target)
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    return _form_page(request, service, db, auth, parsed, target)


async def _body_form(
    request: Request, db: Session, cap: int
) -> tuple[dict[str, list[str]] | None, int, str | None]:
    """(form, status, error key) of the request body; the connection is released first."""
    await run_in_threadpool(db.rollback)  # no pooled connection is held while the body is read
    try:
        body = await _read_capped(request, cap)
    except _BodyTooLarge:
        return None, 413, TOO_LARGE_KEY
    form = _form(body)
    if form is None:
        return None, 422, INVALID_FORM_KEY
    return form, 200, None


async def _save(
    request: Request,
    service: CustomChecksAdminService,
    db: Session,
    auth: AuthSession,
    scope: RuleScope,
    target: int | None,
) -> Response:
    """Create (`target` None) or update a check from the form. The caller has already checked the
    permission (and the row's visibility), so the body is read only for an allowed caller."""
    form, status, problem = await _body_form(request, db, MAX_SAVE_BYTES)
    if form is None:
        return await run_in_threadpool(
            _form_page,
            request,
            service,
            db,
            auth,
            scope,
            target,
            status_code=status,
            plain_error=problem,
        )
    data, echo, problem = _save_data(form, scope, test=False)
    del form
    if problem is not None:
        values = None if problem == INVALID_CHARS_KEY else echo  # never echo a NUL
        return await run_in_threadpool(
            _form_page,
            request,
            service,
            db,
            auth,
            scope,
            target,
            values=values,
            status_code=422,
            plain_error=problem,
        )
    try:
        if target is None:
            await run_in_threadpool(service.create, scope, data)
        else:
            data.pop("check_key")  # the key is fixed once created
            await run_in_threadpool(service.update, scope, target, data)
    except CustomCheckFieldInvalid as exc:
        return await run_in_threadpool(
            _form_page,
            request,
            service,
            db,
            auth,
            scope,
            target,
            values=echo,
            status_code=422,
            error=_field_error(exc),
        )
    except CheckKeyConflict as exc:
        return await run_in_threadpool(
            _form_page,
            request,
            service,
            db,
            auth,
            scope,
            target,
            values=echo,
            status_code=409,
            error={"key": exc.key, "field_label": _FIELD_LABELS["check_key"], "reason": None},
        )
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    return _redirect(scope, "created" if target is None else "updated")


@router.post("", include_in_schema=False)
async def checks_create(
    request: Request, auth: CurrentSession, db: DbDep, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    try:  # permission first: a denied caller never has its body read
        await run_in_threadpool(service.check_manage, parsed)
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    return await _save(request, service, db, auth, parsed, None)


@router.post("/test", include_in_schema=False)
async def checks_test(
    request: Request,
    auth: CurrentSession,
    db: DbDep,
    resolver: ResolverDep,
    scope: str | None = None,
    check: str | None = None,
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    target = None if check is None else parse_id(check)
    if check is not None and target is None:
        return _not_found(request)
    service = _service(db, auth)
    try:  # `rules.read` on the tenant first: a denied caller never has its body read
        await run_in_threadpool(service.check_test)
    except CustomChecksAdminError as exc:
        return _failure(request, exc)

    async def page(**extra: Any) -> Response:
        return await run_in_threadpool(
            _form_page, request, service, db, auth, parsed, target, **extra
        )

    form, status, problem = await _body_form(request, db, MAX_SAVE_BYTES)
    if form is None:
        return await page(status_code=status, plain_error=problem)
    data, echo, problem = _save_data(form, parsed, test=True)
    del form
    if problem is not None:
        return await page(
            values=None if problem == INVALID_CHARS_KEY else echo,
            status_code=422,
            plain_error=problem,
        )
    if not echo["domain_id"].strip():
        return await page(values=echo, status_code=422, plain_error=NO_DOMAIN_KEY)
    domain = echo["domain_id"].strip()
    # The service wants an int id; anything else is passed on as text for it to refuse (404).
    data["domain_id"] = parse_id(domain) or domain

    def prepare() -> DryRun:
        try:
            return service.prepare_test(data)
        finally:
            db.rollback()  # no connection is held during the DNS work

    try:
        dry = await run_in_threadpool(prepare)
    except CustomCheckFieldInvalid as exc:
        return await page(values=echo, status_code=422, error=_field_error(exc))
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    ctx = CheckContext(
        resolver=resolver, tenant_id=str(dry.tenant_id), domain_id=str(dry.domain_id)
    )
    registry = CheckRegistry()
    registry.register(dry.check)
    result = await run_check(dry.check.id, dry.domain_name, ctx, registry=registry)
    return await page(values=echo, result=result)


@router.post("/{custom_check_id}/edit", include_in_schema=False)
async def checks_update(
    request: Request,
    auth: CurrentSession,
    db: DbDep,
    custom_check_id: str,
    scope: str | None = None,
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(custom_check_id)
    try:  # permission and visibility of the row first
        await run_in_threadpool(service.check_write, parsed, target)
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    return await _save(request, service, db, auth, parsed, target)


# --- toggle / delete ----------------------------------------------------------------------------


@router.post("/{custom_check_id}/toggle", include_in_schema=False)
async def checks_toggle(
    request: Request,
    auth: CurrentSession,
    db: DbDep,
    custom_check_id: str,
    scope: str | None = None,
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(custom_check_id)
    try:
        await run_in_threadpool(service.check_write, parsed, target)
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    form, status, problem = await _body_form(request, db, _FORM_OVERHEAD_BYTES)
    if form is None:
        return await run_in_threadpool(
            _list_page, request, service, parsed, status_code=status, error=problem
        )
    enabled = _single(form, "enabled")
    if enabled not in ("0", "1"):
        return await run_in_threadpool(
            _list_page, request, service, parsed, status_code=422, error=INVALID_FORM_KEY
        )
    try:
        await run_in_threadpool(service.update, parsed, target, {"enabled": enabled == "1"})
    except CustomCheckFieldInvalid as exc:
        return await run_in_threadpool(
            _list_page, request, service, parsed, status_code=422, error=exc.key
        )
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    return _redirect(parsed, "enabled" if enabled == "1" else "disabled")


@router.post("/{custom_check_id}/delete", include_in_schema=False)
async def checks_delete(
    request: Request,
    auth: CurrentSession,
    db: DbDep,
    custom_check_id: str,
    scope: str | None = None,
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(custom_check_id)
    try:
        await run_in_threadpool(service.check_write, parsed, target)
        await run_in_threadpool(db.rollback)
        await run_in_threadpool(service.delete, parsed, target)
    except CustomChecksAdminError as exc:
        return _failure(request, exc)
    return _redirect(parsed, "deleted")
