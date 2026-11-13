"""Content rules admin UI (M5-19): `/rules`, list, create, edit, enable/disable, delete and a
"test on a sample" panel.

Every operation goes through `ContentRulesAdminService` (M5-18), the same service as the REST
API: this module holds no repository and repeats no authorization. The scope is the `?scope=`
query (`tenant`, the default, or `global`), never a form field, so the permission is decided
before the body is read. A denied principal gets a 403 page (404 for a missing tenant, a foreign
or malformed rule id), and the service is not reached with the body.

Routes (all need a session; anonymous GET -> 303 /login, anonymous POST -> 401):
- GET  /rules                   list (tenant tab: the tenant's rows, then global rows read-only;
                                `?page=`; a session that may not read the tenant tab, or has no
                                tenant, defaults to the global tab if its user may manage it)
- GET  /rules/new               create form
- POST /rules                   create
- GET  /rules/{rule_id}/edit    edit form
- POST /rules/{rule_id}/edit    update
- POST /rules/{rule_id}/toggle  enable / disable (`enabled=1|0`)
- POST /rules/{rule_id}/delete  delete (a seeded global row answers 409: disable it instead)
- GET/POST /rules/test          test on a sample (`service.test_pattern`, in a worker thread)

Bodies are urlencoded and size-capped by `_read_capped`. NUL and lone surrogates are refused before
the service and never echoed. A browser submits textarea newlines as CRLF: `_lf` turns them back
into LF, and an edit that leaves the pattern as shown keeps the stored bytes. The sample and
pattern are echoed back only in the test panel; everything derived from rules and samples is
autoescaped (no `|safe`) and shown through `visible`. Every response is `Cache-Control: no-store`.
The caps are far below the CSRF middleware's default form cap, so an oversize no-JS post reaches
this module's localized 413.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.i18n import load_catalogue
from app.core.permissions import RuleScope
from app.core.tenancy import TenantContext
from app.models.content_rule import KINDS, SEVERITIES
from app.repositories.base import MAX_LIMIT, parse_id
from app.repositories.content_rules import ContentRuleRecord
from app.services.content_rules_admin import (
    MAX_SAMPLE_BYTES,
    ContentRulesAdminService,
    RuleFieldInvalid,
    RulesAdminError,
    RuleTestOutcome,
    SeededRuleNotDeletable,
    SeedKeyConflict,
)
from app.web.deps import AuthSession, CurrentSession, DbDep
from app.web.dns_tools import visible  # registers the `visible` filter
from app.web.templating import render, request_language

router = APIRouter(prefix="/rules")

_NO_STORE: Final = {"Cache-Control": "no-store"}
_FORM_OVERHEAD_BYTES: Final = 4096
# Worst case of the text fields of a rule (4 bytes per character), percent-encoded (3x).
MAX_SAVE_BYTES: Final = 3 * 4 * 4000 + _FORM_OVERHEAD_BYTES
MAX_TEST_BYTES: Final = 3 * (MAX_SAMPLE_BYTES + 4 * 1100) + _FORM_OVERHEAD_BYTES
_MAX_FIELDS: Final = 40
PAGE_SIZE: Final = 200
_WEIGHT = re.compile(r"-?[0-9]{1,6}")

# Regex flag letters of the form, mapped to `re` flags (the service rejects anything it does not
# allow). Display order is the template's.
FLAG_LETTERS: Final = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "x": re.VERBOSE,
    "a": re.ASCII,
}
_RULE_TEXT_FIELDS: Final = (
    "name",
    "kind",
    "pattern",
    "weight",
    "category",
    "language",
    "severity",
    "title",
    "advice",
    "seed_key",
)
_FLASH: Final = {
    "created": "web.rules.flash.created",
    "updated": "web.rules.flash.updated",
    "deleted": "web.rules.flash.deleted",
    "enabled": "web.rules.flash.enabled",
    "disabled": "web.rules.flash.disabled",
}
_FIELD_LABELS: Final = {
    "name": "web.rules.field.name",
    "kind": "web.rules.field.kind",
    "pattern": "web.rules.field.pattern",
    "flags": "web.rules.field.flags",
    "weight": "web.rules.field.weight",
    "category": "web.rules.field.category",
    "language": "web.rules.field.language",
    "severity": "web.rules.field.severity",
    "title": "web.rules.field.title",
    "advice": "web.rules.field.advice",
    "seed_key": "web.rules.field.seed_key",
    "sample": "web.rules.field.sample",
}
_TEST_STATUS_KEYS: Final = {
    "matched": "web.rules.test.matched",
    "no_match": "web.rules.test.no_match",
    "timed_out": "web.rules.test.timed_out",
    "busy": "web.rules.test.busy",
    "error": "web.rules.test.error",
    "invalid": "web.rules.test.invalid",
}
INVALID_FORM_KEY: Final = "web.rules.error.invalid_form"
INVALID_CHARS_KEY: Final = "web.rules.error.invalid_chars"
TOO_LARGE_KEY: Final = "web.rules.error.too_large"
INVALID_FLAGS_KEY: Final = "web.rules.error.invalid_flags"
INVALID_WEIGHT_KEY: Final = "api.rules.error.invalid_weight"

__all__ = ["MAX_SAVE_BYTES", "MAX_TEST_BYTES", "PAGE_SIZE", "router", "visible"]


# --- helpers ------------------------------------------------------------------------------------


def _service(db: Session, auth: AuthSession) -> ContentRulesAdminService:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return ContentRulesAdminService(db, ctx, auth.principal)


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


def _failure(request: Request, exc: RulesAdminError) -> Response:
    """The page for a refused operation: 404 (missing, foreign or malformed, or no tenant) or the
    403 denied page. Any other error is a bug and is raised."""
    if exc.status == 404:
        return _not_found(request)
    if exc.status == 403:
        return _respond(request, "rules/denied.html", 403)
    raise exc


def _allowed(check: Callable[[RuleScope], None], scope: RuleScope) -> bool:
    try:
        check(scope)
    except RulesAdminError:
        return False
    return True


def _redirect(scope: RuleScope, notice: str) -> Response:
    return RedirectResponse(f"/rules?scope={scope.value}&notice={notice}", status_code=303)


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
            errors="strict",  # an invalid percent-encoded UTF-8 sequence is refused, not replaced
        )
    except (UnicodeDecodeError, ValueError):
        return None


def _single(form: dict[str, list[str]], name: str) -> str | None:
    """The one value of `name` ("" if absent); None if the field is repeated."""
    values = form.get(name, [""])
    return values[0] if len(values) == 1 else None


def _lf(value: str) -> str:
    return value.replace("\r\n", "\n")


def _bad_chars(value: str) -> bool:
    return "\x00" in value or any("\ud800" <= ch <= "\udfff" for ch in value)


def _weight(text: str) -> int | None:
    stripped = text.strip()
    return int(stripped) if _WEIGHT.fullmatch(stripped) else None


def _flags_value(letters: list[str]) -> int | None:
    value = 0
    for letter in letters:
        if letter not in FLAG_LETTERS:
            return None
        value |= FLAG_LETTERS[letter]
    return value


@dataclass(frozen=True, slots=True)
class _Row:
    record: ContentRuleRecord
    title: str
    can_edit: bool
    can_delete: bool
    override_enabled: bool | None = None  # None: no rule of this tenant overrides this global row


def _form_values(record: ContentRuleRecord | None) -> dict[str, Any]:
    if record is None:
        return {
            "name": "",
            "kind": "regex",
            "pattern": "",
            "flags": [],
            "weight": "10",
            "category": "",
            "language": "",
            "enabled": True,
            "severity": "medium",
            "title": "",
            "advice": "",
            "seed_key": "",
        }
    return {
        "name": record.name,
        "kind": record.kind,
        "pattern": record.pattern,
        "flags": [letter for letter, bit in FLAG_LETTERS.items() if record.flags & bit],
        "weight": str(record.weight),
        "category": record.category,
        "language": record.language or "",
        "enabled": record.enabled,
        "severity": record.severity,
        "title": record.title or "",
        "advice": record.advice or "",
        "seed_key": record.seed_key or "",
    }


def _field_error(exc: RuleFieldInvalid) -> dict[str, str | None]:
    return {"key": exc.key, "field_label": _FIELD_LABELS.get(exc.field)}


# --- list ---------------------------------------------------------------------------------------


def _all_records(service: ContentRulesAdminService, scope: RuleScope) -> list[ContentRuleRecord]:
    """Every row visible in `scope`, read in batches until a short one. The override markers need
    all of the tenant's rows, wherever the page being shown falls."""
    records: list[ContentRuleRecord] = []
    while True:
        batch = service.list_rules(scope, limit=MAX_LIMIT, offset=len(records))
        records.extend(batch)
        if len(batch) < MAX_LIMIT:
            return records


def _list_page(
    request: Request,
    service: ContentRulesAdminService,
    scope: RuleScope,
    *,
    page: int = 1,
    status_code: int = 200,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    try:
        records = _all_records(service, scope)
    except RulesAdminError as exc:
        return _failure(request, exc)
    can_manage = {s: _allowed(service.check_manage, s) for s in RuleScope}
    catalogue = load_catalogue(request_language(request.scope))

    def title(record: ContentRuleRecord) -> str:
        if record.title:
            return record.title
        text = catalogue.get(f"CONTENT_RULE.{record.seed_key}.title") if record.seed_key else None
        return text or record.name

    own = [r for r in records if r.scope == RuleScope.TENANT.value]
    shared = [r for r in records if r.scope == RuleScope.GLOBAL.value]
    overrides = {r.seed_key: r.enabled for r in own if r.seed_key is not None}
    last_page = max(1, (len(records) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, last_page)
    rows = [
        _Row(
            record,
            title(record),
            can_edit=record.scope == scope.value and can_manage[scope],
            can_delete=(
                record.scope == scope.value
                and can_manage[scope]
                and not (record.scope == RuleScope.GLOBAL.value and record.seed_key is not None)
            ),
            override_enabled=(
                overrides.get(record.seed_key)
                if record.scope == RuleScope.GLOBAL.value and record.seed_key is not None
                else None
            ),
        )
        for record in [*own, *shared][(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
    ]
    return _respond(
        request,
        "rules/index.html",
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
def rules_index(
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


def _form_page(
    request: Request,
    service: ContentRulesAdminService,
    scope: RuleScope,
    rule_id: int | None,
    *,
    values: dict[str, Any] | None = None,
    status_code: int = 200,
    error: dict[str, str | None] | None = None,
    plain_error: str | None = None,
) -> Response:
    record = None
    if rule_id is not None:
        try:
            record = service.get_rule(scope, rule_id)
        except RulesAdminError as exc:
            return _failure(request, exc)
    return _respond(
        request,
        "rules/form.html",
        status_code,
        scope=scope.value,
        record=record,
        form=values if values is not None else _form_values(record),
        kinds=KINDS,
        severities=SEVERITIES,
        flag_letters=tuple(FLAG_LETTERS),
        seeded=record is not None
        and record.scope == RuleScope.GLOBAL.value
        and record.seed_key is not None,
        error=error,
        plain_error=plain_error,
    )


@router.get("/new", include_in_schema=False)
def rules_new(
    request: Request, auth: CurrentSession, db: DbDep, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    try:
        service.check_manage(parsed)
    except RulesAdminError as exc:
        return _failure(request, exc)
    return _form_page(request, service, parsed, None)


@router.get("/{rule_id}/edit", include_in_schema=False)
def rules_edit(
    request: Request, auth: CurrentSession, db: DbDep, rule_id: str, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(rule_id)
    try:
        service.check_write(parsed, target)
    except RulesAdminError as exc:
        return _failure(request, exc)
    return _form_page(request, service, parsed, target)


def _save_data(
    form: dict[str, list[str]], scope: RuleScope
) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    """(service data, echo values, error key). The data holds every field of the form, so an
    omitted field is rejected by the service rather than silently kept."""
    echo = _form_values(None)
    texts: dict[str, str] = {}
    for name in _RULE_TEXT_FIELDS:
        value = _single(form, name)
        if value is None:
            return {}, echo, INVALID_FORM_KEY
        texts[name] = value
    texts["pattern"] = _lf(texts["pattern"])
    texts["advice"] = _lf(texts["advice"])
    letters = form.get("flags", [])
    enabled = _single(form, "enabled")
    if enabled is None:
        return {}, echo, INVALID_FORM_KEY
    if any(_bad_chars(v) for v in (*texts.values(), *letters, enabled)):
        return {}, echo, INVALID_CHARS_KEY
    echo.update({**texts, "flags": letters, "enabled": enabled == "1"})
    flags = _flags_value(letters)
    weight = _weight(texts["weight"])
    if flags is None:
        return {}, echo, INVALID_FLAGS_KEY
    if weight is None:
        return {}, echo, INVALID_WEIGHT_KEY
    data: dict[str, Any] = {
        "name": texts["name"],
        "kind": texts["kind"],
        "pattern": texts["pattern"],
        "flags": flags,
        "weight": weight,
        "category": texts["category"],
        "language": texts["language"].strip() or None,
        "enabled": enabled == "1",
        "severity": texts["severity"],
        "title": texts["title"] or None,
        "advice": texts["advice"] or None,
    }
    if scope is RuleScope.TENANT:
        data["seed_key"] = texts["seed_key"].strip() or None
    return data, echo, None


async def _save(
    request: Request,
    service: ContentRulesAdminService,
    db: Session,
    scope: RuleScope,
    target: int | None,
) -> Response:
    """Create (`target` None) or update a rule from the form. The caller has already checked the
    permission (and the rule's visibility), so the body is read only for an allowed caller."""
    await run_in_threadpool(db.rollback)  # no pooled connection is held while the body is read
    try:
        body = await _read_capped(request, MAX_SAVE_BYTES)
    except _BodyTooLarge:
        return await run_in_threadpool(
            _form_page, request, service, scope, target, status_code=413, plain_error=TOO_LARGE_KEY
        )
    form = _form(body)
    del body
    if form is None:
        return await run_in_threadpool(
            _form_page,
            request,
            service,
            scope,
            target,
            status_code=422,
            plain_error=INVALID_FORM_KEY,
        )
    data, echo, problem = _save_data(form, scope)
    del form
    if problem is not None:
        values = None if problem == INVALID_CHARS_KEY else echo  # never echo a NUL
        return await run_in_threadpool(
            _form_page,
            request,
            service,
            scope,
            target,
            values=values,
            status_code=422,
            plain_error=problem,
        )
    if target is not None:
        try:
            stored = (await run_in_threadpool(service.get_rule, scope, target)).pattern
        except RulesAdminError as exc:
            return _failure(request, exc)
        # A textarea cannot carry a stored CR, so a pattern left as shown keeps its stored bytes.
        if _lf(stored).replace("\r", "\n") == data["pattern"]:
            data["pattern"] = stored
    try:
        if target is None:
            await run_in_threadpool(service.create, scope, data)
        else:
            await run_in_threadpool(service.update, scope, target, data)
    except RuleFieldInvalid as exc:
        return await run_in_threadpool(
            _form_page,
            request,
            service,
            scope,
            target,
            values=echo,
            status_code=422,
            error=_field_error(exc),
        )
    except SeedKeyConflict as exc:
        return await run_in_threadpool(
            _form_page,
            request,
            service,
            scope,
            target,
            values=echo,
            status_code=409,
            error={"key": exc.key, "field_label": _FIELD_LABELS["seed_key"]},
        )
    except RulesAdminError as exc:
        return _failure(request, exc)
    return _redirect(scope, "created" if target is None else "updated")


@router.post("", include_in_schema=False)
async def rules_create(
    request: Request, auth: CurrentSession, db: DbDep, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    try:  # permission first: a denied caller never has its body read
        await run_in_threadpool(service.check_manage, parsed)
    except RulesAdminError as exc:
        return _failure(request, exc)
    return await _save(request, service, db, parsed, None)


@router.post("/{rule_id}/edit", include_in_schema=False)
async def rules_update(
    request: Request, auth: CurrentSession, db: DbDep, rule_id: str, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(rule_id)
    try:  # permission and visibility of the rule first
        await run_in_threadpool(service.check_write, parsed, target)
    except RulesAdminError as exc:
        return _failure(request, exc)
    return await _save(request, service, db, parsed, target)


# --- toggle / delete ----------------------------------------------------------------------------


@router.post("/{rule_id}/toggle", include_in_schema=False)
async def rules_toggle(
    request: Request, auth: CurrentSession, db: DbDep, rule_id: str, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(rule_id)
    try:
        await run_in_threadpool(service.check_write, parsed, target)
    except RulesAdminError as exc:
        return _failure(request, exc)
    await run_in_threadpool(db.rollback)
    try:
        body = await _read_capped(request, _FORM_OVERHEAD_BYTES)
    except _BodyTooLarge:
        return await run_in_threadpool(
            _list_page, request, service, parsed, status_code=413, error=TOO_LARGE_KEY
        )
    form = _form(body)
    enabled = None if form is None else _single(form, "enabled")
    if enabled not in ("0", "1"):
        return await run_in_threadpool(
            _list_page, request, service, parsed, status_code=422, error=INVALID_FORM_KEY
        )
    try:
        await run_in_threadpool(service.update, parsed, target, {"enabled": enabled == "1"})
    except RuleFieldInvalid as exc:  # the service re-validates the stored pattern on any update
        return await run_in_threadpool(
            _list_page, request, service, parsed, status_code=422, error=exc.key
        )
    except RulesAdminError as exc:
        return _failure(request, exc)
    return _redirect(parsed, "enabled" if enabled == "1" else "disabled")


@router.post("/{rule_id}/delete", include_in_schema=False)
async def rules_delete(
    request: Request, auth: CurrentSession, db: DbDep, rule_id: str, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(rule_id)
    try:
        await run_in_threadpool(service.check_write, parsed, target)
        await run_in_threadpool(db.rollback)
        await run_in_threadpool(service.delete, parsed, target)
    except SeededRuleNotDeletable as exc:
        return await run_in_threadpool(
            _list_page, request, service, parsed, status_code=409, error=exc.key
        )
    except RulesAdminError as exc:
        return _failure(request, exc)
    return _redirect(parsed, "deleted")


# --- test on a sample ---------------------------------------------------------------------------


def _test_page(
    request: Request,
    scope: RuleScope,
    *,
    values: dict[str, Any] | None = None,
    status_code: int = 200,
    outcome: RuleTestOutcome | None = None,
    error: dict[str, str | None] | None = None,
    plain_error: str | None = None,
) -> Response:
    return _respond(
        request,
        "rules/test.html",
        status_code,
        scope=scope.value,
        form=values or {"kind": "regex", "pattern": "", "flags": [], "sample": ""},
        kinds=KINDS,
        flag_letters=tuple(FLAG_LETTERS),
        outcome=outcome,
        status_key=None if outcome is None else _TEST_STATUS_KEYS[outcome.status.value],
        error=error,
        plain_error=plain_error,
    )


@router.get("/test", include_in_schema=False)
def rules_test_form(
    request: Request, auth: CurrentSession, db: DbDep, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    try:
        _service(db, auth).check_manage(parsed)
    except RulesAdminError as exc:
        return _failure(request, exc)
    return _test_page(request, parsed)


@router.post("/test", include_in_schema=False)
async def rules_test(
    request: Request, auth: CurrentSession, db: DbDep, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    try:
        await run_in_threadpool(service.check_manage, parsed)
    except RulesAdminError as exc:
        return _failure(request, exc)
    await run_in_threadpool(
        db.rollback
    )  # the search can block for seconds: hold no pooled connection meanwhile
    try:
        body = await _read_capped(request, MAX_TEST_BYTES)
    except _BodyTooLarge:
        return _test_page(request, parsed, status_code=413, plain_error=TOO_LARGE_KEY)
    form = _form(body)
    del body
    fields = None if form is None else {n: _single(form, n) for n in ("kind", "pattern", "sample")}
    if form is None or fields is None or any(v is None for v in fields.values()):
        return _test_page(request, parsed, status_code=422, plain_error=INVALID_FORM_KEY)
    letters = form.get("flags", [])
    texts = {n: _lf(v) for n, v in fields.items() if v is not None}
    if any(_bad_chars(v) for v in (*texts.values(), *letters)):
        return _test_page(request, parsed, status_code=422, plain_error=INVALID_CHARS_KEY)
    echo = {**texts, "flags": letters}
    flags = _flags_value(letters)
    if flags is None:
        return _test_page(
            request, parsed, values=echo, status_code=422, plain_error=INVALID_FLAGS_KEY
        )
    try:
        outcome = await run_in_threadpool(service.test_pattern, parsed, {**texts, "flags": flags})
    except RuleFieldInvalid as exc:
        return _test_page(request, parsed, values=echo, status_code=422, error=_field_error(exc))
    except RulesAdminError as exc:
        return _failure(request, exc)
    return _test_page(request, parsed, values=echo, outcome=outcome)
