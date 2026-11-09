"""Content analysis web UI (M5-16): `/tools/content`, paste HTML, text, subject or an `.eml`.

Routes: GET `/tools/content` (form) and POST `/tools/content` (re-renders the page with the
result). The analyzer (`analyze_content`) runs in a worker thread, like the M5-15 API route. Access
follows the M4-12 conventions: anonymous GET -> 303 /login, anonymous POST -> 401 (after the CSRF
middleware); no active tenant -> 404; a principal without `content.analyze` (client viewers) ->
403 denied page. The permission is checked before the body is read, so a denied request never
reaches the analyzer. After the access checks the session's transaction is ended (`rollback`), so
no pooled connection is held while the body is read.

The form is urlencoded; the optional `.eml` picker reads the file into a textarea in the browser
(progressive enhancement, no inline script). The transport cap is `3 * MAX_RAW_BYTES + overhead`
(percent-encoding) and is registered as this route's CSRF form cap, so a no-JS oversize post gets
this route's localized 413, not the CSRF 403 (M5-01). The real limit, `MAX_RAW_BYTES` on the
decoded fields together, is checked afterwards. `data-max-bytes` is `MAX_RAW_BYTES`.

Nothing is stored. Pasted content is never echoed back (the form is not pre-filled), logged, or
put in a URL or cookie; every response is `Cache-Control: no-store`. All values from the content
(subject, evidence, rule names) are autoescaped by Jinja, never `|safe`, and shown through
`visible`. The pasted HTML is never rendered and there is no preview.
"""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response
from starlette.concurrency import run_in_threadpool

from app.core.csrf import register_form_cap
from app.core.permissions import Action, Principal, TenantResource, can
from app.core.tenancy import TenantContext
from app.models.content_rule import MAX_LANGUAGE_LENGTH
from app.parsers.message import MAX_RAW_BYTES
from app.services.content_analysis import ContentAnalysis, ContentInput, analyze_content
from app.web.deps import CurrentSession, DbDep, tenant_ctx
from app.web.dns_tools import visible  # registers the `visible` filter
from app.web.templating import render

router = APIRouter(prefix="/tools/content")

FORM_OVERHEAD_BYTES: Final = 4096
MAX_BODY_BYTES: Final = 3 * MAX_RAW_BYTES + FORM_OVERHEAD_BYTES
_MAX_FIELDS: Final = 12
_NO_STORE: Final = {"Cache-Control": "no-store"}
_FIELDS: Final = ("html", "text", "subject", "eml", "language")
_LANGUAGE = re.compile(r"[a-z]{2,3}(?:-[a-z0-9]{2,8})*")

register_form_cap("/tools/content", MAX_BODY_BYTES)

__all__ = ["MAX_BODY_BYTES", "content_allowed", "router", "visible"]


def content_allowed(principal: Principal, tenant_id: int | None) -> bool:
    return tenant_id is not None and can(
        principal, Action.CONTENT_ANALYZE, TenantResource(tenant_id)
    )


def _page(
    request: Request,
    *,
    status_code: int = 200,
    error: str | None = None,
    analysis: ContentAnalysis | None = None,
) -> HTMLResponse:
    response = render(
        request,
        "content/index.html",
        status_code=status_code,
        logged_in=True,
        error=error,
        analysis=analysis,
        max_raw_bytes=MAX_RAW_BYTES,
    )
    response.headers.update(_NO_STORE)
    return response


def _guard(request: Request, auth: CurrentSession) -> TenantContext | Response:
    """The tenant context if allowed; the 403 page without `content.analyze`; 404 (via
    tenant_ctx) without a valid active tenant."""
    ctx = tenant_ctx(auth)
    if not content_allowed(auth.principal, ctx.tenant_id):
        response = render(request, "content/denied.html", status_code=403, logged_in=True)
        response.headers.update(_NO_STORE)
        return response
    return ctx


class _BodyTooLarge(Exception):
    pass


async def _read_capped(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (
        not (declared.isascii() and declared.isdigit()) or int(declared) > MAX_BODY_BYTES
    ):
        raise _BodyTooLarge
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise _BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def _form_fields(body: bytes) -> dict[str, str] | None:
    """The known content fields (missing ones are ""), or None if the body is not a usable
    urlencoded form or repeats a field."""
    try:
        form = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=_MAX_FIELDS)
    except (UnicodeDecodeError, ValueError):
        return None
    fields: dict[str, str] = {}
    for name in _FIELDS:
        values = form.get(name, [""])
        if len(values) != 1:
            return None
        fields[name] = values[0]
    return fields


@router.get("", include_in_schema=False)
def content_index(request: Request, auth: CurrentSession, db: DbDep) -> Response:
    guarded = _guard(request, auth)
    db.rollback()
    if isinstance(guarded, Response):
        return guarded
    return _page(request)


@router.post("", include_in_schema=False)
async def content_analyze_form(request: Request, auth: CurrentSession, db: DbDep) -> Response:
    guarded = _guard(request, auth)  # permission first: 403 whatever the body contains
    # End the transaction the auth dependency left open, so no pooled connection is held while the
    # body is read and analysed. `guarded` holds plain ints, so the expiry cannot affect it.
    db.rollback()
    if isinstance(guarded, Response):
        return guarded
    try:
        body = await _read_capped(request)
    except _BodyTooLarge:
        return _page(request, status_code=413, error="web.content.error.too_large")
    fields = _form_fields(body)
    del body
    if fields is None or not any(fields[name].strip() for name in ("html", "text", "eml")):
        return _page(request, status_code=422, error="web.content.error.empty")
    if any("\x00" in value for value in fields.values()):
        return _page(request, status_code=422, error="web.content.error.nul_byte")
    language = fields["language"].strip().lower() or None
    if language is not None and (
        len(language) > MAX_LANGUAGE_LENGTH or not _LANGUAGE.fullmatch(language)
    ):
        return _page(request, status_code=422, error="web.content.error.invalid_language")
    total = sum(len(fields[name].encode("utf-8")) for name in ("html", "text", "subject", "eml"))
    if total > MAX_RAW_BYTES:
        return _page(request, status_code=413, error="web.content.error.too_large")
    content = ContentInput(
        html=fields["html"] or None,
        text=fields["text"] or None,
        subject=fields["subject"] or None,
        eml=fields["eml"].encode("utf-8") if fields["eml"].strip() else None,
        language_hint=language,
    )
    del fields
    analysis = await run_in_threadpool(analyze_content, guarded, db, content)
    return _page(request, analysis=analysis)
