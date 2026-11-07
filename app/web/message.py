"""Message analysis web UI (M4-12): `/tools/message`, paste a raw message or header block.

Routes: GET `/tools/message` (form) and POST `/tools/message` (re-renders the page with the
result). The analyzer (`analyze_message`) is called directly, like `web/dns_tools.py` calls its
service. Access follows the M1-19 web conventions: anonymous GET -> 303 /login, anonymous POST
-> 401 (after the CSRF middleware); no active tenant -> 404; a principal without
`message.analyze` (client viewers) -> 403 denied page. The permission is checked before the body
is read, so a denied request never reaches the analyzer.

The form is urlencoded (no multipart, no server-side file handling): the optional file picker is
progressive enhancement and reads the `.eml` into the textarea in the browser. The body is read
with a hard cap (declared length first, then counted while streaming). A urlencoded text can be
up to three times larger than the raw bytes (`%0D%0A` per CRLF), so the transport cap is
`3 * MAX_RAW_BYTES + overhead` and the real limit, `MAX_RAW_BYTES` on the decoded message, is
checked afterwards. Note that the CSRF middleware refuses form bodies over its own
`MAX_FORM_BYTES` when no `X-CSRF-Token` header is sent.

Nothing is stored. The pasted text is never echoed back, logged, or put in a URL or cookie, and
every response is `Cache-Control: no-store`. Values from the message are autoescaped by Jinja
(never `|safe`) and shown through `visible`. Hops and warnings come from the service's redacted
output (the `for <addr>` clause is gone); this module never touches the raw text beyond
passing it to the analyzer.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response
from starlette.concurrency import run_in_threadpool

from app.core.permissions import Action, Principal, TenantResource, can
from app.parsers.message import MAX_RAW_BYTES
from app.services.message_analysis import MessageAnalysis, analyze_message
from app.web.deps import CurrentSession, tenant_ctx
from app.web.dns_tools import visible  # registers the `visible` filter
from app.web.templating import render

router = APIRouter(prefix="/tools/message")

FORM_OVERHEAD_BYTES: Final = 4096
MAX_BODY_BYTES: Final = 3 * MAX_RAW_BYTES + FORM_OVERHEAD_BYTES
_MAX_FIELDS: Final = 8
_NO_STORE: Final = {"Cache-Control": "no-store"}

__all__ = ["MAX_BODY_BYTES", "message_allowed", "router", "visible"]


def message_allowed(principal: Principal, tenant_id: int | None) -> bool:
    return tenant_id is not None and can(
        principal, Action.MESSAGE_ANALYZE, TenantResource(tenant_id)
    )


def _page(
    request: Request,
    *,
    status_code: int = 200,
    error: str | None = None,
    analysis: MessageAnalysis | None = None,
) -> HTMLResponse:
    response = render(
        request,
        "message/index.html",
        status_code=status_code,
        logged_in=True,
        error=error,
        analysis=analysis,
        max_raw_bytes=MAX_RAW_BYTES,
    )
    response.headers.update(_NO_STORE)
    return response


def _guard(request: Request, auth: CurrentSession) -> Response | None:
    """None if allowed; the 403 page without `message.analyze`; 404 (via tenant_ctx) without a
    valid active tenant."""
    ctx = tenant_ctx(auth)
    if not message_allowed(auth.principal, ctx.tenant_id):
        response = render(request, "message/denied.html", status_code=403, logged_in=True)
        response.headers.update(_NO_STORE)
        return response
    return None


class _BodyTooLarge(Exception):
    pass


async def _read_capped(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
        raise _BodyTooLarge
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise _BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def _raw_field(body: bytes) -> str | None:
    """The `raw` form field, or None if the body is not a usable urlencoded form."""
    try:
        form = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=_MAX_FIELDS)
    except (UnicodeDecodeError, ValueError):
        return None
    values = form.get("raw", [])
    return values[0] if len(values) == 1 else None


@router.get("", include_in_schema=False)
def message_index(request: Request, auth: CurrentSession) -> Response:
    denied = _guard(request, auth)
    if denied is not None:
        return denied
    return _page(request)


@router.post("", include_in_schema=False)
async def message_analyze_form(request: Request, auth: CurrentSession) -> Response:
    denied = _guard(request, auth)  # permission first: 403 whatever the body contains
    if denied is not None:
        return denied
    try:
        body = await _read_capped(request)
    except _BodyTooLarge:
        return _page(request, status_code=413, error="message.error.too_large")
    text = _raw_field(body)
    del body
    if text is None or not text.strip():
        return _page(request, status_code=422, error="message.error.empty")
    if "\x00" in text:
        return _page(request, status_code=422, error="message.error.nul_byte")
    raw = text.encode("utf-8")
    del text
    if len(raw) > MAX_RAW_BYTES:
        return _page(request, status_code=413, error="message.error.too_large")
    analysis = await run_in_threadpool(analyze_message, raw)
    return _page(request, analysis=analysis)
