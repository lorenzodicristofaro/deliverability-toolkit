"""`/api/v1/message`: offline analysis of a pasted message or header block (M4-11).

`POST /analyze` takes the RAW message (`message/rfc822` or `text/plain`, no multipart) and answers
with the `MessageAnalysis` JSON of `analyze_message`, byte-for-byte (`model_dump_json`).

Status codes (error bodies are `{"detail": ...}`, never echoing the input):
- 401 anonymous (mutating requests first need a valid CSRF token, else the middleware answers 403);
- 404 no active tenant (a stale or foreign one included);
- 403 the principal lacks `message.analyze` in the active tenant (client viewers);
- 415 other content type; 413 body over MAX_RAW_BYTES (declared length first, then counted while
  streaming: the rest is never buffered); 422 empty body or NUL byte;
  these detail objects are `{key, message, field, reason}` with stable codes.
- 200 otherwise; an input the analyzer rejects is data (status `error`), not an HTTP error.

Nothing is stored or logged and there is no network or DNS access. Permission checks run before
the body is read, so a denied caller never reaches the analyzer.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.v1._common import _error
from app.core.i18n import t
from app.core.permissions import Action, TenantResource, can
from app.core.tenancy import TenantContext
from app.parsers.message import MAX_RAW_BYTES
from app.services.message_analysis import MessageAnalysis, analyze_message
from app.web.deps import CurrentSession, tenant_ctx
from app.web.templating import request_language

router = APIRouter(prefix="/message", tags=["message"])

_ALLOWED_TYPES = frozenset({"message/rfc822", "text/plain"})


def _access(request: Request, auth: CurrentSession) -> TenantContext:
    """401 anonymous (via current_session), 404 no active tenant, 403 without `message.analyze`."""
    try:
        ctx = tenant_ctx(auth)
    except HTTPException:
        raise _error(request, 404, "api.error.not_found") from None
    if not can(auth.principal, Action.MESSAGE_ANALYZE, TenantResource(ctx.tenant_id)):
        raise _error(request, 403, "api.error.forbidden")
    return ctx


Access = Annotated[TenantContext, Depends(_access)]


def _problem(request: Request, status: int, key: str, field: str, reason: str) -> HTTPException:
    return HTTPException(
        status_code=status,
        detail={
            "key": key,
            "message": t(key, request_language(request.scope)),
            "field": field,
            "reason": reason,
        },
    )


def _too_large(request: Request) -> HTTPException:
    return _problem(request, 413, "api.message.error.too_large", "body", "too_large")


async def _read_capped(request: Request) -> bytes:
    """The body, read with a hard cap: Content-Length is checked first, then the bytes are
    counted while streaming and reading stops at the first chunk that crosses the cap."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_RAW_BYTES):
        raise _too_large(request)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_RAW_BYTES:
            raise _too_large(request)
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/analyze", responses={200: {"model": MessageAnalysis}})
async def message_analyze(request: Request, _ctx: Access) -> Response:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in _ALLOWED_TYPES:
        raise _problem(
            request,
            415,
            "api.message.error.unsupported_media_type",
            "content_type",
            "unsupported_media_type",
        )
    raw = await _read_capped(request)
    if not raw:
        raise _problem(request, 422, "api.message.error.empty", "body", "empty")
    if b"\x00" in raw:
        raise _problem(request, 422, "api.message.error.nul_byte", "body", "nul_byte")
    analysis = await run_in_threadpool(analyze_message, raw)
    return Response(content=analysis.model_dump_json(), media_type="application/json")
