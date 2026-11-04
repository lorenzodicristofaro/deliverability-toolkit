"""Structured JSON logging and request-id middleware (operator logs, not translated)."""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import time
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER = "X-Request-ID"
# An incoming request id is only accepted if it matches this strict charset and length.
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9._-]{8,64}")
_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = ("authorization", "cookie", "password", "secret", "token")
_HANDLER_MARK = "_deliverability_json_handler"
_STANDARD_ATTRS = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "taskName"}

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(s in lowered for s in _SENSITIVE_KEYS)


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _REDACTED if _is_sensitive(str(k)) else _scrub(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_scrub(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Known secret values are masked in the final output."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        needles: set[str] = set()
        for secret in secrets:
            if secret:
                needles.add(secret)
                needles.add(json.dumps(secret)[1:-1])  # JSON-escaped form
        # Longest first so a secret containing another is fully masked.
        self._needles = sorted(needles, key=len, reverse=True)

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None) or request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key in payload:
                continue
            payload[key] = _REDACTED if _is_sensitive(key) else _scrub(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        line = json.dumps(payload, default=str)
        for needle in self._needles:
            line = line.replace(needle, _REDACTED)
        return line


class _StripQueryFilter(logging.Filter):
    """uvicorn.access logs the full request target; drop the query string from it."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            record.args = (*args[:2], args[2].split("?", 1)[0], *args[3:])
        return True


def configure_logging(level: str = "INFO", secrets: Iterable[str] = ()) -> None:
    """Route the root logger and uvicorn's loggers through the JSON formatter. Idempotent."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter(secrets))
    setattr(handler, _HANDLER_MARK, True)

    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, _HANDLER_MARK, False):
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(level)
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _StripQueryFilter) for f in access.filters):
        access.addFilter(_StripQueryFilter())


request_logger = logging.getLogger("app.request")


class RequestLoggingMiddleware:
    """Assigns a request id and logs method, path (no query), status and duration."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = Headers(scope=scope).get(REQUEST_ID_HEADER, "")
        rid = incoming if _REQUEST_ID_RE.fullmatch(incoming) else uuid.uuid4().hex
        token = request_id_var.set(rid)
        status = 500
        start = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = rid
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            request_logger.info(
                "request",
                extra={
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "status": status,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                },
            )
            request_id_var.reset(token)
