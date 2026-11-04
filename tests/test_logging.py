import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.logging import JsonFormatter, configure_logging
from app.main import create_app

SECRET = "s3cr3t-signing-value"  # noqa: S105
ENC = 'enc-k3y/with"quote'
SECRETS = [SECRET, ENC]


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).setLevel(logging.NOTSET)


def _lines(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    err = capsys.readouterr().err
    return [json.loads(line) for line in err.splitlines() if line.strip()]


def _client(level: str = "INFO") -> TestClient:
    settings = Settings(secret_key=SECRET, encryption_key=ENC, log_level=level)  # type: ignore[arg-type]
    return TestClient(create_app(settings))


def _request_records(lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in lines if r["logger"] == "app.request"]


def test_json_line_fields(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", SECRETS)
    logging.getLogger("x.y").warning("hello %s", "world")
    (rec,) = _lines(capsys)
    assert rec["level"] == "WARNING"
    assert rec["logger"] == "x.y"
    assert rec["message"] == "hello world"
    assert "timestamp" in rec
    assert "request_id" not in rec


@pytest.mark.parametrize(
    ("level", "expect_info"),
    [("INFO", True), ("DEBUG", True), ("WARNING", False), ("ERROR", False)],
)
def test_level_respected(capsys: pytest.CaptureFixture[str], level: str, expect_info: bool) -> None:
    configure_logging(level, SECRETS)
    logging.getLogger("lvl").info("i")
    assert bool(_lines(capsys)) is expect_info


def test_configure_is_idempotent(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", SECRETS)
    configure_logging("INFO", SECRETS)
    logging.getLogger("once").info("m")
    assert len(_lines(capsys)) == 1


def test_request_logged_with_generated_id(capsys: pytest.CaptureFixture[str]) -> None:
    with _client() as client:
        response = client.get("/healthz?token=abc&x=1")
    (rec,) = _request_records(_lines(capsys))
    assert rec["method"] == "GET"
    assert rec["path"] == "/healthz"
    assert rec["status"] == 200
    assert rec["duration_ms"] >= 0
    assert rec["request_id"] == response.headers["X-Request-ID"]
    assert "abc" not in json.dumps(rec)
    assert "?" not in json.dumps(rec)


@pytest.mark.parametrize(
    ("incoming", "trusted"),
    [
        ("abcdef123456", True),
        ("A.b_c-D1234", True),
        ("short", False),
        ("a" * 65, False),
        ("has space 12345", False),
        ('inj"ect\\12345', False),
        ("new\nline12345", False),
        ("ünïcode12345", False),
        ("", False),
    ],
)
def test_incoming_request_id(
    capsys: pytest.CaptureFixture[str], incoming: str, trusted: bool
) -> None:
    _send_with_id(capsys, incoming, trusted)


def _send_with_id(capsys: pytest.CaptureFixture[str], incoming: str, trusted: bool) -> None:
    import asyncio

    app = create_app(Settings(secret_key=SECRET, encryption_key=ENC))  # type: ignore[arg-type]
    configure_logging("INFO", SECRETS)
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/healthz",
        "raw_path": b"/healthz",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"x-request-id", incoming.encode("utf-8"))],
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
    }
    asyncio.run(app(scope, receive, send))  # type: ignore[arg-type]
    start = next(m for m in sent if m["type"] == "http.response.start")
    rid = dict(start["headers"])[b"x-request-id"].decode()
    assert (rid == incoming) is trusted
    (rec,) = _request_records(_lines(capsys))
    assert rec["request_id"] == rid


def test_error_status_logged(capsys: pytest.CaptureFixture[str]) -> None:
    with _client() as client:
        client.get("/nope")
    (rec,) = _request_records(_lines(capsys))
    assert rec["status"] == 404


def test_secrets_and_sensitive_fields_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("DEBUG", SECRETS)
    log = logging.getLogger("redact")
    log.info("key is %s and %s", SECRET, ENC)
    log.info(
        "extra",
        extra={
            "Authorization": "Bearer abc.def",
            "cookie": "session=zzz",
            "password": "hunter2",
            "headers": {"Cookie": "c=1", "Authorization": "Basic Zm9v", "ok": "fine"},
        },
    )
    try:
        raise RuntimeError(f"boom {SECRET}")
    except RuntimeError:
        log.exception("failed")
    out = capsys.readouterr().err
    for leaked in (SECRET, ENC, "Bearer abc.def", "session=zzz", "hunter2", "Basic Zm9v", "c=1"):
        assert leaked not in out
    assert "enc-k3y" not in out
    assert '"ok": "fine"' in out


def test_secrets_not_logged_by_requests(capsys: pytest.CaptureFixture[str]) -> None:
    with _client() as client:
        client.get(
            "/healthz",
            headers={"Authorization": f"Bearer {SECRET}", "Cookie": f"s={SECRET}"},
            params={"password": "hunter2"},
        )
    # Only the app's own records: httpx (the test client) logs its own outgoing URL.
    out = json.dumps(_request_records(_lines(capsys)))
    assert SECRET not in out
    assert "hunter2" not in out
    assert "Bearer" not in out


def test_uvicorn_loggers_use_json_and_strip_query(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", SECRETS)
    logging.getLogger("uvicorn.error").info("started")
    logging.getLogger("uvicorn.access").info(
        '%s - "%s %s HTTP/%s" %d', "127.0.0.1:1", "GET", "/healthz?token=abc", "1.1", 200
    )
    recs = _lines(capsys)
    assert [r["logger"] for r in recs] == ["uvicorn.error", "uvicorn.access"]
    assert "abc" not in recs[1]["message"]
    assert "/healthz" in recs[1]["message"]


def test_formatter_ignores_empty_secret() -> None:
    fmt = JsonFormatter(["", SECRET])
    record = logging.LogRecord("n", logging.INFO, "f", 1, "plain text", None, None)
    assert json.loads(fmt.format(record))["message"] == "plain text"
