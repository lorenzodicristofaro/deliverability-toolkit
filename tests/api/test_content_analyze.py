"""M5-15 `POST /api/v1/content/analyze` through the real app and middleware.

The route is also in the M1-20 matrix (tests/tenancy/test_matrix.py); this file adds the role
table (a spy proves the analyzer never runs on a denial), the format/size rules, the
byte-for-byte contract, tenant-rule isolation and the offline / nothing-stored guarantees.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1 import content as content_api
from app.api.v1.dns_tools import dns_backend
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.tenancy import TenantContext
from app.main import create_app
from app.models import Membership
from app.models.base import Base
from app.parsers.message import MAX_RAW_BYTES
from app.repositories import repo_for
from app.services.content_analysis import ContentAnalysis, ContentInput, analyze_content
from tests.api.test_domains import KEY, World, _cookie, _seed, call
from tests.support.dns_backend import fake_backend
from tests.support.dns_zones import FakeServerSet
from tests.support.socket_guard import db_endpoint, install

URL = "/api/v1/content/analyze"
JSON = {"Content-Type": "application/json"}
EML_H = {"Content-Type": "message/rfc822"}
SECRET = "SECRET-BODY-9191"
EML = (
    b"From: Alice <alice@example.com>\r\nTo: bob@example.net\r\n"
    b"Subject: SECRET-SUBJECT-4242\r\nContent-Type: text/plain\r\n\r\n" + SECRET.encode() + b"\r\n"
)


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # Only the test database endpoint stays reachable (setup/teardown need it).
    install(monkeypatch, "content analyze API", db_endpoint())


@pytest.fixture
def world(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[World, FakeServerSet]]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    backend, servers = fake_backend()
    application.dependency_overrides[dns_backend] = lambda: backend
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains), servers
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> list[ContentInput]:
    """Records every analyzer call (and delegates to the real one)."""
    calls: list[ContentInput] = []

    def wrapper(ctx: TenantContext, session: Any, content: ContentInput) -> ContentAnalysis:
        calls.append(content)
        return analyze_content(ctx, session, content)

    monkeypatch.setattr(content_api, "analyze_content", wrapper)
    return calls


def post_json(w: World, who: str, body: Any = None, **kw: Any) -> Any:
    body = {"text": "hello there"} if body is None else body
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    kw.setdefault("headers", JSON)
    return call(w, who, "POST", URL, content=raw, **kw)


def post_eml(w: World, who: str, raw: bytes = EML, **kw: Any) -> Any:
    kw.setdefault("headers", EML_H)
    return call(w, who, "POST", URL, content=raw, **kw)


def problem(key: str, field: str, reason: str, lang: str = "en") -> dict[str, str]:
    return {"key": key, "message": t(key, lang), "field": field, "reason": reason}


# --- permissions and tenancy -------------------------------------------------------------------

EXPECTED = {"anon": 401, "owner": 200, "admin": 200, "analyst": 200, "viewer": 403}


@pytest.mark.parametrize("sender", [post_json, post_eml], ids=["json", "eml"])
@pytest.mark.parametrize("who", list(EXPECTED))
def test_role_table(
    world: tuple[World, Any], spy: list[ContentInput], who: str, sender: Any
) -> None:
    w, _ = world
    r = sender(w, who)
    assert r.status_code == EXPECTED[who], r.text[:200]
    if who == "anon":
        assert r.json() == {"detail": t("auth.required", "en")}
    if who == "viewer":
        assert r.json() == {"detail": t("api.error.forbidden", "en")}
    assert len(spy) == (1 if EXPECTED[who] == 200 else 0)


def test_foreign_tenant_is_404(world: tuple[World, Any], spy: list[ContentInput]) -> None:
    w, _ = world
    r = post_json(w, "analyst", tenant="b")
    assert r.status_code == 404
    assert r.json() == {"detail": t("api.error.not_found", "en")}
    assert spy == []


def test_user_without_membership_is_404(world: tuple[World, Any], spy: list[ContentInput]) -> None:
    w, _ = world
    m = w.db.scalars(select(Membership).where(Membership.user_id == w.users["analyst"])).one()
    w.db.delete(m)
    w.db.commit()
    assert post_json(w, "analyst").status_code == 404
    assert spy == []


def test_toggle_false_denies(world: tuple[World, Any], spy: list[ContentInput]) -> None:
    w, _ = world
    m = w.db.scalars(select(Membership).where(Membership.user_id == w.users["analyst"])).one()
    m.feature_toggles = {"content.analyze": False}
    w.db.commit()
    assert post_json(w, "analyst").status_code == 403
    assert spy == []


def test_client_viewer_toggle_cannot_grant(
    world: tuple[World, Any], spy: list[ContentInput]
) -> None:
    w, _ = world
    m = w.db.scalars(select(Membership).where(Membership.user_id == w.users["viewer"])).one()
    m.feature_toggles = {"content.analyze": True}
    w.db.commit()
    assert post_json(w, "viewer").status_code == 403
    assert spy == []


def test_csrf_is_required(world: tuple[World, Any], spy: list[ContentInput]) -> None:
    w, _ = world
    assert post_json(w, "analyst", csrf=False).status_code == 403
    assert post_json(w, "anon", csrf=False).status_code == 403
    assert spy == []


@pytest.mark.parametrize("who", ["anon", "viewer"])
def test_denied_before_body_is_inspected(
    world: tuple[World, Any], spy: list[ContentInput], who: str
) -> None:
    w, _ = world
    status = EXPECTED[who]
    assert post_json(w, who, b"").status_code == status
    assert post_json(w, who, b"a\x00b").status_code == status
    assert post_json(w, who, b"x" * (MAX_RAW_BYTES + 1)).status_code == status
    assert post_json(w, who, headers={"Content-Type": "text/html"}).status_code == status
    assert post_json(w, who, {"language": "!!"}).status_code == status
    assert spy == []


def test_other_tenants_rules_are_never_applied(world: tuple[World, Any]) -> None:
    w, _ = world
    base: dict[str, Any] = {
        "kind": "keyword",
        "weight": 10,
        "category": "spam",
        "severity": "medium",
        "enabled": True,
    }
    repo_a = repo_for(TenantContext(w.tenant_a, None), w.db).content_rules
    repo_b = repo_for(TenantContext(w.tenant_b, None), w.db).content_rules
    repo_a.create({**base, "name": "ra", "pattern": "zebraword", "title": "TITLE-A-RULE"})
    repo_b.create({**base, "name": "rb", "pattern": "okapiword", "title": "TITLE-B-RULE"})
    both = {"text": "zebraword and okapiword"}
    a = post_json(w, "analyst", both, tenant="a").json()
    assert {r["name"] for r in a["rules"]["facts"]["results"] if r["status"] == "matched"} == {"ra"}
    b = post_json(w, "b_owner", both, tenant="b").json()
    assert {r["name"] for r in b["rules"]["facts"]["results"] if r["status"] == "matched"} == {"rb"}


# --- format and size ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        JSON,
        {"Content-Type": "Application/JSON; charset=utf-8"},
    ],
)
def test_accepted_json_content_types(world: tuple[World, Any], headers: dict[str, str]) -> None:
    w, _ = world
    assert post_json(w, "analyst", headers=headers).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/plain"},
        {"Content-Type": "multipart/form-data; boundary=x"},
        {"Content-Type": "text/html"},
        {"Content-Type": ""},
    ],
)
def test_unsupported_media_type(
    world: tuple[World, Any], spy: list[ContentInput], headers: dict[str, str]
) -> None:
    w, _ = world
    r = post_json(w, "analyst", headers=headers)
    assert r.status_code == 415
    assert r.json()["detail"] == problem(
        "api.content.error.unsupported_media_type",
        "content_type",
        "unsupported_media_type",
    )
    assert spy == []


EMPTY = problem("api.content.error.empty", "body", "empty")


@pytest.mark.parametrize(
    "body",
    [b"", b"{}", b'{"html": "", "text": ""}', b'{"html": null}', b'{"subject": "only"}'],
)
def test_empty_json_is_422(world: tuple[World, Any], spy: list[ContentInput], body: bytes) -> None:
    w, _ = world
    r = post_json(w, "analyst", body)
    assert r.status_code == 422
    assert r.json()["detail"] == EMPTY
    assert spy == []


def test_empty_eml_is_422(world: tuple[World, Any], spy: list[ContentInput]) -> None:
    w, _ = world
    r = post_eml(w, "analyst", b"")
    assert r.status_code == 422
    assert r.json()["detail"] == EMPTY
    assert spy == []


@pytest.mark.parametrize(
    ("body", "field"),
    [
        (b'{"text": "a\\u0000b"}', "text"),
        (b'{"html": "<p>a\\u0000</p>"}', "html"),
        (b'{"text": "x", "subject": "s\\u0000"}', "subject"),
        (b'{"text": "x", "language": "e\\u0000"}', "language"),
        (b'{"text": "a\x00b"}', "body"),
        (b"\x00", "body"),
    ],
)
def test_nul_byte_is_422_without_echo(
    world: tuple[World, Any], spy: list[ContentInput], body: bytes, field: str
) -> None:
    w, _ = world
    r = post_json(w, "analyst", body)
    assert r.status_code == 422
    assert r.json()["detail"] == problem("api.content.error.nul_byte", field, "nul_byte")
    assert spy == []


def test_nul_byte_in_eml_is_422(world: tuple[World, Any], spy: list[ContentInput]) -> None:
    w, _ = world
    r = post_eml(w, "analyst", EML + b"\x00")
    assert r.status_code == 422
    assert r.json()["detail"]["key"] == "api.content.error.nul_byte"
    assert spy == []


@pytest.mark.parametrize("language", ["", "english", "e", "EN_us", "en-", "ü", "x" * 17, "en us"])
def test_invalid_language_is_422(
    world: tuple[World, Any], spy: list[ContentInput], language: str
) -> None:
    w, _ = world
    r = post_json(w, "analyst", {"text": "hi", "language": language})
    assert r.status_code == 422
    assert r.json()["detail"] == problem(
        "api.content.error.invalid_language", "language", "invalid_language"
    )
    assert spy == []


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"{not json", "malformed_json"),
        (b"\xff\xfe", "malformed_json"),
        (b'{"text": "a", "text": "b"}', "malformed_json"),
        (b'{"text": NaN}', "malformed_json"),
        (b"[" * 5000, "malformed_json"),
        (b'["text"]', "not_an_object"),
        (b'"text"', "not_an_object"),
        (b'{"text": "x", "extra": 1}', "unknown_field"),
        (b'{"text": 5}', "not_a_string"),
        (b'{"html": ["x"]}', "not_a_string"),
        (b'{"text": "x", "language": 5}', "not_a_string"),
    ],
)
def test_malformed_json_is_422(
    world: tuple[World, Any], spy: list[ContentInput], body: bytes, reason: str
) -> None:
    w, _ = world
    r = post_json(w, "analyst", body)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["key"] == "api.content.error.invalid_body"
    assert detail["reason"] == reason
    assert spy == []


def test_analyzer_runs_off_the_event_loop(
    world: tuple[World, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """analyze_content blocks for seconds: it must run in a worker thread, not on the loop."""
    w, _ = world
    on_loop: list[bool] = []

    def wrapper(ctx: TenantContext, session: Any, content: ContentInput) -> ContentAnalysis:
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        return analyze_content(ctx, session, content)

    monkeypatch.setattr(content_api, "analyze_content", wrapper)
    assert post_json(w, "analyst").status_code == 200
    assert on_loop == [False]


def test_no_transaction_is_held_during_body_read_and_analysis(
    world: tuple[World, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    w, _ = world
    events: list[str] = []
    real_read = content_api._read_capped
    real_rollback = Session.rollback
    in_tx: list[bool] = []

    async def read(request: Any) -> bytes:
        events.append("read")
        return await real_read(request)

    def rollback(self: Session) -> None:
        events.append("rollback")
        real_rollback(self)

    def wrapper(ctx: TenantContext, session: Any, content: ContentInput) -> ContentAnalysis:
        in_tx.append(session.in_transaction())
        return analyze_content(ctx, session, content)

    monkeypatch.setattr(content_api, "_read_capped", read)
    monkeypatch.setattr(Session, "rollback", rollback)
    monkeypatch.setattr(content_api, "analyze_content", wrapper)
    assert post_json(w, "analyst").status_code == 200
    assert "rollback" in events[: events.index("read")]
    assert in_tx == [False]


BAD_STRINGS = ["\\ud800", "\\udc00", "a\\ud800b", "\\ud83d\\ude00\\ud800"]


@pytest.mark.parametrize("bad", BAD_STRINGS)
@pytest.mark.parametrize("field", ["html", "text", "subject", "language"])
def test_lone_surrogates_are_clean(
    world: tuple[World, Any], spy: list[ContentInput], field: str, bad: str
) -> None:
    """JSON escapes yield lone surrogates, which cannot be UTF-8 encoded: never a 500."""
    w, _ = world
    extra = '"text": "hello", ' if field not in ("html", "text") else ""
    r = post_json(w, "analyst", (f'{{{extra}"{field}": "{bad}"}}').encode())
    if field == "language":
        assert r.status_code == 422
        assert r.json()["detail"]["key"] == "api.content.error.invalid_language"
        assert spy == []
    else:
        assert r.status_code == 200, r.text[:200]
        assert r.json()["status"] in {"ok", "warn", "fail", "error", "not_evaluated"}


@pytest.mark.parametrize("charset", ["latin-1", "bogus", "utf-16", '"utf-8"'])
def test_declared_charset_is_ignored_cleanly(world: tuple[World, Any], charset: str) -> None:
    """The body is always UTF-8 JSON; a declared charset neither crashes nor changes that."""
    w, _ = world
    headers = {"Content-Type": f"application/json; charset={charset}"}
    r = post_json(w, "analyst", {"text": "caf\u00e9"}, headers=headers)
    assert r.status_code == 200
    latin = post_json(w, "analyst", '{"text": "caf\u00e9"}'.encode("latin-1"), headers=headers)
    assert latin.status_code == 422
    assert latin.json()["detail"]["reason"] == "malformed_json"


@pytest.mark.parametrize("charset", ["latin-1", "bogus"])
@pytest.mark.parametrize("raw", [EML, EML.replace(b"text/plain", b"text/plain; charset=bogus")])
def test_eml_charsets_are_clean(world: tuple[World, Any], charset: str, raw: bytes) -> None:
    w, _ = world
    r = post_eml(w, "analyst", raw, headers={"Content-Type": f"message/rfc822; charset={charset}"})
    assert r.status_code == 200
    assert r.content == _service(w, eml=raw)


def test_language_hint_and_fields_reach_the_analyzer(
    world: tuple[World, Any], spy: list[ContentInput]
) -> None:
    w, _ = world
    body = {"html": "<p>hi</p>", "text": "hi", "subject": "S", "language": "IT-it"}
    assert post_json(w, "analyst", body).status_code == 200
    assert spy == [ContentInput(html="<p>hi</p>", text="hi", subject="S", language_hint="it-it")]
    assert post_eml(w, "analyst").status_code == 200
    assert spy[1] == ContentInput(eml=EML)


def test_error_messages_are_translated(world: tuple[World, Any]) -> None:
    w, _ = world
    r = post_json(w, "analyst", b"{}", headers={**JSON, "Accept-Language": "it"})
    assert r.status_code == 422
    assert r.json()["detail"]["message"] == t("api.content.error.empty", "it")
    assert t("api.content.error.empty", "it") != t("api.content.error.empty", "en")


def test_exactly_max_bytes_is_accepted(world: tuple[World, Any]) -> None:
    w, _ = world
    raw = b"Subject: x\r\n\r\n" + b"a" * (MAX_RAW_BYTES - 14)
    assert len(raw) == MAX_RAW_BYTES
    assert post_eml(w, "analyst", raw).status_code == 200


@pytest.mark.parametrize("sender", [post_json, post_eml], ids=["json", "eml"])
def test_over_cap_is_413_by_content_length(
    world: tuple[World, Any], spy: list[ContentInput], sender: Any
) -> None:
    w, _ = world
    r = sender(w, "analyst", b"a" * (MAX_RAW_BYTES + 1))
    assert r.status_code == 413
    assert r.json()["detail"] == problem("api.content.error.too_large", "body", "too_large")
    assert spy == []


def test_over_cap_is_413_when_streamed(world: tuple[World, Any], spy: list[ContentInput]) -> None:
    w, _ = world

    def chunks() -> Iterator[bytes]:
        for _ in range(MAX_RAW_BYTES // 65536 + 2):
            yield b"a" * 65536

    r = post_eml(w, "analyst", chunks())  # type: ignore[arg-type]
    assert r.status_code == 413
    assert spy == []


def test_bad_content_length_is_413(world: tuple[World, Any], spy: list[ContentInput]) -> None:
    w, _ = world
    r = post_eml(w, "analyst", headers={**EML_H, "Content-Length": "abc"})
    assert r.status_code == 413
    assert spy == []


async def test_reader_rejects_non_ascii_digit_length() -> None:
    """`"\u00b2".isdigit()` is True but `int()` raises: a clean 413, never a ValueError. (An HTTP
    client cannot send this header, so the reader is called directly.)"""
    req = _FakeRequest({"content-length": "\u00b2"}, total_chunks=5, size=10)
    with pytest.raises(HTTPException) as exc:
        await content_api._read_capped(req)  # type: ignore[arg-type]
    assert exc.value.status_code == 413
    assert req.pulled == 0


async def test_lying_content_length_is_still_counted() -> None:
    """A small declared length does not switch the counter off: it trips at the 4th chunk."""
    req = _FakeRequest({"content-length": "10"}, total_chunks=1000, size=MAX_RAW_BYTES // 4 + 1)
    with pytest.raises(HTTPException) as exc:
        await content_api._read_capped(req)  # type: ignore[arg-type]
    assert exc.value.status_code == 413
    assert req.pulled == 4


class _FakeRequest:
    def __init__(self, headers: dict[str, str], total_chunks: int, size: int) -> None:
        self.headers = headers
        self.scope: dict[str, Any] = {"headers": []}
        self.pulled = 0
        self._total = total_chunks
        self._size = size

    async def stream(self) -> AsyncIterator[bytes]:
        for _ in range(self._total):
            self.pulled += 1
            yield b"a" * self._size


async def test_reader_stops_at_the_first_chunk_over_the_cap() -> None:
    req = _FakeRequest({}, total_chunks=1000, size=MAX_RAW_BYTES // 4 + 1)
    with pytest.raises(HTTPException) as exc:
        await content_api._read_capped(req)  # type: ignore[arg-type]
    assert exc.value.status_code == 413
    assert req.pulled == 4


async def test_reader_rejects_declared_length_without_reading() -> None:
    req = _FakeRequest({"content-length": str(MAX_RAW_BYTES + 1)}, total_chunks=5, size=10)
    with pytest.raises(HTTPException) as exc:
        await content_api._read_capped(req)  # type: ignore[arg-type]
    assert exc.value.status_code == 413
    assert req.pulled == 0


# --- contract ----------------------------------------------------------------------------------


def _service(w: World, **fields: Any) -> bytes:
    ctx = TenantContext(w.tenant_a, None)
    return analyze_content(ctx, w.db, ContentInput(**fields)).model_dump_json().encode()


def test_json_response_is_byte_equal_to_the_service(world: tuple[World, Any]) -> None:
    w, _ = world
    body = {"html": "<p>Hello <a href='https://example.com'>x</a></p>", "subject": "Hi"}
    r = post_json(w, "owner", body)
    assert r.status_code == 200
    assert r.headers["content-type"].split(";")[0] == "application/json"
    assert r.content == _service(w, **body)


@pytest.mark.parametrize("raw", [EML, b"not a message at all", b"\xff\xfe garbage\r\n\r\n"])
def test_eml_response_is_byte_equal_to_the_service(world: tuple[World, Any], raw: bytes) -> None:
    w, _ = world
    r = post_eml(w, "owner", raw)
    assert r.status_code == 200
    assert r.content == _service(w, eml=raw)


def test_response_json_shape_is_frozen(world: tuple[World, Any]) -> None:
    w, _ = world
    data = post_json(w, "owner", {"text": "hello"}).json()
    assert set(data) == set(ContentAnalysis.model_fields)


# --- offline and nothing stored ----------------------------------------------------------------


def _count_rows(w: World) -> dict[str, int]:
    w.db.expire_all()
    return {
        table.name: w.db.scalar(select(func.count()).select_from(table)) or 0
        for table in Base.metadata.sorted_tables
    }


def test_offline_and_nothing_stored(
    world: tuple[World, FakeServerSet], caplog: pytest.LogCaptureFixture
) -> None:
    w, servers = world
    _cookie(w, "analyst", "a")  # session rows exist before the baseline
    before = _count_rows(w)
    caplog.set_level(logging.DEBUG)

    assert post_eml(w, "analyst").status_code == 200
    body = {"html": f"<p>{SECRET}</p>", "subject": "SECRET-SUBJECT-4242"}
    assert post_json(w, "analyst", body).status_code == 200

    assert servers.all_questions == []
    assert servers.server_queries == []
    assert _count_rows(w) == before
    logged = "\n".join(f"{rec.getMessage()} {rec.__dict__}" for rec in caplog.records)
    for secret in (SECRET, "SECRET-SUBJECT-4242", "alice@example.com", "bob@example.net"):
        assert secret not in logged


DENIED_BODIES = [
    ("413", EML_H, b"a" * (MAX_RAW_BYTES + 1) + SECRET.encode()),
    ("415", {"Content-Type": "text/plain"}, EML),
    ("422-empty", EML_H, b""),
    ("422-nul", EML_H, EML + b"\x00"),
    ("422-json", JSON, b'{"text": "SECRET-BODY-9191", "bogus": 1}'),
    ("422-lang", JSON, b'{"text": "SECRET-BODY-9191", "language": "SECRET-BODY-9191"}'),
]


@pytest.mark.parametrize(
    ("label", "headers", "raw"), DENIED_BODIES, ids=[d[0] for d in DENIED_BODIES]
)
def test_rejected_requests_do_not_log_content(
    world: tuple[World, Any],
    caplog: pytest.LogCaptureFixture,
    label: str,
    headers: dict[str, str],
    raw: bytes,
) -> None:
    w, _ = world
    caplog.set_level(logging.DEBUG)
    r = post_eml(w, "analyst", raw, headers=headers)
    assert r.status_code in (413, 415, 422), label
    assert SECRET not in r.text
    logged = "\n".join(f"{rec.getMessage()} {rec.__dict__}" for rec in caplog.records)
    for secret in (SECRET, "SECRET-SUBJECT-4242", "alice@example.com"):
        assert secret not in logged
