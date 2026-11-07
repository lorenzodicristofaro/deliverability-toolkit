"""M4 acceptance (M4-14): message analysis across service, REST, CLI and UI.

Everything here is offline: sockets are blocked for the whole module and the DNS fake must see
zero questions. Corpus facts come from tests/fixtures/messages/MANIFEST.yaml; samples marked
`unverified` are only asserted to parse with all sections present (never vendor shape).
"""

from __future__ import annotations

import ast
import logging
import re
import socket
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
import yaml
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from app.api.v1.dns_tools import dns_backend
from app.cli.main import app as cli_app
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.main import create_app
from app.models import Membership
from app.models.base import Base
from app.parsers.message import MAX_RAW_BYTES
from app.services import message_findings
from app.services.message_analysis import MessageAnalysis, analyze_message
from tests.support.dns_backend import fake_backend
from tests.support.dns_zones import FakeServerSet
from tests.tenancy.test_matrix import MATRIX
from tests.web.test_domains_ui import CSRF_HEADER, KEY, ROOT, World, _login, _seed, post

REST = "/api/v1/message/analyze"
UI = "/tools/message"
FIXTURES = ROOT / "tests" / "fixtures" / "messages"
APP = ROOT / "app"
SAMPLES: list[dict[str, Any]] = yaml.safe_load((FIXTURES / "MANIFEST.yaml").read_text())["samples"]
IDS = [s["file"] for s in SAMPLES]
runner = CliRunner()


def _raw(sample: dict[str, Any]) -> bytes:
    return (FIXTURES / sample["file"]).read_bytes()


# --- fixtures ----------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_a: Any, **_k: Any) -> None:
        raise AssertionError("network access in the M4 suite")

    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)


@pytest.fixture
def env(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[World, FakeServerSet]]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
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
def spy(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Every call the REST and UI handlers make to the analyzer."""
    from app.api.v1 import message as message_api
    from app.web import message as message_web

    calls: list[bytes] = []

    def wrapper(raw: bytes) -> MessageAnalysis:
        calls.append(raw)
        return analyze_message(raw)

    monkeypatch.setattr(message_api, "analyze_message", wrapper)
    monkeypatch.setattr(message_web, "analyze_message", wrapper)
    return calls


# --- surface helpers ---------------------------------------------------------------------------


def rest(w: World, who: str, raw: bytes, *, tenant_id: int | None = None) -> Any:
    token = _login(w, who, tenant_id)
    headers = {"Content-Type": "message/rfc822"}
    if token:
        headers[CSRF_HEADER] = token
    return w.client.post(REST, content=raw, headers=headers)


def ui(w: World, who: str, raw: bytes, *, tenant_id: int | None = None) -> Any:
    body = urlencode({"raw": raw.decode("utf-8")}).encode()
    return post(w, who, UI, content=body, tenant_id=tenant_id)


def cli(tmp_path: Path, raw: bytes, *args: str) -> Any:
    path = tmp_path / "m.eml"
    path.write_bytes(raw)
    return runner.invoke(cli_app, ["analyze", str(path), *args])


def ui_findings(html: str) -> list[tuple[str, str]]:
    return re.findall(r'<li data-code="([A-Z_]+)" data-severity="([a-z]+)"', html)


def ui_status(html: str) -> str:
    m = re.search(r'data-testid="message-result" data-status="([a-z]+)"', html)
    assert m, "no result block"
    return m.group(1)


def expected_exit(a: MessageAnalysis) -> int:
    return {"error": 2, "warn": 1, "fail": 1}.get(a.status, 0)


def rows(w: World) -> dict[str, int]:
    w.db.expire_all()
    return {
        t.name: w.db.scalar(select(func.count()).select_from(t)) or 0
        for t in Base.metadata.sorted_tables
    }


# --- corpus: manifest facts --------------------------------------------------------------------

DEFECTS: dict[str, Any] = {
    "nul_byte": lambda a: a.status == "error" and a.findings[0].code == "MSG_PARSER_LIMIT",
    "line_too_long": lambda a: a.status == "error" and a.findings[0].code == "MSG_PARSER_LIMIT",
    "date_without_timezone": lambda a: "MSG_DATE_NO_TIMEZONE" in {f.code for f in a.findings},
    "mime_depth": lambda a: "MSG_MIME_TRUNCATED" in {f.code for f in a.findings},
    "boundary_missing": lambda a: a.mime is not None and "missing_boundary" in a.mime.warnings,
    "bad_encoded_word": lambda a: "MSG_ENCODED_HEADER_BROKEN" in {f.code for f in a.findings},
}


@pytest.mark.parametrize("sample", SAMPLES, ids=IDS)
def test_corpus_sample_parses_with_sections(sample: dict[str, Any]) -> None:
    a = analyze_message(_raw(sample))
    assert a.status in ("ok", "info", "warn", "fail", "error")
    rejected = {"nul_byte", "line_too_long"} & set(sample["facts"].get("defects", []))
    if rejected:  # refused before parsing: no sections, a parser-limit finding
        assert a.summary is None and a.findings[0].code == "MSG_PARSER_LIMIT"
        return
    for section in ("summary", "received", "authentication", "arc", "alignment", "mime"):
        assert getattr(a, section) is not None, section


@pytest.mark.parametrize(
    "sample", [s for s in SAMPLES if s["status"] == "verified"], ids=lambda s: s["file"]
)
def test_verified_sample_facts(sample: dict[str, Any]) -> None:
    facts = sample["facts"]
    a = analyze_message(_raw(sample))
    assert (len(a.received.hops) if a.received else 0) == facts["hop_count"]
    if "auth_methods" in facts:
        assert a.authentication is not None
        got = [r.method for h in a.authentication for r in h.results]
        assert got == facts["auth_methods"]
    if "arc_chain" in facts:
        assert a.arc is not None
        assert a.arc.instance_count == facts["arc_chain"]["instances"]
        assert a.arc.status == facts["arc_chain"]["state"]
        if "cv" in facts["arc_chain"]:
            assert [s.cv for s in a.arc.sets] == facts["arc_chain"]["cv"]
    if "alignment" in facts:
        assert a.alignment is not None
        for kind in ("spf", "dkim"):
            states = {p.state for p in a.alignment.pairs if p.kind == kind}
            assert states == {facts["alignment"][kind]}, kind
    if "identifier_alignment" in facts:
        # identifier alignment (header.i / smtp.from vs From), independent of the stated results
        assert a.alignment is not None
        for kind in ("spf", "dkim"):
            assert facts["identifier_alignment"][kind] == "aligned"
            assert any(p.relaxed_aligned for p in a.alignment.pairs if p.kind == kind), kind
            # the RFC sample uses smtp.from / header.i, which the parser does not take as a
            # stated result: it keeps the pair `unknown` with reason `no_stated_result`
            assert {(p.state, p.reason) for p in a.alignment.pairs if p.relaxed_aligned} == {
                ("unknown", "no_stated_result")
            }
    if facts.get("must_not_crash"):
        for defect in facts["defects"]:
            assert DEFECTS[defect](a), defect


def test_fold_bomb_sample_is_accepted_and_bounded() -> None:
    sample = next(s for s in SAMPLES if s["file"] == "malformed-folding-bomb.eml")
    a = analyze_message(_raw(sample))
    assert a.summary is not None and a.summary.subject is not None
    assert "MSG_PARSER_LIMIT" not in {f.code for f in a.findings}
    assert len(a.summary.subject) <= message_findings.MAX_EXCERPT


def test_manifest_lists_every_eml() -> None:
    assert sorted(IDS) == sorted(p.name for p in FIXTURES.glob("*.eml"))


def test_provider_report(capsys: pytest.CaptureFixture[str]) -> None:
    verified = sorted({s["provider_label"] for s in SAMPLES if s["status"] == "verified"})
    unverified = sorted({s["provider_label"] for s in SAMPLES if s["status"] == "unverified"})
    with capsys.disabled():
        print(f"\nM4 corpus verified providers: {', '.join(verified)}")
        print(
            f"M4 corpus UNVERIFIED providers (maintainer samples pending): {', '.join(unverified)}"
        )
    assert {"gmail", "outlook", "ses", "sendgrid", "mailup"} == set(unverified)
    assert "plain-rfc" in verified and "arc-rfc8617" in verified


# --- identical results across surfaces ---------------------------------------------------------


def test_corpus_identical_on_every_surface(
    env: tuple[World, FakeServerSet], tmp_path: Path
) -> None:
    w, servers = env
    for sample in SAMPLES:
        raw = _raw(sample)
        expected = analyze_message(raw)
        want = expected.model_dump_json()
        name = sample["file"]

        c = cli(tmp_path, raw, "--format", "json")
        if sample.get("contains_nul"):
            assert c.exit_code == 2, name
            assert rest(w, "analyst", raw).status_code == 422, name
            assert ui(w, "analyst", raw).status_code == 422, name
            continue
        assert c.exit_code == expected_exit(expected), name
        assert c.stdout == want + "\n", name  # exactly one trailing newline

        r = rest(w, "analyst", raw)
        assert r.status_code == 200, name
        assert r.content == want.encode(), name

        h = ui(w, "analyst", raw)
        assert h.status_code == 200, name
        assert ui_status(h.text) == expected.status, name
        assert ui_findings(h.text) == [(f.code, f.severity) for f in expected.findings], name
    assert servers.all_questions == []
    assert servers.server_queries == []


def test_pass_despite_unknown_sibling() -> None:
    """spf=pass with an aligned smtp.mailfrom plus dkim=pass without header.d: computed pass."""
    raw = (
        b"From: a@example.com\r\n"
        b"Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass\r\n"
        b"\r\nbody\r\n"
    )
    a = analyze_message(raw)
    assert a.alignment is not None
    states = {p.kind: p.state for p in a.alignment.pairs}
    assert states == {"spf": "aligned", "dkim": "unknown"}
    assert a.alignment.computed_dmarc == "pass"


# --- hostile input ------------------------------------------------------------------------------

_FROM = b"From: a@example.com\r\n"
_RECV = b"Received: from a.example by b.example; Mon, 1 Jan 2024 10:00:00 +0000\r\n"
_DEEP = b"".join(
    f"Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n".encode() for i in range(100)
)

# name -> (raw, REST status, UI status, analysis status or None when rejected before analysis,
#          a finding code that must be present)
HOSTILE: dict[str, tuple[bytes, int, int, str | None, str]] = {
    "oversize": (b"Subject: x\r\n\r\n" + b"a" * MAX_RAW_BYTES, 413, 413, None, ""),
    "nul": (_FROM + b"\r\nbo\x00dy", 422, 422, None, ""),
    "fold_bomb": (
        b"Subject: a\r\n" + b" x\r\n" * 40000 + b"\r\nbody",
        200,
        200,
        "error",
        "MSG_PARSER_LIMIT",
    ),
    "headers_501": (
        b"".join(f"X-H{i}: v\r\n".encode() for i in range(501)) + b"\r\nb",
        200,
        200,
        "error",
        "MSG_PARSER_LIMIT",
    ),
    "deep_mime": (_FROM + _DEEP + b"x", 200, 200, "warn", "MSG_MIME_TRUNCATED"),
    "received_10k": (_RECV * 10000 + b"\r\nbody", 200, 200, "error", "MSG_PARSER_LIMIT"),
    "received_200": (_FROM + _RECV * 200 + b"\r\nbody", 200, 200, "error", "MSG_PARSER_LIMIT"),
    "rfc2047_junk": (
        _FROM + b"Subject: =?utf-8?B?!!!?= =?x-unknown?Q?a?= =?utf-8?Q?unterminated\r\n\r\nb",
        200,
        200,
        "warn",
        "MSG_ENCODED_HEADER_BROKEN",
    ),
    "invalid_date": (_FROM + b"Date: not a date\r\n\r\nb", 200, 200, "error", "MSG_DATE_INVALID"),
    "date_no_timezone": (
        _FROM + b"Date: Thu, 14 Jan 2015 15:00:01\r\n\r\nb",
        200,
        200,
        "error",
        "MSG_DATE_NO_TIMEZONE",
    ),
}


@pytest.mark.parametrize("case", list(HOSTILE))
def test_hostile_input_on_every_surface(
    env: tuple[World, FakeServerSet], tmp_path: Path, case: str
) -> None:
    w, servers = env
    raw, rest_status, ui_status_code, status, code = HOSTILE[case]
    started = time.monotonic()

    r = rest(w, "analyst", raw)
    h = ui(w, "analyst", raw)
    c = cli(tmp_path, raw, "--format", "json")

    assert r.status_code == rest_status
    assert h.status_code == ui_status_code
    if status is None:
        assert c.exit_code == 2
    else:
        a = analyze_message(raw)
        assert a.status == status
        assert code in {f.code for f in a.findings}
        assert r.content == a.model_dump_json().encode()
        assert c.stdout == a.model_dump_json() + "\n"
        assert c.exit_code == expected_exit(a)
        assert ui_status(h.text) == status
    assert time.monotonic() - started < 30  # never a hang
    assert servers.all_questions == []


# --- permissions -------------------------------------------------------------------------------

M4_ROUTES = [("GET", UI), ("POST", UI), ("POST", REST)]
MESSAGE = (
    b"From: Alice <alice@example.com>\r\nTo: bob@example.net\r\n"
    b"Subject: SECRET-SUBJECT-4242\r\nDate: Mon, 01 Jan 2024 10:00:00 +0000\r\n"
    b"Message-ID: <m1@example.com>\r\n\r\nSECRET-BODY-9191\r\n"
)


def test_m4_routes_are_in_the_matrix() -> None:
    assert set(M4_ROUTES) <= set(MATRIX)
    from tests.tenancy.test_matrix import LEAVES

    message_routes = {leaf.key for leaf in LEAVES if "message" in leaf.path}
    assert message_routes == set(M4_ROUTES)


def test_denied_cases_never_invoke_the_analyzer(
    env: tuple[World, FakeServerSet], spy: list[bytes]
) -> None:
    w, _ = env
    expected = {"anon": (401, 401), "viewer": (403, 403)}
    for who, (rest_status, ui_status_code) in expected.items():
        assert rest(w, who, MESSAGE).status_code == rest_status, who
        assert ui(w, who, MESSAGE).status_code == ui_status_code, who
    # a session whose active tenant is not the user's tenant has no TenantContext
    assert rest(w, "analyst", MESSAGE, tenant_id=w.tenant_b).status_code == 404
    assert ui(w, "analyst", MESSAGE, tenant_id=w.tenant_b).status_code == 404
    assert spy == []

    member = w.db.scalars(select(Membership).where(Membership.user_id == w.users["analyst"])).one()
    member.feature_toggles = {"message.analyze": False}
    w.db.commit()
    assert rest(w, "analyst", MESSAGE).status_code == 403
    assert ui(w, "analyst", MESSAGE).status_code == 403
    assert spy == []


def test_allowed_roles_do_invoke_it(env: tuple[World, FakeServerSet], spy: list[bytes]) -> None:
    w, _ = env
    for who in ("owner", "admin", "analyst"):
        assert rest(w, who, MESSAGE).status_code == 200
        assert ui(w, who, MESSAGE).status_code == 200
    assert len(spy) == 6


# --- nothing stored, nothing logged ------------------------------------------------------------


def test_no_persistence_and_no_content_in_logs(
    env: tuple[World, FakeServerSet], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    w, servers = env
    _login(w, "analyst")
    before = rows(w)
    caplog.set_level(logging.DEBUG)
    assert rest(w, "analyst", MESSAGE).status_code == 200
    assert ui(w, "analyst", MESSAGE).status_code == 200
    assert cli(tmp_path, MESSAGE, "--format", "json").exit_code in (0, 1)
    assert rows(w) == before
    logged = "\n".join(f"{rec.getMessage()} {rec.__dict__}" for rec in caplog.records)
    for secret in (
        "SECRET-SUBJECT-4242",
        "SECRET-BODY-9191",
        "alice@example.com",
        "bob@example.net",
    ):
        assert secret not in logged
    assert servers.all_questions == []


# --- i18n completeness -------------------------------------------------------------------------

M4_PREFIXES = ("message.", "api.message.", "cli.analyze.", "finding.MSG_")
M4_SOURCES = [
    APP / "web" / "message.py",
    APP / "api" / "v1" / "message.py",
    APP / "cli" / "analyze.py",
    APP / "services" / "message_analysis.py",
    APP / "services" / "message_findings.py",
]
M4_TEMPLATES = sorted((APP / "web" / "templates" / "message").glob("*.html"))


def test_every_finding_code_has_en_and_it_text() -> None:
    for lang in i18n.SUPPORTED_LANGUAGES:
        cat = i18n.load_catalogue(lang)
        for code in message_findings.CODES:
            for part in ("title", "detail", "remediation"):
                assert cat.get(f"finding.{code}.{part}", "").strip(), (lang, code, part)


def test_m4_keys_are_identical_in_both_locales() -> None:
    en, it = (i18n.load_catalogue(lang) for lang in ("en", "it"))
    m4 = lambda cat: {k for k in cat if k.startswith(M4_PREFIXES)}  # noqa: E731
    assert m4(en) == m4(it)
    for key in m4(en):
        assert i18n.placeholders(en[key]) == i18n.placeholders(it[key]), key


def _referenced_keys() -> set[str]:
    keys: set[str] = set()
    for path in M4_SOURCES:
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith(M4_PREFIXES)
                and " " not in node.value
            ):
                keys.add(node.value)
    for path in M4_TEMPLATES:
        keys |= set(re.findall(r"""\bt\(\s*["']([^"']+)["']""", path.read_text()))
    return {k for k in keys if not k.endswith(".")}


def test_every_referenced_m4_key_exists_in_both_locales() -> None:
    keys = _referenced_keys()
    assert len(keys) > 40  # the scan really found the keys
    for lang in i18n.SUPPORTED_LANGUAGES:
        cat = i18n.load_catalogue(lang)
        missing = sorted(k for k in keys if k not in cat and not k.startswith("finding.MSG_"))
        assert missing == [], (lang, missing)


_KEY = re.compile(r"^[a-z][a-z0-9_]*(\.[A-Za-z0-9_]+)+\.?$")
_T_CALL = re.compile(r"""\bt\(\s*(["'])[^"']*\1""")
_JINJA_EXPR = re.compile(r"\{\{(.*?)\}\}", re.S)
_TEXT_ATTRS = re.compile(
    r"""\b(placeholder|title|aria-label|alt|value)\s*=\s*("[^"]*"|'[^']*')""", re.S
)
_LETTERS = re.compile(r"[A-Za-z]{2,}")


def _expr_literals(expr: str) -> list[str]:
    """String literals with letters in a Jinja expression, outside t("key") calls."""
    expr = _T_CALL.sub("t()", expr)
    found = re.finditer(r"""(["'])([^"']*)\1""", expr)
    return [m.group(2) for m in found if _LETTERS.search(m.group(2))]


def scan_template(src: str) -> list[str]:
    """Hardcoded user-facing text in a template: text nodes, literals printed by `{{ }}` and
    the text attributes placeholder, title, aria-label, alt and value."""
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    src = re.sub(r"\{%.*?%\}", "", src, flags=re.S)
    src = re.sub(r"<(script|style)\b.*?</\1>", "", src, flags=re.S)
    found: list[str] = []
    for tag in re.finditer(r"<[^>]*>", src, flags=re.S):
        for attr in _TEXT_ATTRS.finditer(tag.group(0)):
            value = attr.group(2)[1:-1]
            for expr in _JINJA_EXPR.findall(value):
                found += _expr_literals(expr)
            found += _LETTERS.findall(_JINJA_EXPR.sub("", value))
    text = re.sub(r"<[^>]*>", "", src, flags=re.S)
    for expr in _JINJA_EXPR.findall(text):
        found += _expr_literals(expr)
    plain = re.sub(r"&\w+;", "", _JINJA_EXPR.sub("", text))
    found += re.findall(r"[A-Za-z]{3,}", plain)
    return found


# Non-text literals the CLI may use: option names, mode words and status names.
_CLI_ALLOWED = frozenset({"text", "json", "error", "warn", "fail", "rb", "--format", "--lang"})


def scan_python(source: str, catalogue: dict[str, str]) -> list[str]:
    """String literals with letters that are neither docstrings, i18n keys (existing in the
    catalogue, or a key prefix) nor an allowed non-text word."""
    tree = ast.parse(source)
    skip: set[int] = set()
    for n in ast.walk(tree):
        if (
            isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef))
            and n.body
            and isinstance(n.body[0], ast.Expr)
            and isinstance(n.body[0].value, ast.Constant)
        ):
            skip.add(id(n.body[0].value))
    out: list[str] = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Constant) and isinstance(n.value, str)) or id(n) in skip:
            continue
        v = n.value
        if not re.search(r"[A-Za-z]", v) or v in _CLI_ALLOWED:
            continue
        if _KEY.match(v) and (v in catalogue or v.endswith(".")):
            continue
        out.append(v)
    return out


def test_no_hardcoded_text_in_m4_templates() -> None:
    assert M4_TEMPLATES
    for path in M4_TEMPLATES:
        assert scan_template(path.read_text()) == [], path.name


def test_no_hardcoded_text_in_the_cli_command() -> None:
    cat = i18n.load_catalogue("en")
    assert scan_python((APP / "cli" / "analyze.py").read_text(), cat) == []


@pytest.mark.parametrize(
    "html",
    [
        "<p>Hello world</p>",
        '<input placeholder="Paste here">',
        '<a title="Open">x</a>',
        '<button aria-label="Close">x</button>',
        '<img alt="Logo" src="x">',
        '<input type="submit" value="Analyze">',
        '<p>{{ "Literal" }}</p>',
        "<p>{{ 'Literal' if x else t('message.ok') }}</p>",
        "<input title=\"{{ 'Literal' }}\">",
        "<p>{# comment #}Stray</p>",
    ],
)
def test_template_scanner_catches_planted_text(html: str) -> None:
    assert scan_template(html) != []


@pytest.mark.parametrize(
    "html",
    [
        '<p>{{ t("message.section.summary") }}</p>',
        '<input placeholder="{{ t(\'message.x\') }}" value="{{ csrf_token() }}">',
        "<p class=\"{{ 'failure' if x else 'ok' }}\">{{ '· ' * 2 }}{{ v|visible }}</p>",
        "{# Only a comment #}{% if x %}<br>{% endif %}",
    ],
)
def test_template_scanner_accepts_keys_and_non_text(html: str) -> None:
    assert scan_template(html) == []


@pytest.mark.parametrize(
    "code",
    [
        'typer.echo("Error")',
        'typer.echo("Usage: analyze FILE")',
        'print("Done")',
        'x = f"Hop {n}"',
        'typer.echo("message.section.nonexistent")',
    ],
)
def test_python_scanner_catches_planted_text(code: str) -> None:
    assert scan_python(code, {"message.section.summary": "x"}) != []


def test_python_scanner_accepts_keys_docstrings_and_allowed_words() -> None:
    code = (
        '"""Module doc words."""\nx = t("message.section.summary")\n'
        'y = "json"\nz = "cli.check.status."'
    )
    assert scan_python(code, {"message.section.summary": "x"}) == []
