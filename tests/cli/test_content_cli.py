"""M5-17: CLI `content` command. Offline apart from the test database (socket guard).

Runs on SQLite and, with TEST_DATABASE_URL, on PostgreSQL (`migrated_db_url`).
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import typer
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from app.checks.models import Finding
from app.cli import content as cli_content
from app.cli.main import app
from app.cli.tenant_scope import EXIT_DENIED
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.tenancy import TenantContext
from app.main import create_app
from app.parsers.message import MAX_RAW_BYTES
from app.repositories import repo_for
from app.services.content_analysis import (
    BodySection,
    ContentAnalysis,
    ContentInput,
    LinksSection,
    RulesFacts,
    RulesSection,
    RuleView,
    SubjectSection,
    UnsubscribeSection,
    analyze_content,
)
from tests.api.test_domains import KEY, _seed, call
from tests.api.test_domains import World as ApiWorld
from tests.support.socket_guard import db_endpoint, install

runner = CliRunner()
EML = (
    b"From: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: hello\r\n"
    b"Message-ID: <m1@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n"
    b"zebraword here\r\n"
)
# Latin-1 body byte (0xe8): not valid UTF-8, so `--eml` must never decode the file.
EML_8BIT = (
    b"From: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: hello\r\n"
    b"Message-ID: <m2@example.com>\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
    b"zebraword caff\xe8\r\n"
)
API_URL = "/api/v1/content/analyze"
RULE = {
    "kind": "keyword",
    "weight": 10,
    "category": "spam",
    "severity": "medium",
    "enabled": True,
}


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "the CLI content suite", db_endpoint())


@pytest.fixture(autouse=True)
def _strict_i18n() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@dataclass
class World:
    url: str
    a: int
    b: int
    users: dict[str, int]


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> World:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    try:
        a, b, users, _ = _seed(db)
    finally:
        db.close()
        engine.dispose()
    return World(migrated_db_url, a, b, users)


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> list[ContentInput]:
    calls: list[ContentInput] = []

    def wrapper(ctx: TenantContext, session: Any, content: ContentInput) -> ContentAnalysis:
        calls.append(content)
        return analyze_content(ctx, session, content)

    monkeypatch.setattr(cli_content, "analyze_content", wrapper)
    return calls


@pytest.fixture
def api(world: World) -> Iterator[ApiWorld]:
    """The real API app and middleware on the same database as the CLI runs."""
    settings = Settings(database_url=world.url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    engine = create_db_engine(world.url)
    db = create_session_factory(engine)()
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield ApiWorld(client, db, settings, world.a, world.b, world.users, {})
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def _add_rules(w: World, tenant: int, name: str, pattern: str, language: str | None = None) -> None:
    engine = create_db_engine(w.url)
    db = create_session_factory(engine)()
    try:
        repo_for(TenantContext(tenant, None), db).content_rules.create(
            {
                **RULE,
                "name": name,
                "pattern": pattern,
                "title": f"TITLE-{name}",
                "language": language,
            }
        )
        db.commit()
    finally:
        db.close()
        engine.dispose()


def _service(w: World, tenant: int, user: str, content: ContentInput) -> ContentAnalysis:
    engine = create_db_engine(w.url)
    db = create_session_factory(engine)()
    try:
        return analyze_content(TenantContext(tenant, w.users[user]), db, content)
    finally:
        db.close()
        engine.dispose()


def _run(w: World, user: str, *args: str, tenant: int | None = None, **kw: Any) -> Any:
    ids = ["--tenant-id", str(tenant or w.a), "--user-id", str(w.users[user])]
    return runner.invoke(app, ["content", *ids, *args], **kw)


def _file(tmp_path: Path, data: bytes | str, name: str = "in.txt") -> str:
    p = tmp_path / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


# --- permission ---------------------------------------------------------------------------------


def test_client_viewer_is_denied_before_any_input_is_read(
    world: World, spy: list[ContentInput], tmp_path: Path
) -> None:
    ok = _file(tmp_path, "hello there")
    for args in (["--text", ok], ["--text", str(tmp_path / "missing")], ["--text", "-"]):
        r = _run(world, "viewer", *args, input=b"hello")
        assert r.exit_code == EXIT_DENIED, r.output
        assert r.stderr.strip() == t("cli.operator.error.denied")
        assert r.stdout == ""
    assert spy == []


def test_foreign_tenant_user_is_denied(
    world: World, spy: list[ContentInput], tmp_path: Path
) -> None:
    r = _run(world, "b_owner", "--text", _file(tmp_path, "hi"), tenant=world.a)
    assert r.exit_code == EXIT_DENIED
    assert spy == []


@pytest.mark.parametrize("who", ["owner", "admin", "analyst"])
def test_allowed_roles_run(world: World, who: str, tmp_path: Path) -> None:
    r = _run(world, who, "--text", _file(tmp_path, "hello there"), "--json")
    assert r.exit_code in (0, 1), r.output


# --- JSON equals the service --------------------------------------------------------------------


def test_json_is_byte_equal_to_the_service(world: World, tmp_path: Path) -> None:
    _add_rules(world, world.a, "ra", "zebraword")
    html = _file(tmp_path, "<p>zebraword <a href='https://x.example/'>go</a></p>", "a.html")
    txt = _file(tmp_path, "zebraword plain", "a.txt")
    r = _run(
        world, "analyst", "--html", html, "--text", txt, "--subject", "Hi", "--lang", "EN", "--json"
    )
    expected = _service(
        world,
        world.a,
        "analyst",
        ContentInput(
            html="<p>zebraword <a href='https://x.example/'>go</a></p>",
            text="zebraword plain",
            subject="Hi",
            language_hint="en",
        ),
    )
    assert r.stdout == expected.model_dump_json() + "\n"
    assert r.exit_code == cli_content.exit_code(expected)


def _matched(body: bytes | str) -> set[str]:
    results = json.loads(body)["rules"]["facts"]["results"]
    return {r["name"] for r in results if r["status"] == "matched"}


def test_json_is_byte_equal_to_the_api(api: ApiWorld, world: World, tmp_path: Path) -> None:
    _add_rules(world, world.a, "ra", "zebraword")
    _add_rules(world, world.a, "rl", "zebraword", language="en")  # runs only if --lang arrives
    _add_rules(world, world.b, "rb", "zebraword")  # the other tenant's rule must not apply
    body = {
        "html": "<p>zebraword caffè <a href='https://x.example/'>go</a></p>",
        "text": "zebraword plain caffè",
        "subject": "Ciao è",
        "language": "EN",
    }
    resp = call(
        api,
        "analyst",
        "POST",
        API_URL,
        content=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    r = _run(
        world,
        "analyst",
        "--html",
        _file(tmp_path, body["html"], "a.html"),
        "--text",
        _file(tmp_path, body["text"], "a.txt"),
        "--subject",
        body["subject"],
        "--lang",
        body["language"],
        "--json",
    )
    assert r.stdout_bytes == resp.content + b"\n"
    assert _matched(resp.content) == {"ra", "rl"}
    assert r.exit_code == cli_content.exit_code(ContentAnalysis.model_validate_json(resp.content))


@pytest.mark.parametrize("raw", [EML, EML_8BIT], ids=["ascii", "8bit"])
def test_eml_json_is_byte_equal_to_the_api(
    api: ApiWorld, world: World, tmp_path: Path, raw: bytes
) -> None:
    _add_rules(world, world.a, "ra", "zebraword")
    resp = call(
        api, "owner", "POST", API_URL, content=raw, headers={"Content-Type": "message/rfc822"}
    )
    assert resp.status_code == 200, resp.text
    r = _run(world, "owner", "--eml", _file(tmp_path, raw, "m.eml"), "--json")
    assert r.stdout_bytes == resp.content + b"\n"
    assert _matched(resp.content) == {"ra"}
    assert r.exit_code == cli_content.exit_code(ContentAnalysis.model_validate_json(resp.content))


def test_eml_and_stdin_give_the_same_json(world: World, tmp_path: Path) -> None:
    from_file = _run(world, "owner", "--eml", _file(tmp_path, EML, "m.eml"), "--json")
    from_stdin = _run(world, "owner", "--eml", "-", "--json", input=EML)
    assert from_stdin.stdout == from_file.stdout
    assert from_stdin.exit_code == from_file.exit_code
    expected = _service(world, world.a, "owner", ContentInput(eml=EML))
    assert from_file.stdout == expected.model_dump_json() + "\n"


def test_text_output_shows_matched_rule_evidence_and_completeness(
    world: World, tmp_path: Path
) -> None:
    _add_rules(world, world.a, "ra", "zebraword")
    r = _run(world, "analyst", "--text", _file(tmp_path, "a zebraword b"))
    assert r.exit_code in (0, 1), r.output
    assert "ra" in r.stdout
    assert t("cli.check.evidence", text="a zebraword b") in r.stdout
    assert f"{t('cli.content.complete')}:" in r.stdout


def test_other_tenants_rules_are_not_applied(world: World, tmp_path: Path) -> None:
    _add_rules(world, world.a, "ra", "zebraword")
    _add_rules(world, world.b, "rb", "okapiword")
    r = _run(world, "analyst", "--text", _file(tmp_path, "zebraword okapiword"), "--json")
    names = {rule["name"] for rule in json.loads(r.stdout)["rules"]["facts"]["results"]}
    assert names == {"ra"}  # tenant B's rule is not among the rules that ran


def test_no_rules_is_not_reported_as_nothing_matched(world: World, tmp_path: Path) -> None:
    # No tenant or global rules in this database: the rules did not run, so say so and exit 1.
    r = _run(world, "analyst", "--text", _file(tmp_path, "hello there friend"))
    assert t("cli.content.rules.not_evaluated") in r.stdout
    assert t("cli.content.rules.none") not in r.stdout
    assert r.exit_code != 0


def test_no_rules_message_in_italian(world: World, tmp_path: Path) -> None:
    r = _run(world, "analyst", "--text", _file(tmp_path, "hello there"), "--output-lang", "it")
    assert t("cli.content.rules.not_evaluated", "it") in r.stdout


def test_none_matched_only_when_every_rule_ran(world: World, tmp_path: Path) -> None:
    _add_rules(world, world.a, "ra", "absentword")
    r = _run(world, "analyst", "--text", _file(tmp_path, "hello there friend"))
    analysis = _service(world, world.a, "analyst", ContentInput(text="hello there friend"))
    facts = analysis.rules.facts
    assert facts is not None
    verdict = facts.evaluated_rules > 0 and not facts.error_rules and not analysis.rules.reasons
    assert (t("cli.content.rules.none") in r.stdout) == (verdict and not facts.not_evaluated_rules)


def test_language_skipped_partial_run_is_not_reported_as_nothing_matched(
    world: World, tmp_path: Path
) -> None:
    # No hint: the language rule is left out, the other rule reaches a verdict and does not match.
    _add_rules(world, world.a, "plain", "absentword")
    _add_rules(world, world.a, "english", "absentword", language="en")
    source = "hello there friend"
    analysis = _service(world, world.a, "analyst", ContentInput(text=source))
    facts = analysis.rules.facts
    assert facts is not None
    assert (facts.skipped_by_language, facts.evaluated_rules) == (1, 1)
    assert (facts.error_rules, facts.not_evaluated_rules) == (0, 0)
    assert analysis.rules.reasons == ("language_rules_skipped",)
    r = _run(world, "analyst", "--text", _file(tmp_path, source))
    assert t("cli.content.rules.none") not in r.stdout
    assert t("cli.content.rules.not_evaluated") in r.stdout
    assert r.exit_code == 1


# --- text rendering of built results ------------------------------------------------------------


def _rule_view(**update: Any) -> RuleView:
    values: dict[str, Any] = {
        "rule_id": 1,
        "seed_key": None,
        "name": "rule-name",
        "category": "spam",
        "severity": "medium",
        "weight": 10,
        "status": "matched",
        "issue": None,
        "part": "text",
        "evidence": None,
    }
    return RuleView(**{**values, **update})


def _built(
    *,
    status: str = "ok",
    complete: bool = True,
    reasons: tuple[str, ...] = (),
    rule: RuleView | None = None,
    finding: Finding | None = None,
) -> ContentAnalysis:
    results = () if rule is None else (rule,)
    counts = {"matched": 0, "ok": 0, "error": 0, "not_evaluated": 0}
    for row in results:
        counts[row.status] += 1
    facts = RulesFacts(
        enabled_rules=len(results),
        skipped_by_language=0,
        evaluated_rules=counts["matched"] + counts["ok"],
        matched_rules=counts["matched"],
        error_rules=counts["error"],
        not_evaluated_rules=counts["not_evaluated"],
        score=0,
        complete=complete,
        capped_parts=(),
        categories=(),
        results=results,
    )
    return ContentAnalysis(
        status=status,  # type: ignore[arg-type]
        complete=complete,
        not_evaluated_sections=(),
        message=None,
        body=BodySection(status="ok", reasons=reasons),
        links=LinksSection(status="ok", reasons=()),
        subject=SubjectSection(status="ok", reasons=()),
        unsubscribe=UnsubscribeSection(status="ok", reasons=()),
        rules=RulesSection(status="ok", reasons=(), facts=facts),
        findings=() if finding is None else (finding,),
    )


def _finding(**update: Any) -> Finding:
    key = "cli.check.evidence"  # any key whose template shows the `text` parameter
    values: dict[str, Any] = {
        "code": "CONTENT_TEST",
        "severity": "low",
        "title_key": key,
        "detail_key": key,
        "remediation_key": key,
        "params": {"text": "ok"},
    }
    return Finding(**{**values, **update})


# One entry per place render_text prints a value that can come from the message or a rule.
_INJECTION_PATHS: dict[str, Callable[[str], ContentAnalysis]] = {
    "section_reason": lambda p: _built(reasons=(p,)),
    "matched_issue": lambda p: _built(rule=_rule_view(issue=p)),
    "matched_category": lambda p: _built(rule=_rule_view(category=p)),
    "matched_name": lambda p: _built(rule=_rule_view(name=p)),
    "matched_evidence": lambda p: _built(rule=_rule_view(evidence=p)),
    "failed_issue": lambda p: _built(rule=_rule_view(status="error", issue=p)),
    "failed_name": lambda p: _built(rule=_rule_view(status="error", name=p)),
    "finding_param": lambda p: _built(finding=_finding(params={"text": p})),
    "finding_evidence": lambda p: _built(finding=_finding(evidence=(p,))),
}


@pytest.mark.parametrize("path", sorted(_INJECTION_PATHS))
@pytest.mark.parametrize(
    ("char", "escaped"),
    [("\x1b", "\\x1b"), ("\x9b", "\\x9b"), ("\u202e", "\\u202e"), ("\n", "\\x0a")],
    ids=["esc", "c1", "bidi", "newline"],
)
def test_render_text_escapes_control_characters(path: str, char: str, escaped: str) -> None:
    payload = f"before{char}FORGED"
    out = cli_content.render_text(_INJECTION_PATHS[path](payload), "en")
    assert payload not in out
    assert f"before{escaped}FORGED" in out


@pytest.mark.parametrize("lang", ["en", "it"])
def test_incomplete_ok_run_says_it_was_not_fully_evaluated(lang: str) -> None:
    note = t("cli.content.complete.note", lang)
    assert note in cli_content.render_text(_built(status="ok", complete=False), lang)
    assert note not in cli_content.render_text(_built(status="ok", complete=True), lang)


# --- exit codes ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("update", "code"),
    [
        ({"status": "error"}, 2),
        ({"status": "error", "complete": True}, 2),
        ({"status": "warn", "complete": True}, 1),
        ({"status": "fail", "complete": True}, 1),
        ({"status": "ok", "complete": False}, 1),
        ({"status": "info", "complete": False}, 1),
        ({"status": "not_evaluated", "complete": True}, 1),
        ({"status": "ok", "complete": True}, 0),
        ({"status": "info", "complete": True}, 0),
    ],
)
def test_exit_code_table(world: World, update: dict[str, Any], code: int) -> None:
    base = _service(world, world.a, "owner", ContentInput(text="hello"))
    assert cli_content.exit_code(base.model_copy(update=update)) == code


# --- input errors (after the permission check, same outcomes as the API) -----------------------


@pytest.mark.parametrize("source", ["file", "stdin"])
def test_eml_stays_bytes(
    world: World, spy: list[ContentInput], tmp_path: Path, source: str
) -> None:
    if source == "file":
        r = _run(world, "analyst", "--eml", _file(tmp_path, EML_8BIT, "8bit.eml"), "--json")
    else:
        r = _run(world, "analyst", "--eml", "-", "--json", input=EML_8BIT)
    assert r.exit_code in (0, 1), r.output
    assert spy[0].eml == EML_8BIT
    assert (
        r.stdout
        == _service(world, world.a, "analyst", ContentInput(eml=EML_8BIT)).model_dump_json() + "\n"
    )


def _cases(tmp_path: Path) -> list[tuple[list[str], str]]:
    d = tmp_path / "adir"
    d.mkdir()
    return [
        (["--text", str(tmp_path / "missing")], cli_content.CANNOT_READ_KEY),
        (["--html", str(d)], cli_content.CANNOT_READ_KEY),
        (["--text", _file(tmp_path, b"\xff\xfe\x80 binary", "bin")], cli_content.CANNOT_READ_KEY),
        (["--text", _file(tmp_path, b"abc\x00def", "nul")], cli_content.NUL_KEY),
        (["--eml", _file(tmp_path, b"From: a\x00b\r\n\r\nx", "nul.eml")], cli_content.NUL_KEY),
        (["--text", _file(tmp_path, b"x" * (MAX_RAW_BYTES + 1), "big")], cli_content.TOO_LARGE_KEY),
        (
            ["--text", _file(tmp_path, b"x" * MAX_RAW_BYTES, "big2"), "--subject", "s"],
            cli_content.TOO_LARGE_KEY,
        ),
        (
            [
                "--html",
                _file(tmp_path, b"x" * (MAX_RAW_BYTES // 2 + 1), "half1"),
                "--text",
                _file(tmp_path, b"x" * (MAX_RAW_BYTES // 2 + 1), "half2"),
            ],
            cli_content.TOO_LARGE_KEY,
        ),
        (["--text", _file(tmp_path, "hello"), "--lang", "!!"], cli_content.LANGUAGE_KEY),
        (["--text", _file(tmp_path, "hello"), "--lang", "x" * 40], cli_content.LANGUAGE_KEY),
        (["--text", _file(tmp_path, "hello"), "--lang", "en_US"], cli_content.LANGUAGE_KEY),
        (["--text", _file(tmp_path, b"", "empty")], cli_content.EMPTY_KEY),
        (["--eml", _file(tmp_path, b"", "empty.eml")], cli_content.EMPTY_KEY),
        (["--subject", "only a subject"], cli_content.EMPTY_KEY),
        ([], cli_content.EMPTY_KEY),
    ]


def test_input_errors(world: World, spy: list[ContentInput], tmp_path: Path) -> None:
    for args, key in _cases(tmp_path):
        r = _run(world, "analyst", *args)
        assert r.exit_code == 2, (args, r.output)
        assert r.stderr.strip() == t(key), args
        assert r.stdout == ""
    assert spy == []


def test_oversized_stdin_is_too_large(world: World, spy: list[ContentInput]) -> None:
    r = _run(world, "analyst", "--text", "-", input=b"y" * (MAX_RAW_BYTES + 1))
    assert r.exit_code == 2
    assert r.stderr.strip() == t(cli_content.TOO_LARGE_KEY)
    assert spy == []


@pytest.mark.parametrize("stdin", [None, io.StringIO("no buffer")], ids=["closed", "no_buffer"])
def test_unusable_stdin_cannot_be_read(
    world: World,
    spy: list[ContentInput],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stdin: Any,
) -> None:
    # CliRunner always installs its own stdin, so the command is called directly.
    monkeypatch.setattr(sys, "stdin", stdin)
    with pytest.raises(typer.Exit) as exc:
        cli_content.content_command(world.a, world.users["analyst"], text="-")
    assert exc.value.exit_code == 2
    assert capsys.readouterr().err.strip() == t(cli_content.CANNOT_READ_KEY)
    assert spy == []


def test_stdin_read_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    class Endless:
        def __init__(self) -> None:
            self.read_bytes = 0

        def read(self, n: int) -> bytes:
            self.read_bytes += n
            return b"x" * n

    stream = Endless()
    with pytest.raises(cli_content.InputRejected):
        cli_content.read_bounded(stream, MAX_RAW_BYTES)  # type: ignore[arg-type]
    assert stream.read_bytes == MAX_RAW_BYTES + 1


def test_language_is_lowercased_like_the_api(
    world: World, spy: list[ContentInput], tmp_path: Path
) -> None:
    r = _run(world, "analyst", "--text", _file(tmp_path, "hello"), "--lang", "PT-BR")
    assert r.exit_code in (0, 1), r.output
    assert spy[0].language_hint == "pt-br"


# --- usage --------------------------------------------------------------------------------------


def test_usage_errors(world: World, spy: list[ContentInput], tmp_path: Path) -> None:
    ok = _file(tmp_path, "hello")
    r = _run(world, "analyst", "--text", ok, "--output-lang", "xx")
    assert r.exit_code == 64
    r = _run(world, "analyst", "--text", "-", "--html", "-", input=b"x")
    assert r.exit_code == 64
    assert r.stderr.strip() == t(cli_content.STDIN_ONCE_KEY)
    r = runner.invoke(app, ["content", "--tenant-id", "x", "--user-id", "1", "--text", ok])
    assert r.exit_code == 64
    r = runner.invoke(app, ["content", "--text", ok])  # ids are required
    assert r.exit_code == 64
    assert spy == []


def test_settings_are_not_needed_for_help() -> None:
    r = runner.invoke(app, ["content", "--help"])
    assert r.exit_code == 0
    assert "--tenant-id" in r.stdout and "--eml" in r.stdout
