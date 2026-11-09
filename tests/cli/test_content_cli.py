"""M5-17: CLI `content` command. Offline apart from the test database (socket guard).

Runs on SQLite and, with TEST_DATABASE_URL, on PostgreSQL (`migrated_db_url`).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from app.cli import content as cli_content
from app.cli.main import app
from app.cli.tenant_scope import EXIT_DENIED
from app.core import i18n
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.tenancy import TenantContext
from app.parsers.message import MAX_RAW_BYTES
from app.repositories import repo_for
from app.services.content_analysis import ContentAnalysis, ContentInput, analyze_content
from tests.api.test_domains import KEY, _seed
from tests.support.socket_guard import db_endpoint, install

runner = CliRunner()
EML = (
    b"From: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: hello\r\n"
    b"Message-ID: <m1@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n"
    b"zebraword here\r\n"
)
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


def _add_rules(w: World, tenant: int, name: str, pattern: str) -> None:
    engine = create_db_engine(w.url)
    db = create_session_factory(engine)()
    try:
        repo_for(TenantContext(tenant, None), db).content_rules.create(
            {**RULE, "name": name, "pattern": pattern, "title": f"TITLE-{name}"}
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
    assert '"name":"ra"' in r.stdout
    assert "rb" not in r.stdout.replace("TITLE", "")  # tenant B's rule name never appears


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


def test_unreadable_stdin_budget_is_shared(world: World, spy: list[ContentInput]) -> None:
    r = _run(world, "analyst", "--text", "-", input=b"y" * (MAX_RAW_BYTES + 1))
    assert r.exit_code == 2
    assert r.stderr.strip() == t(cli_content.TOO_LARGE_KEY)
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
