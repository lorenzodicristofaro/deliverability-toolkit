"""M3-18: CLI `check` command. Fake resolver injected through the factory seam; no network."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import TypeAdapter
from typer.testing import CliRunner

from app.checks.models import CheckContext, CheckResult
from app.cli import check as cli_check
from app.cli.main import app
from app.core import i18n
from app.core.config import ConfigError
from app.dns.types import Resolver
from app.services.checks import run_checks
from tests.support.dns_zones import load_zones

ZONES = Path(__file__).parent.parent / "fixtures" / "zones"
_NOW = datetime(2026, 1, 1, tzinfo=UTC)
runner = CliRunner()


def _use(monkeypatch: pytest.MonkeyPatch, fixture: str) -> Callable[[], Resolver]:
    def factory() -> Resolver:
        return load_zones(ZONES / fixture).resolver()

    monkeypatch.setattr(cli_check, "resolver_factory", factory)
    return factory


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def boom() -> Resolver:
        raise AssertionError("real resolver requested in a unit test")

    monkeypatch.setattr(cli_check, "resolver_factory", boom)
    yield


EXIT_CASES = [
    ("dmarc_cases.yaml", "healthy.example.com", 0),
    ("dmarc_cases.yaml", "nodmarc.example.com", 1),
    ("dmarc_failures.yaml", "servfail.example.com", 2),
    ("dmarc_failures.yaml", "timeout.example.com", 2),
]


@pytest.mark.parametrize(("fixture", "domain", "code"), EXIT_CASES)
@pytest.mark.parametrize("fmt", ["text", "json"])
def test_exit_codes(
    monkeypatch: pytest.MonkeyPatch, fixture: str, domain: str, code: int, fmt: str
) -> None:
    _use(monkeypatch, fixture)
    r = runner.invoke(app, ["check", domain, "--only", "dmarc", "--format", fmt])
    assert r.exit_code == code, r.output


def test_json_single_is_object_byte_equal_to_service(monkeypatch: pytest.MonkeyPatch) -> None:
    factory = _use(monkeypatch, "dmarc_cases.yaml")
    r = runner.invoke(app, ["check", "nodmarc.example.com", "--only", "dmarc", "--format", "json"])
    out = r.stdout.rstrip("\n")
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    assert parsed["check_id"] == "dmarc"
    # The same runner with the same recorded zone: identical bytes once the timing fields
    # (wall clock) are normalised on both sides.
    res = CheckResult.model_validate_json(out)
    again = _run_service(factory(), ["dmarc"], "nodmarc.example.com")[0]
    norm = again.model_copy(update={"started_at": res.started_at, "duration_ms": res.duration_ms})
    assert out == norm.model_dump_json()


def _run_service(resolver: Resolver, ids: list[str], name: str) -> list[CheckResult]:
    import asyncio

    ctx = CheckContext(resolver=resolver, clock=lambda: _NOW)
    return asyncio.run(run_checks(ids, name, ctx))


def test_json_several_is_array_in_request_order(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, "dmarc_cases.yaml")
    r = runner.invoke(
        app, ["check", "healthy.example.com", "--only", "spf,dmarc", "--format", "json"]
    )
    arr = json.loads(r.stdout)
    assert [x["check_id"] for x in arr] == ["spf", "dmarc"]
    adapter = TypeAdapter(list[CheckResult])
    results = adapter.validate_json(r.stdout)
    assert r.stdout.rstrip("\n") == adapter.dump_json(results).decode()
    r2 = runner.invoke(
        app, ["check", "healthy.example.com", "--only", "dmarc,spf", "--format", "json"]
    )
    assert [x["check_id"] for x in json.loads(r2.stdout)] == ["dmarc", "spf"]


def test_default_runs_all_checks_as_array(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, "dmarc_cases.yaml")
    r = runner.invoke(app, ["check", "healthy.example.com", "--format", "json"])
    arr = json.loads(r.stdout)
    assert [x["check_id"] for x in arr] == ["dkim", "dmarc", "spf"]


def test_error_never_exits_zero_with_other_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, "dmarc_failures.yaml")
    r = runner.invoke(app, ["check", "servfail.example.com", "--only", "dmarc,spf"])
    assert r.exit_code == 2


@pytest.mark.parametrize(
    ("lang", "heading", "status"),
    [("en", "for nodmarc.example.com", "WARNING"), ("it", "per nodmarc.example.com", "ATTENZIONE")],
)
def test_text_is_translated(
    monkeypatch: pytest.MonkeyPatch, lang: str, heading: str, status: str
) -> None:
    _use(monkeypatch, "dmarc_cases.yaml")
    r = runner.invoke(app, ["check", "nodmarc.example.com", "--only", "dmarc", "--lang", lang])
    assert heading in r.stdout
    assert status in r.stdout
    assert i18n.t("finding.DMARC_MISSING.title", lang) in r.stdout
    assert i18n.t("cli.check.summary", lang, count=1, code=1) in r.stdout
    assert "finding.DMARC_MISSING" not in r.stdout  # no raw keys


def test_text_error_status_translated(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, "dmarc_failures.yaml")
    r = runner.invoke(app, ["check", "servfail.example.com", "--only", "dmarc", "--lang", "it"])
    assert i18n.t("cli.check.status.error", "it") in r.stdout
    assert r.exit_code == 2


USAGE_CASES = [
    ["check", "not a domain!", "--only", "dmarc"],
    ["check", "", "--only", "dmarc"],
    ["check", "bad\x00.example.com", "--only", "dmarc"],
    ["check", "127.0.0.1", "--only", "dmarc"],
    ["check", "example.com", "--only", "nope"],
    ["check", "example.com", "--only", "dmarc,nope"],
    ["check", "example.com", "--only", ""],
    ["check", "example.com", "--only", "spf,spf"],
    ["check", "example.com", "--format", "xml"],
    ["check", "example.com", "--lang", "fr"],
    ["check", "example.com", "--bogus"],
    ["check"],
    ["nosuchcommand"],
    ["check", "example.com", "--only", "spf", "--selector", "k1"],
]


@pytest.mark.parametrize("args", USAGE_CASES)
def test_usage_errors_exit_64(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    _use(monkeypatch, "dmarc_cases.yaml")
    r = runner.invoke(app, args)
    assert r.exit_code == 64, r.output
    assert r.stdout == ""  # nothing on stdout, so --format json consumers never see junk


def test_usage_error_does_not_echo_input(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, "dmarc_cases.yaml")
    r = runner.invoke(app, ["check", "secret-input!", "--only", "dmarc"])
    assert "secret-input" not in r.output


def test_adhoc_selector_probed_this_run_only(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, "dkim_cases.yaml")
    r = runner.invoke(
        app,
        [
            "check",
            "d2048.example.com",
            "--only",
            "dkim",
            "--selector",
            "zzadhoc",
            "--format",
            "json",
        ],
    )
    names = [s["selector"] for s in json.loads(r.stdout)["data"]["selectors"]]
    assert "zzadhoc" in names
    r2 = runner.invoke(app, ["check", "d2048.example.com", "--only", "dkim", "--format", "json"])
    assert "zzadhoc" not in [s["selector"] for s in json.loads(r2.stdout)["data"]["selectors"]]


def test_config_error_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def bad() -> Resolver:
        raise ConfigError("config.resolver_addrs_required", mode="custom")

    monkeypatch.setattr(cli_check, "resolver_factory", bad)
    r = runner.invoke(app, ["check", "example.com"])
    assert r.exit_code == 2
    assert "config.resolver_addrs_required" in r.stderr


def test_help_is_translated_and_exits_zero() -> None:
    r = runner.invoke(app, ["check", "--help"])
    assert r.exit_code == 0
    assert i18n.t("cli.check.help") in " ".join(r.stdout.split())


def test_catalogues_have_cli_keys_in_both_languages() -> None:
    en = i18n.load_catalogue("en")
    it = i18n.load_catalogue("it")
    cli_keys = {k for k in en if k.startswith("cli.check.")}
    assert cli_keys == {k for k in it if k.startswith("cli.check.")}
    for key in cli_keys:
        assert i18n.placeholders(en[key]) == i18n.placeholders(it[key])


# R1-20 (PARSE-04): DNS-controlled bytes must never reach the terminal raw in text output.
_FORGED_SPF = "v=spf1 include:\x1b[2J\x1b[31mFORGED.example.com bogus\x1b]0;title\x07 -all"
_FORGED_DMARC = "v=DMARC1; p=none; rua=mailto:\x1b[31mx@example.com"


def _hostile_zone(tmp_path: Path) -> Path:
    zone = {
        "zones": {
            "default": [
                {"name": "example.com", "type": "TXT", "ttl": 300, "rdata": [_FORGED_SPF]},
                {"name": "_dmarc.example.com", "type": "TXT", "ttl": 300, "rdata": [_FORGED_DMARC]},
            ]
        }
    }
    path = tmp_path / "hostile.yaml"
    path.write_text(json.dumps(zone), encoding="utf-8")
    return path


def test_text_output_has_no_raw_control_characters_from_dns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    zone = _hostile_zone(tmp_path)
    monkeypatch.setattr(cli_check, "resolver_factory", lambda: load_zones(zone).resolver())
    r = runner.invoke(app, ["check", "example.com", "--only", "spf,dmarc", "--format", "text"])
    assert r.exit_code in (0, 1, 2), r.output
    for bad in ("\x1b", "\x07", "\x9b", "‮"):
        assert bad not in r.output
    assert "\\x1b[2J" in r.output


def test_json_output_still_json_escapes_controls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    zone = _hostile_zone(tmp_path)
    monkeypatch.setattr(cli_check, "resolver_factory", lambda: load_zones(zone).resolver())
    r = runner.invoke(app, ["check", "example.com", "--only", "spf,dmarc", "--format", "json"])
    assert "\x1b" not in r.output and "\x07" not in r.output
    assert "\\u001b" in r.output
    json.loads(r.output)


def _result(*, params: dict[str, object], evidence: tuple[str, ...]) -> CheckResult:
    from app.checks.models import Finding

    key = "cli.check.evidence"  # any key whose template shows the `text` parameter
    f = Finding(
        code="TEST",
        severity="low",
        title_key=key,
        detail_key=key,
        remediation_key=key,
        params=params,
        evidence=evidence,
    )
    return CheckResult(
        check_id="spf",
        target="example.com",
        status="warn",
        findings=(f,),
        started_at=_NOW,
        duration_ms=0,
    )


@pytest.mark.parametrize("where", ["param", "evidence"])
@pytest.mark.parametrize(
    ("char", "escaped"),
    [
        ("\x1b", "\\x1b"),
        ("\x07", "\\x07"),
        ("\r", "\\x0d"),
        ("\x9b", "\\x9b"),
        ("‮", "\\u202e"),
        ("\n", "\\x0a"),
    ],
    ids=["esc", "bel", "cr", "c1", "bidi", "newline"],
)
def test_render_text_escapes_control_characters(where: str, char: str, escaped: str) -> None:
    payload = f"before{char}FORGED"
    res = (
        _result(params={"text": payload}, evidence=())
        if where == "param"
        else _result(params={"text": "ok"}, evidence=(payload,))
    )
    out = cli_check.render_text([res], "en")
    assert payload not in out
    assert f"before{escaped}FORGED" in out
