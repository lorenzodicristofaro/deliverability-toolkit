"""M7-05: the `dnsbl` check through the `check` CLI. Fake resolver, no network."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from app.checks.dnsbl import DnsblCheck
from app.checks.dnsbl_schema import read_dnsbl_lists
from app.checks.registry import CheckRegistry, load_builtin_checks
from app.cli import check as cli_check
from app.cli.main import app
from app.dns.types import Resolver
from app.services import checks as checks_service
from tests.support.dns_zones import FakeResolver, parse_zones

FIXTURE = Path(__file__).parent.parent / "checks" / "fixtures" / "dnsbl_test_lists.yaml"
LISTS = {x.id: x for x in read_dnsbl_lists(FIXTURE, date(2026, 11, 13))}
runner = CliRunner()


def _resolver(*entries: dict[str, Any]) -> FakeResolver:
    return parse_zones({"zones": {"default": list(entries)}}).resolver()


def _a(name: str, *rdata: str) -> dict[str, Any]:
    return {"name": name, "type": "A", "ttl": 60, "rdata": list(rdata)}


def _install(
    monkeypatch: pytest.MonkeyPatch, resolver: FakeResolver, check: DnsblCheck | None = None
) -> None:
    monkeypatch.setattr(cli_check, "resolver_factory", lambda: resolver)
    if check is not None:
        reg = CheckRegistry()
        base = load_builtin_checks()
        for check_id in base.all_ids():
            reg.register(check if check_id == "dnsbl" else base.get(check_id))
        monkeypatch.setattr(checks_service, "_default_registry", reg)


@pytest.fixture(autouse=True)
def _reset_registry(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def boom() -> Resolver:
        raise AssertionError("real resolver requested in a unit test")

    monkeypatch.setattr(cli_check, "resolver_factory", boom)
    monkeypatch.setattr(checks_service, "_default_registry", None)
    # No database here: an instance with nothing enabled (M7-05c; an unreadable enablement is an
    # error, covered in tests/api/test_dnsbl_enablement.py).
    monkeypatch.setattr(cli_check, "dnsbl_enablement_loader", lambda: frozenset())
    yield


def test_ip_listed_exit_code_and_text(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(
        monkeypatch,
        _resolver(_a("8.8.8.8.bl.example.com", "127.0.0.2")),
        DnsblCheck((LISTS["ip-both"],)),
    )
    r = runner.invoke(app, ["check", "8.8.8.8", "--only", "dnsbl"])
    assert r.exit_code == 1, r.output
    assert "Listed on Example IP list" in r.stdout


def test_ip_listed_italian(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(
        monkeypatch,
        _resolver(_a("8.8.8.8.bl.example.com", "127.0.0.2")),
        DnsblCheck((LISTS["ip-both"],)),
    )
    r = runner.invoke(app, ["check", "8.8.8.8", "--only", "dnsbl", "--lang", "it"])
    assert "Presente nella lista" in r.stdout


def test_list_error_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = _resolver(
        {"name": "8.8.8.8.bl.example.com", "type": "A", "state": "servfail", "rcode": 2}
    )
    _install(monkeypatch, resolver, DnsblCheck((LISTS["ip-both"],)))
    r = runner.invoke(app, ["check", "8.8.8.8", "--only", "dnsbl", "--format", "json"])
    assert r.exit_code == 2
    body = json.loads(r.stdout)
    assert body["status"] == "error"
    assert [f["code"] for f in body["findings"]] == ["DNSBL_LIST_ERROR"]


def test_domain_target_uses_domain_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(
        monkeypatch,
        _resolver(_a("bad.example.com.dbl.example.net", "127.0.1.2")),
        DnsblCheck((LISTS["ip-both"], LISTS["dom"])),
    )
    r = runner.invoke(app, ["check", "bad.example.com", "--only", "dnsbl", "--format", "json"])
    assert r.exit_code == 1
    assert [f["code"] for f in json.loads(r.stdout)["findings"]] == ["DNSBL_LISTED"]


def test_non_public_ip_sends_no_query(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = _resolver()
    _install(monkeypatch, resolver, DnsblCheck((LISTS["ip-both"],)))
    r = runner.invoke(app, ["check", "10.0.0.1", "--only", "dnsbl", "--format", "json"])
    assert r.exit_code == 0
    assert resolver.questions == []
    assert [f["code"] for f in json.loads(r.stdout)["findings"]] == ["DNSBL_NO_LISTS_APPLICABLE"]


def test_shipped_lists_are_disabled_so_no_query(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = _resolver()
    _install(monkeypatch, resolver)
    r = runner.invoke(app, ["check", "8.8.8.8", "--only", "dnsbl", "--format", "json"])
    assert r.exit_code == 0
    assert resolver.questions == []


@pytest.mark.parametrize("ids", ["spf", "spf,dnsbl", "dmarc"])
def test_ip_is_not_a_domain_for_other_checks(monkeypatch: pytest.MonkeyPatch, ids: str) -> None:
    _install(monkeypatch, _resolver())
    r = runner.invoke(app, ["check", "8.8.8.8", "--only", ids])
    assert r.exit_code == 64


@pytest.mark.parametrize("target", ["1.2.3", "999.1.1.1", "8.8.8.8%eth0", "8.8.8.08", "::g"])
def test_malformed_ip_is_usage_error(monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    _install(monkeypatch, _resolver(), DnsblCheck((LISTS["ip-both"],)))
    r = runner.invoke(app, ["check", target, "--only", "dnsbl"])
    assert r.exit_code == 64


def test_control_characters_in_findings_are_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    evil = dataclasses.replace(LISTS["ip-both"], name="Evil\x1b[31m\nFORGED")
    _install(
        monkeypatch,
        _resolver(_a("8.8.8.8.bl.example.com", "127.0.0.2")),
        DnsblCheck((evil,)),
    )
    r = runner.invoke(app, ["check", "8.8.8.8", "--only", "dnsbl"])
    assert "\x1b" not in r.stdout
    assert "\nFORGED" not in r.stdout
