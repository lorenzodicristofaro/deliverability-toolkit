"""M7-05 `dnsbl` check: status mapping, finding codes, enablement, privacy of query names.

Invented lists (tests/checks/fixtures/dnsbl_test_lists.yaml) and the in-memory fake resolver:
no network.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from app.checks import dnsbl, dnsbl_engine
from app.checks.dnsbl import CODES, DnsblCheck, listed_severity
from app.checks.dnsbl_schema import DnsblList, load_dnsbl_lists, read_dnsbl_lists
from app.checks.models import CheckContext, CheckResult, Target
from app.checks.registry import load_builtin_checks
from app.core import i18n
from app.core.i18n import t
from tests.support.dns_zones import FakeResolver, parse_zones

FIXTURE = Path(__file__).parent / "fixtures" / "dnsbl_test_lists.yaml"
LISTS = {x.id: x for x in read_dnsbl_lists(FIXTURE, date(2026, 11, 13))}
BOTH, DOM, UNVERIFIED = LISTS["ip-both"], LISTS["dom"], LISTS["ip-unverified"]
IP = "8.8.8.8"  # a public address: reserved test ranges are never queried
IP_NAME = "8.8.8.8.bl.example.com"
DOM_NAME = "bad.example.com.dbl.example.net"


def _resolver(*entries: dict[str, Any]) -> FakeResolver:
    return parse_zones({"zones": {"default": list(entries)}}).resolver()


def _a(name: str, *rdata: str) -> dict[str, Any]:
    return {"name": name, "type": "A", "ttl": 60, "rdata": list(rdata)}


def _state(name: str, state: str, rcode: int | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"name": name, "type": "A", "state": state}
    if rcode is not None:
        entry["rcode"] = rcode
    return entry


async def _run(
    resolver: FakeResolver,
    target: str,
    lists: tuple[DnsblList, ...],
    enabled: tuple[str, ...] = (),
) -> CheckResult:
    ctx = CheckContext(resolver=resolver)
    return await DnsblCheck(lists, enabled).run(ctx, Target(domain=target))


def _codes(r: CheckResult) -> list[str]:
    return [f.code for f in r.findings]


# --- status mapping ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entries", "target", "lists", "status", "codes"),
    [
        ([], IP, (BOTH,), "ok", []),  # clean NXDOMAIN
        ([_a(IP_NAME, "127.0.0.2")], IP, (BOTH,), "warn", ["DNSBL_LISTED"]),
        ([_a(DOM_NAME, "127.0.1.2")], "bad.example.com", (DOM,), "warn", ["DNSBL_LISTED"]),
        ([_a(IP_NAME, "127.0.0.10")], IP, (BOTH,), "ok", []),  # info code: recorded in data only
        ([_a(IP_NAME, "127.0.0.254")], IP, (BOTH,), "error", ["DNSBL_LIST_REFUSED"]),
        ([_a(IP_NAME, "127.255.255.254")], IP, (BOTH,), "error", ["DNSBL_LIST_REFUSED"]),
        ([_state(IP_NAME, "refused", 5)], IP, (BOTH,), "error", ["DNSBL_LIST_REFUSED"]),
        ([_state(IP_NAME, "servfail", 2)], IP, (BOTH,), "error", ["DNSBL_LIST_ERROR"]),
        ([_state(IP_NAME, "timeout")], IP, (BOTH,), "error", ["DNSBL_LIST_ERROR"]),
        ([_a(IP_NAME, "10.0.0.1")], IP, (BOTH,), "error", ["DNSBL_LIST_ERROR"]),  # out of range
        ([_a(IP_NAME, "127.0.0.99")], IP, (BOTH,), "error", ["DNSBL_LIST_ERROR"]),  # unmapped
        ([], IP, (UNVERIFIED,), "error", ["DNSBL_LIST_UNVERIFIED"]),
        # listed on one list, another could not be evaluated: error AND both findings
        (
            [_a(IP_NAME, "127.0.0.2"), _state("8.8.8.8.unverified.example.com", "servfail", 2)],
            IP,
            (
                BOTH,
                dataclasses.replace(UNVERIFIED, status="verified", unverified_fields=frozenset()),
            ),
            "error",
            ["DNSBL_LISTED", "DNSBL_LIST_ERROR"],
        ),
    ],
)
async def test_status_mapping(
    entries: list[dict[str, Any]],
    target: str,
    lists: tuple[DnsblList, ...],
    status: str,
    codes: list[str],
) -> None:
    r = await _run(_resolver(*entries), target, lists)
    assert r.status == status
    assert sorted(_codes(r)) == sorted(codes)


async def test_error_is_never_ok_and_finding_names_the_list() -> None:
    r = await _run(_resolver(_state(IP_NAME, "servfail", 2)), IP, (BOTH,))
    assert r.status == "error"
    (f,) = r.findings
    assert f.params["list"] == BOTH.name
    assert f.params["list_id"] == "ip-both"
    assert f.params["reason"] == "servfail"


async def test_listed_params_and_evidence() -> None:
    r = await _run(_resolver(_a(IP_NAME, "127.0.0.2")), IP, (BOTH,))
    (f,) = r.findings
    assert f.params["return_code"] == "127.0.0.2"
    assert f.params["category"] == "spam_source"
    assert f.params["target"] == IP
    assert f.severity == "medium"
    assert f.evidence == ("bl.example.com 127.0.0.2",)


async def test_unverified_list_is_not_queried() -> None:
    resolver = _resolver(_a("8.8.8.8.unverified.example.com", "127.0.0.2"))
    r = await _run(resolver, IP, (UNVERIFIED,))
    assert _codes(r) == ["DNSBL_LIST_UNVERIFIED"]
    assert resolver.questions == []


@pytest.mark.parametrize(
    ("categories", "severity"),
    [
        (["malware"], "high"),
        (["spam_source", "phishing"], "high"),
        (["spam_source"], "medium"),
        (["grey"], "low"),
        (["something_new"], "medium"),
        ([], "medium"),
    ],
)
def test_category_severity(categories: list[str], severity: str) -> None:
    assert listed_severity(categories) == severity


# --- enablement ----------------------------------------------------------------------------------


def _disabled(lst: DnsblList) -> DnsblList:
    return dataclasses.replace(lst, default_enabled=False)


async def test_disabled_list_is_not_applicable_and_sends_no_query() -> None:
    resolver = _resolver(_a(IP_NAME, "127.0.0.2"))
    r = await _run(resolver, IP, (_disabled(BOTH),))
    assert resolver.questions == []  # zero queries
    assert _codes(r) == ["DNSBL_NO_LISTS_APPLICABLE"]
    assert r.status == "info"  # never a clean "ok" when nothing was looked up
    assert r.data["lists"] == [
        {
            "id": "ip-both",
            "outcome": "not_applicable",
            "reason": "list_disabled",
            "codes": [],
            "unverified": False,
        }
    ]


async def test_enabling_a_disabled_list_queries_it() -> None:
    resolver = _resolver(_a(IP_NAME, "127.0.0.2"))
    r = await _run(resolver, IP, (_disabled(BOTH),), enabled=("ip-both",))
    assert _codes(r) == ["DNSBL_LISTED"]
    assert [q.name for q in resolver.questions] == [IP_NAME]


async def test_enabling_one_list_does_not_enable_another() -> None:
    other = dataclasses.replace(_disabled(BOTH), id="other", zone="other.example.com")
    resolver = _resolver()
    r = await _run(resolver, IP, (_disabled(BOTH), other), enabled=("other",))
    assert [q.name for q in resolver.questions] == ["8.8.8.8.other.example.com"]
    assert r.status == "ok"


async def test_shipped_lists_are_all_disabled_by_default_and_never_queried() -> None:
    lists = load_dnsbl_lists()
    assert lists and not any(x.default_enabled for x in lists)
    resolver = _resolver()
    for target in (IP, "bad.example.com"):
        r = await _run(resolver, target, lists)
        assert _codes(r) == ["DNSBL_NO_LISTS_APPLICABLE"]
    assert resolver.questions == []


# --- privacy: no query name for a non-public IP --------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "192.168.1.1",
        "192.0.2.1",
        "198.51.100.7",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "2001:db8::1",
        "::ffff:10.0.0.1",
    ],
)
async def test_non_public_ip_is_never_queried(ip: str) -> None:
    resolver = _resolver()
    r = await _run(resolver, ip, (BOTH,))
    assert resolver.questions == []
    assert _codes(r) == ["DNSBL_NO_LISTS_APPLICABLE"]


def test_no_public_name_builder_skips_the_address_policy() -> None:
    """`build_query_name` must not be importable as a public function, and the only caller of the
    private builder is the engine's `_one`, which applies the address policy first."""
    assert not hasattr(dnsbl_engine, "build_query_name")
    module_src = inspect.getsource(dnsbl_engine)
    assert module_src.count("_build_query_name(") == 2  # the definition and the engine's call
    src = inspect.getsource(dnsbl_engine.DnsblEngine._one)
    assert src.index("_address_policy") < src.index("_build_query_name")
    assert "_build_query_name" not in inspect.getsource(dnsbl)


# --- registration, i18n --------------------------------------------------------------------------


def test_registered_as_builtin() -> None:
    assert "dnsbl" in load_builtin_checks().all_ids()


@pytest.mark.parametrize("lang", ["en", "it"])
@pytest.mark.parametrize("code", CODES)
def test_i18n_keys_exist(code: str, lang: str) -> None:
    i18n.set_strict(True)
    try:
        for part in ("title", "detail", "remediation"):
            assert t(
                f"finding.{code}.{part}",
                lang,
                list="L",
                target="x",
                reason="r",
                return_code="c",
                category="k",
            )
        assert t("checks.dnsbl.title", lang)
    finally:
        i18n.set_strict(False)


async def test_wire_json_is_serialisable() -> None:
    r = await _run(_resolver(_a(IP_NAME, "127.0.0.2")), IP, (BOTH,))
    assert json.loads(r.model_dump_json())["check_id"] == "dnsbl"
