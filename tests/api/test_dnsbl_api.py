# ruff: noqa: F811
"""M7-05: the `dnsbl` check on the check endpoints: roles, tenancy, IP targets, enablement.

Reuses the world and fake DNS backend of tests/api/test_checks_api.py. Lists are invented
(tests/checks/fixtures/dnsbl_test_lists.yaml); no network.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from app.api.v1.dns_tools import dns_backend
from app.checks.dnsbl import DnsblCheck
from app.checks.dnsbl_schema import read_dnsbl_lists
from app.checks.registry import CheckRegistry, load_builtin_checks
from app.core.i18n import t
from app.services import checks as checks_service
from tests.api.test_checks_api import (  # noqa: F401 - fixtures
    FREE,
    _strict_mode,
    dpath,
    set_toggles,
    world,
)
from tests.api.test_domains import World, call
from tests.support.dns_backend import fake_backend
from tests.support.dns_zones import FakeServerSet

FIXTURE = Path(__file__).parent.parent / "checks" / "fixtures" / "dnsbl_test_lists.yaml"
LISTS = {x.id: x for x in read_dnsbl_lists(FIXTURE, date(2026, 11, 13))}
ZONES: dict[str, list[dict[str, Any]]] = {
    "default": [
        {
            "name": "assigned.example.dbl.example.net",
            "type": "A",
            "ttl": 60,
            "rdata": ["127.0.1.2"],
        },
        {"name": "8.8.8.8.bl.example.com", "type": "A", "ttl": 60, "rdata": ["127.0.0.2"]},
        {"name": "9.9.9.9.bl.example.com", "type": "A", "state": "servfail", "rcode": 2},
    ]
}
DNSBL_DOMAIN_EXPECTED = {"anon": 401, "owner": 200, "admin": 200, "analyst": 200, "viewer": 200}
FREE_EXPECTED = {"anon": 401, "owner": 200, "admin": 200, "analyst": 200, "viewer": 403}


@pytest.fixture
def servers(world: World, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeServerSet]:  # noqa: F811
    """Enabled test lists in the default registry and a backend that serves their zones."""
    base = load_builtin_checks()
    reg = CheckRegistry()
    for check_id in base.all_ids():
        reg.register(
            DnsblCheck((LISTS["ip-both"], LISTS["dom"]))
            if check_id == "dnsbl"
            else base.get(check_id)
        )
    monkeypatch.setattr(checks_service, "_default_registry", reg)
    backend, servers = fake_backend(ZONES)
    world.client.app.dependency_overrides[dns_backend] = lambda: backend  # type: ignore[attr-defined]
    yield servers


def _queries(servers: FakeServerSet) -> list[str]:
    return [q.name for q in servers.resolver("default").questions]


# --- domain routes: same permissions as every check (check.run) ---------------------------------


@pytest.mark.parametrize("tail", ["/dnsbl", "/all", ""])
@pytest.mark.parametrize("who", list(DNSBL_DOMAIN_EXPECTED))
def test_domain_roles_on_assigned_domain(
    world: World,  # noqa: F811
    servers: FakeServerSet,
    who: str,
    tail: str,
) -> None:
    body = {"ids": ["dnsbl"]} if tail == "" else None
    r = call(world, who, "POST", dpath(world, "assigned", tail), json=body)
    assert r.status_code == DNSBL_DOMAIN_EXPECTED[who], r.text[:200]
    if who == "anon":
        assert r.json() == {"detail": t("auth.required", "en")}


@pytest.mark.parametrize(
    ("who", "status"), [("owner", 200), ("admin", 200), ("analyst", 200), ("viewer", 404)]
)
def test_unassigned_domain(world: World, servers: FakeServerSet, who: str, status: int) -> None:  # noqa: F811
    r = call(world, who, "POST", dpath(world, "unassigned", "/dnsbl"))
    assert r.status_code == status
    if status == 404:
        assert r.json() == {"detail": t("api.error.not_found", "en")}
        assert _queries(servers) == []  # nothing was looked up for an invisible domain


def test_foreign_tenant_domain_is_404_and_not_queried(world: World, servers: FakeServerSet) -> None:  # noqa: F811
    r = call(world, "analyst", "POST", dpath(world, "other", "/dnsbl"))
    assert r.status_code == 404
    assert _queries(servers) == []


def test_check_run_toggle_false_denies(world: World, servers: FakeServerSet) -> None:  # noqa: F811
    set_toggles(world, "analyst", {"check.run": False})
    r = call(world, "analyst", "POST", dpath(world, "assigned", "/dnsbl"))
    assert r.status_code == 403
    assert _queries(servers) == []


def test_domain_result_listed(world: World, servers: FakeServerSet) -> None:  # noqa: F811
    r = call(world, "viewer", "POST", dpath(world, "assigned", "/dnsbl"))
    body = r.json()
    assert body["check_id"] == "dnsbl"
    assert body["status"] == "warn"
    assert [f["code"] for f in body["findings"]] == ["DNSBL_LISTED"]
    assert body["findings"][0]["remediation_key"] == "finding.DNSBL_LISTED.remediation"
    assert _queries(servers) == ["assigned.example.dbl.example.net"]  # domain lists only


def test_domain_route_rejects_ip_lists_in_ids_body_unaffected(
    world: World, servers: FakeServerSet
) -> None:  # noqa: F811
    """The domain routes never take a name from the client, so IP lists are never queried."""
    r = call(world, "owner", "POST", dpath(world, "assigned", ""), json={"ids": ["dnsbl", "spf"]})
    assert r.status_code == 200
    assert not any(q.endswith(".bl.example.com") for q in _queries(servers))


# --- free route ---------------------------------------------------------------------------------


@pytest.mark.parametrize("who", list(FREE_EXPECTED))
def test_free_roles_for_an_ip(world: World, servers: FakeServerSet, who: str) -> None:  # noqa: F811
    r = call(world, who, "POST", FREE, json={"name": "8.8.8.8", "ids": ["dnsbl"]})
    assert r.status_code == FREE_EXPECTED[who], r.text[:200]
    if who == "viewer":
        assert r.json() == {"detail": t("api.error.forbidden", "en")}
        assert _queries(servers) == []


def test_free_foreign_active_tenant_is_404(world: World, servers: FakeServerSet) -> None:  # noqa: F811
    r = call(world, "analyst", "POST", FREE, json={"name": "8.8.8.8", "ids": ["dnsbl"]}, tenant="b")
    assert r.status_code == 404


def test_free_dns_tools_toggle_false_denies(world: World, servers: FakeServerSet) -> None:  # noqa: F811
    set_toggles(world, "analyst", {"dns.tools": False})
    r = call(world, "analyst", "POST", FREE, json={"name": "8.8.8.8", "ids": ["dnsbl"]})
    assert r.status_code == 403


def test_free_ip_listed(world: World, servers: FakeServerSet) -> None:  # noqa: F811
    r = call(world, "analyst", "POST", FREE, json={"name": "8.8.8.8", "ids": ["dnsbl"]})
    (body,) = r.json()
    assert body["target"] == "8.8.8.8"
    assert [f["code"] for f in body["findings"]] == ["DNSBL_LISTED"]
    assert _queries(servers) == ["8.8.8.8.bl.example.com"]  # domain list is not applicable


def test_free_ip_list_error_is_error_status(world: World, servers: FakeServerSet) -> None:  # noqa: F811
    r = call(world, "analyst", "POST", FREE, json={"name": "9.9.9.9", "ids": ["dnsbl"]})
    (body,) = r.json()
    assert body["status"] == "error"
    assert [f["code"] for f in body["findings"]] == ["DNSBL_LIST_ERROR"]


@pytest.mark.parametrize("name", ["10.0.0.1", "127.0.0.1", "192.168.0.1", "169.254.169.254", "::1"])
def test_free_non_public_ip_is_never_queried(
    world: World, servers: FakeServerSet, name: str
) -> None:  # noqa: F811
    r = call(world, "analyst", "POST", FREE, json={"name": name, "ids": ["dnsbl"]})
    assert r.status_code == 200
    assert _queries(servers) == []


@pytest.mark.parametrize(
    "body",
    [
        {"name": "8.8.8.8", "ids": ["spf"]},
        {"name": "8.8.8.8", "ids": ["dnsbl", "spf"]},
        {"name": "1.2.3", "ids": ["dnsbl"]},
        {"name": "8.8.8.8%eth0", "ids": ["dnsbl"]},
        {"name": "999.1.1.1", "ids": ["dnsbl"]},
        {"name": "8.8.8.8", "ids": ["dnsbl", "dnsbl"]},
    ],
)
def test_free_invalid_ip_requests_are_422(world: World, servers: FakeServerSet, body: Any) -> None:  # noqa: F811
    assert call(world, "analyst", "POST", FREE, json=body).status_code == 422
    assert _queries(servers) == []


def test_free_domain_name_runs_domain_lists(world: World, servers: FakeServerSet) -> None:  # noqa: F811
    r = call(world, "analyst", "POST", FREE, json={"name": "Assigned.Example.", "ids": ["dnsbl"]})
    (body,) = r.json()
    assert [f["code"] for f in body["findings"]] == ["DNSBL_LISTED"]


# --- default state: shipped lists are disabled, nothing is queried ------------------------------


def test_default_registry_sends_no_query(world: World) -> None:  # noqa: F811
    backend, servers = fake_backend(ZONES)
    world.client.app.dependency_overrides[dns_backend] = lambda: backend  # type: ignore[attr-defined]
    r = call(world, "analyst", "POST", FREE, json={"name": "8.8.8.8", "ids": ["dnsbl"]})
    (body,) = r.json()
    assert [f["code"] for f in body["findings"]] == ["DNSBL_NO_LISTS_APPLICABLE"]
    assert _queries(servers) == []
