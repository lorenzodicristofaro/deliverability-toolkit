"""M7-21a domain verification routes through the real app and middleware:
`/api/v1/domains/{id}/verification` (GET status, POST start) and `.../verification/check`.

The routes are also in the M1-20 matrix (tests/tenancy/test_matrix.py) and the id range guard;
this file adds the per-role table, the per-user toggle, CSRF, the token exposure rules and the
flow. The resolver is a scripted fake through the `dns_backend` override: no network.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.v1.dns_tools import dns_backend
from app.api.v1.domain_verification import verification_clock
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.main import create_app
from app.models import Domain, Membership
from tests.api.test_domains import B_SECRET_NAME, KEY, World, _seed, call
from tests.support.socket_guard import db_endpoint, install

NOW = datetime(2026, 11, 17, 9, 30, tzinfo=UTC)
NOT_FOUND = {"detail": t("api.error.not_found", "en")}
FORBIDDEN = {"detail": t("api.error.forbidden", "en")}


class _Clock:
    def now(self) -> datetime:
        return NOW


class Scripted:
    identity = "scripted"

    def __init__(self) -> None:
        self.answers: dict[str, Any] = {}
        self.asked: list[str] = []

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.asked.append(question.name)
        answer = self.answers.get(question.name, ResultState.nxdomain)
        if isinstance(answer, ResultState):
            return DnsResult(question, answer)
        records = tuple(DnsRecord(question.name, "TXT", 60, v) for v in answer)
        return DnsResult(question, ResultState.ok, records)


class _Backend:
    def __init__(self, resolver: Scripted) -> None:
        self.default = resolver


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "domain verification API", db_endpoint())


@pytest.fixture
def resolver() -> Scripted:
    return Scripted()


@pytest.fixture
def world(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, resolver: Scripted
) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    application.dependency_overrides[verification_clock] = _Clock
    application.dependency_overrides[dns_backend] = lambda: _Backend(resolver)
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def url(w: World, which: str = "assigned", check: bool = False) -> str:
    return f"/api/v1/domains/{w.domains[which]}/verification" + ("/check" if check else "")


def state(w: World) -> list[tuple[Any, ...]]:
    """Ground truth: the verification columns of every domain (all tenants)."""
    w.db.expire_all()
    w.db.rollback()
    found = w.db.execute(
        select(
            Domain.id,
            Domain.verification_status,
            Domain.verification_token_hash,
            Domain.verification_token_expires_at,
        ).order_by(Domain.id)
    ).all()
    w.db.rollback()
    return [tuple(r) for r in found]


def set_toggles(w: World, who: str, toggles: dict[str, Any]) -> None:
    membership = w.db.scalars(select(Membership).where(Membership.user_id == w.users[who])).one()
    membership.feature_toggles = toggles
    w.db.commit()


# --- per role -------------------------------------------------------------------------------------

# who -> (GET status, POST start, POST check) on tenant A's assigned domain.
ROLE_TABLE = {
    "anon": (401, 401, 401),
    "owner": (200, 201, 200),
    "admin": (200, 201, 200),
    "analyst": (200, 403, 403),
    "viewer": (200, 403, 403),
}


@pytest.mark.parametrize("who", list(ROLE_TABLE))
def test_role_table(world: World, resolver: Scripted, who: str) -> None:
    get_status, start_status, check_status = ROLE_TABLE[who]
    before = state(world)
    assert call(world, who, "GET", url(world)).status_code == get_status
    response = call(world, who, "POST", url(world))
    assert response.status_code == start_status, response.text
    if start_status == 403:
        assert response.json() == FORBIDDEN
        assert state(world) == before
    response = call(world, who, "POST", url(world, check=True))
    assert response.status_code == check_status
    if check_status == 200:
        assert response.json()["outcome"] == "not_found"  # nxdomain: not published yet
        assert resolver.asked == [f"_dt-verify.{'assigned.example'}"]
    else:
        assert resolver.asked == []


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
@pytest.mark.parametrize(("method", "check"), [("GET", False), ("POST", False), ("POST", True)])
def test_foreign_and_unassigned_domains_are_404(
    world: World, resolver: Scripted, who: str, method: str, check: bool
) -> None:
    before = state(world)
    targets = ["other"] + (["unassigned"] if who == "viewer" else [])
    for which in targets:
        response = call(world, who, method, url(world, which, check))
        assert (response.status_code, response.json()) == (404, NOT_FOUND)
        assert B_SECRET_NAME not in response.text
    suffix = "/check" if check else ""
    for raw in ("0", "abc", "99999", "-1"):
        response = call(world, who, method, f"/api/v1/domains/{raw}/verification{suffix}")
        assert (response.status_code, response.json()) == (404, NOT_FOUND)
    assert state(world) == before and resolver.asked == []


def test_session_in_tenant_b_cannot_reach_tenant_a(world: World) -> None:
    response = call(world, "b_owner", "POST", url(world), tenant="b")
    assert (response.status_code, response.json()) == (404, NOT_FOUND)


@pytest.mark.parametrize("who", ["owner", "admin"])
def test_per_user_toggle_denies(world: World, resolver: Scripted, who: str) -> None:
    set_toggles(world, who, {"domain.verify": False})
    before = state(world)
    assert call(world, who, "POST", url(world)).status_code == 403
    assert call(world, who, "POST", url(world, check=True)).status_code == 403
    assert call(world, who, "GET", url(world)).status_code == 200
    assert state(world) == before and resolver.asked == []


@pytest.mark.parametrize("check", [False, True])
def test_mutations_need_csrf(world: World, resolver: Scripted, check: bool) -> None:
    before = state(world)
    response = call(world, "owner", "POST", url(world, check=check), csrf=False)
    assert response.status_code == 403
    assert state(world) == before and resolver.asked == []


# --- flow and token exposure ----------------------------------------------------------------------


def test_flow_start_publish_verify(world: World, resolver: Scripted) -> None:
    status = call(world, "owner", "GET", url(world)).json()
    assert status["status"] == "unverified" and status["pending"] is False
    assert status["record_name"] == "_dt-verify.assigned.example"

    response = call(world, "owner", "POST", url(world))
    assert response.status_code == 201
    assert "no-store" in response.headers["cache-control"]
    body = response.json()
    value = body["record_value"]
    token = value.removeprefix("dt-verify=")
    assert (body["record_type"], body["record_name"]) == ("TXT", "_dt-verify.assigned.example")
    assert len(token) >= 22 and value == f"dt-verify={token}"
    assert body["verification"]["pending"] is True
    assert body["verification"]["token_expires_at"] == "2026-11-20T09:30:00+00:00"

    # The token is nowhere else: status, check result, stored row.
    status = call(world, "owner", "GET", url(world))
    assert token not in status.text and status.json()["pending"] is True
    assert all(token not in str(row) for row in state(world))

    resolver.answers["_dt-verify.assigned.example"] = ["v=spf1 -all", value]
    response = call(world, "admin", "POST", url(world, check=True))
    assert response.status_code == 200 and token not in response.text
    result = response.json()
    assert result["outcome"] == "verified" and result["dns_state"] == "ok"
    assert result["verification"]["status"] == "verified"
    assert result["verification"]["method"] == "dns_txt"
    assert result["verification"]["verified_at"] == NOW.isoformat()
    assert result["verification"]["pending"] is False


@pytest.mark.parametrize(
    ("answer", "outcome"),
    [
        (ResultState.servfail, "error"),
        (ResultState.timeout, "error"),
        (ResultState.refused, "error"),
        (ResultState.nodata, "not_found"),
        (["dt-verify=wrong"], "not_found"),
    ],
)
def test_check_outcomes_never_verify_on_failure(
    world: World, resolver: Scripted, answer: Any, outcome: str
) -> None:
    call(world, "owner", "POST", url(world))
    resolver.answers["_dt-verify.assigned.example"] = answer
    result = call(world, "owner", "POST", url(world, check=True)).json()
    assert result["outcome"] == outcome
    assert result["verification"]["status"] == "unverified"
    if outcome == "error":
        assert result["dns_state"] == str(answer)


def test_check_without_start(world: World, resolver: Scripted) -> None:
    result = call(world, "owner", "POST", url(world, check=True)).json()
    assert result["outcome"] == "not_started" and resolver.asked == []


def test_rename_through_the_api_resets_verification(world: World, resolver: Scripted) -> None:
    value = call(world, "owner", "POST", url(world)).json()["record_value"]
    resolver.answers["_dt-verify.assigned.example"] = [value]
    call(world, "owner", "POST", url(world, check=True))
    assert call(world, "owner", "GET", url(world)).json()["status"] == "verified"
    response = call(
        world, "owner", "PATCH", f"/api/v1/domains/{world.domains['assigned']}",
        json={"name": "renamed.example"},
    )  # fmt: skip
    assert response.status_code == 200
    status = call(world, "owner", "GET", url(world)).json()
    assert (status["status"], status["pending"], status["verified_at"]) == (
        "unverified",
        False,
        None,
    )
    assert status["record_name"] == "_dt-verify.renamed.example"


def test_status_body_shape(world: World) -> None:
    assert set(call(world, "viewer", "GET", url(world)).json()) == {
        "domain_id",
        "status",
        "method",
        "verified_at",
        "pending",
        "token_expires_at",
        "record_name",
    }


def test_client_has_no_cookie_leak(world: World) -> None:
    """A start response sets no cookie and no Location (the token stays in the body only)."""
    response = call(world, "owner", "POST", url(world))
    assert "set-cookie" not in {k.lower() for k in response.headers}
    assert "location" not in {k.lower() for k in response.headers}
