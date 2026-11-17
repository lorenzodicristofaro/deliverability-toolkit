"""M7-21a domain verification on the domain page: badge, buttons, start page, verify now.

Through the real app and middleware (sessions, CSRF, i18n en + it). The resolver is a scripted
fake (`dns_backend` override) and the clock is fixed: no network.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.v1.dns_tools import dns_backend
from app.api.v1.domain_verification import verification_clock
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.main import create_app
from app.models import Domain, Membership
from tests.web.test_domains_ui import B_SECRET_NAME, KEY, World, _seed, domain_path, get, post

NOW = datetime(2026, 11, 17, 9, 30, tzinfo=UTC)
RECORD = "_dt-verify.assigned.example"
VALUE = re.compile(r'data-testid="verify-record-value">(dt-verify=[A-Za-z0-9_-]+)<')


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


def tokens(w: World) -> list[Any]:
    w.db.expire_all()
    w.db.rollback()
    rows = w.db.execute(
        select(Domain.id, Domain.verification_status, Domain.verification_token_hash).order_by(
            Domain.id
        )
    ).all()
    w.db.rollback()
    return [tuple(r) for r in rows]


def start(w: World, who: str = "owner") -> Any:
    return post(w, who, domain_path(w, "assigned", "/verification"))


def check(w: World, who: str = "owner") -> Any:
    return post(w, who, domain_path(w, "assigned", "/verification/check"))


# --- page per role -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "buttons"), [("owner", True), ("admin", True), ("analyst", False), ("viewer", False)]
)
def test_detail_page_badge_and_buttons(world: World, who: str, buttons: bool) -> None:
    page = get(world, who, domain_path(world, "assigned"))
    assert page.status_code == 200
    assert 'data-testid="badge-unverified"' in page.text
    assert 'data-testid="verify-note"' in page.text
    assert ('data-testid="verify-start"' in page.text) is buttons
    assert 'data-testid="verify-now"' not in page.text  # nothing pending yet


@pytest.mark.parametrize("lang", ["en", "it"])
def test_detail_page_in_both_languages(world: World, lang: str) -> None:
    page = get(world, "owner", domain_path(world, "assigned"), **{"Accept-Language": lang})
    assert t("domain.verify.title", lang) in page.text
    assert t("domain.verify.status.unverified", lang) in page.text
    assert t("domain.verify.start", lang) in page.text


# --- start --------------------------------------------------------------------------------------


def test_start_shows_the_record_once(world: World, resolver: Scripted) -> None:
    response = start(world)
    assert response.status_code == 200
    match = VALUE.search(response.text)
    assert match is not None
    value = match.group(1)
    token = value.removeprefix("dt-verify=")
    assert RECORD in response.text and "TXT" in response.text
    assert t("domain.verify.token_shown_once", "en") in response.text
    assert "location" not in {k.lower() for k in response.headers}
    assert "no-store" in response.headers["cache-control"]
    # The domain page afterwards: pending, verify button, never the token.
    page = get(world, "owner", domain_path(world, "assigned"))
    assert 'data-testid="verify-pending"' in page.text and 'data-testid="verify-now"' in page.text
    assert token not in page.text
    assert all(token not in str(row) for row in tokens(world))
    # Verify now with the record published.
    resolver.answers[RECORD] = [value]
    result = check(world)
    assert result.status_code == 200 and token not in result.text
    assert 'data-testid="badge-verified"' in result.text
    assert t("domain.verify.outcome.verified", "en") in result.text
    page = get(world, "viewer", domain_path(world, "assigned"))
    assert 'data-testid="badge-verified"' in page.text


@pytest.mark.parametrize(
    ("answer", "key", "badge"),
    [
        (ResultState.servfail, "domain.verify.outcome.error", "badge-verify-error"),
        (ResultState.timeout, "domain.verify.outcome.error", "badge-verify-error"),
        (ResultState.nxdomain, "domain.verify.outcome.not_found", "badge-unverified"),
        (["dt-verify=wrong"], "domain.verify.outcome.not_found", "badge-unverified"),
    ],
)
def test_verify_now_outcomes(
    world: World, resolver: Scripted, answer: Any, key: str, badge: str
) -> None:
    start(world)
    resolver.answers[RECORD] = answer
    response = check(world)
    assert response.status_code == 200
    state = str(answer) if isinstance(answer, ResultState) else ""
    assert t(key, "en", state=state) in response.text
    assert f'data-testid="{badge}"' in response.text
    assert tokens(world)[0][1] == "unverified"


def test_verify_now_without_start(world: World, resolver: Scripted) -> None:
    response = check(world)
    assert t("domain.verify.outcome.not_started", "en") in response.text
    assert resolver.asked == []


# --- permissions, tenancy, CSRF ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "target", "status"),
    [
        ("analyst", "assigned", 403),
        ("viewer", "assigned", 403),
        ("viewer", "unassigned", 404),
        ("owner", "other", 404),
        ("admin", "other", 404),
        ("analyst", "other", 404),
        ("anon", "assigned", 401),
    ],
)
@pytest.mark.parametrize("suffix", ["/verification", "/verification/check"])
def test_denied(
    world: World, resolver: Scripted, who: str, target: str, status: int, suffix: str
) -> None:
    before = tokens(world)
    response = post(world, who, domain_path(world, target, suffix))
    assert response.status_code == status
    assert B_SECRET_NAME not in response.text
    assert tokens(world) == before and resolver.asked == []


@pytest.mark.parametrize("suffix", ["/verification", "/verification/check"])
def test_per_user_toggle_denies(world: World, resolver: Scripted, suffix: str) -> None:
    membership = world.db.scalars(
        select(Membership).where(Membership.user_id == world.users["owner"])
    ).one()
    membership.feature_toggles = {"domain.verify": False}
    world.db.commit()
    before = tokens(world)
    assert post(world, "owner", domain_path(world, "assigned", suffix)).status_code == 403
    page = get(world, "owner", domain_path(world, "assigned"))
    assert 'data-testid="verify-start"' not in page.text
    assert tokens(world) == before and resolver.asked == []


@pytest.mark.parametrize("suffix", ["/verification", "/verification/check"])
def test_forms_need_csrf(world: World, resolver: Scripted, suffix: str) -> None:
    before = tokens(world)
    response = post(world, "owner", domain_path(world, "assigned", suffix), csrf=False)
    assert response.status_code == 403
    assert tokens(world) == before and resolver.asked == []


def test_forms_carry_the_csrf_token(world: World) -> None:
    start(world)
    page = get(world, "owner", domain_path(world, "assigned"))
    forms = re.findall(r'<form method="post" action="[^"]*verification[^"]*">\s*<input', page.text)
    assert len(forms) == 2
    assert page.text.count('name="csrf_token"') >= 2
