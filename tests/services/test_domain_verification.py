"""M7-21a domain ownership verification by DNS TXT: the service, the repository writes, the rename
reset and the scheduled-run hook of the http_fetch gate.

A scripted resolver (no network) and a fixed clock. Runs on SQLite and, when TEST_DATABASE_URL is
set, on PostgreSQL (shared `migrated_db_url` fixture).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.checks import custom as custom_module
from app.checks.registry import CheckRegistry
from app.core.db import create_db_engine, create_session_factory
from app.core.permissions import MembershipGrant, Principal
from app.core.tenancy import TenantContext
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState, join_txt_strings
from app.models import Domain, MembershipRole, Tenant
from app.net import FetchLimits, FetchResult
from app.repositories import repo_for
from app.repositories.monitor_targets import DueTarget
from app.services.checks import default_registry
from app.services.custom_checks_admin import run_checks_for
from app.services.domain_verification import (
    RECORD_LABEL,
    TOKEN_BYTES,
    VALUE_PREFIX,
    DomainVerificationService,
    VerifyOutcome,
    VerifyPlan,
    hash_token,
    lookup,
    matches,
    new_token,
    record_name,
    verify,
)
from app.services.domains import DomainService, Forbidden, NotFound
from app.services.monitor_run import MonitorRunExecutor
from app.services.scheduler import ScheduledRun

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
TTL = timedelta(hours=72)
NAME = "a.example.com"
RECORD = f"{RECORD_LABEL}.{NAME}"


class Clock:
    def __init__(self) -> None:
        self.at = NOW

    def now(self) -> datetime:
        return self.at


class Scripted:
    """TXT answers by name: a list of records (each a list of character-strings) or a state."""

    identity = "scripted"

    def __init__(self) -> None:
        self.answers: dict[str, Any] = {}
        self.asked: list[str] = []

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.asked.append(question.name)
        answer = self.answers.get(question.name, ResultState.nxdomain)
        if isinstance(answer, ResultState):
            return DnsResult(question, answer)
        records = tuple(
            DnsRecord(question.name, "TXT", 300, join_txt_strings(s.encode() for s in strings))
            for strings in answer
        )
        return DnsResult(question, ResultState.ok, records)


@dataclass
class World:
    factory: sessionmaker[Session]
    db: Session
    tenants: dict[str, int]
    domains: dict[str, int]
    clock: Clock = field(default_factory=Clock)
    resolver: Scripted = field(default_factory=Scripted)

    def principal(
        self, role: str = "owner", tenant: str = "a", toggles: dict[str, Any] | None = None
    ) -> Principal:
        grant = MembershipGrant(
            self.tenants[tenant],
            MembershipRole(role),
            domain_ids=frozenset({self.domains["a"]}),
            feature_toggles=toggles or {},
        )
        return Principal(1, True, active_tenant_id=self.tenants[tenant], memberships=(grant,))

    def service(self, role: str = "owner", **kw: Any) -> DomainVerificationService:
        ctx = TenantContext(self.tenants["a"], None)
        return DomainVerificationService(self.db, ctx, self.principal(role, **kw), self.clock, TTL)

    def row(self, key: str = "a") -> Domain:
        self.db.expire_all()
        row = self.db.get(Domain, self.domains[key])
        assert row is not None
        self.db.rollback()
        return row

    def verify(self, svc: DomainVerificationService | None = None, key: str = "a") -> Any:
        return asyncio.run(verify(svc or self.service(), self.resolver, self.domains[key]))

    def publish(self, *records: Sequence[str]) -> None:
        self.resolver.answers[RECORD] = [list(r) for r in records]


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    factory = create_session_factory(engine)
    db = factory()
    ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
    db.add_all([ta, tb])
    db.flush()
    a = repo_for(TenantContext(ta.id, None), db).domains.create(NAME)
    a2 = repo_for(TenantContext(ta.id, None), db).domains.create("a2.example.com")
    b = repo_for(TenantContext(tb.id, None), db).domains.create(NAME)
    db.commit()
    w = World(factory, db, {"a": ta.id, "b": tb.id}, {"a": a.id, "a2": a2.id, "b": b.id})
    try:
        yield w
    finally:
        db.close()


def start(w: World, key: str = "a") -> str:
    """Start and return the token (the record value without its prefix)."""
    started = w.service().start(w.domains[key])
    assert started.record_value.startswith(VALUE_PREFIX)
    return started.record_value[len(VALUE_PREFIX) :]


# --- pure helpers ---------------------------------------------------------------------------------


def test_token_has_at_least_128_bits_and_is_random() -> None:
    assert TOKEN_BYTES * 8 >= 128
    tokens = {new_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(t) >= 22 and set(t) <= set(_URLSAFE) for t in tokens)


_URLSAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
TOKEN = "tok-EN_123"
HASH = hashlib.sha256(TOKEN.encode()).hexdigest()

MATCHES = [
    ("exact", [f"dt-verify={TOKEN}"], True),
    ("among others", ["v=spf1 -all", f"dt-verify={TOKEN}", "dt-verify=other"], True),
    ("wrong token", ["dt-verify=other"], False),
    ("no records", [], False),
    ("trailing space", [f"dt-verify={TOKEN} "], False),
    ("leading space", [f" dt-verify={TOKEN}"], False),
    ("prefix case", [f"DT-VERIFY={TOKEN}"], False),
    ("quoted", [f'"dt-verify={TOKEN}"'], False),
    ("bare token", [TOKEN], False),
    ("token prefix only", [f"dt-verify={TOKEN[:-1]}"], False),
    ("token plus suffix", [f"dt-verify={TOKEN}x"], False),
    ("two records concatenated", [f"dt-verify={TOKEN[:4]}", TOKEN[4:]], False),
    ("empty value", ["dt-verify="], False),
    ("non ascii", ["dt-verify=\xe9\x00\xff"], False),
]


@pytest.mark.parametrize(("records", "expected"), [pytest.param(r, e, id=c) for c, r, e in MATCHES])
def test_matches(records: list[str], expected: bool) -> None:
    assert matches(records, HASH) is expected


def test_hash_and_record_name() -> None:
    assert hash_token(TOKEN) == HASH and len(HASH) == 64
    assert record_name("example.com") == "_dt-verify.example.com"


# --- start ----------------------------------------------------------------------------------------


def test_start_stores_only_a_hash_with_expiry(world: World, caplog: Any) -> None:
    caplog.set_level(logging.DEBUG)
    started = world.service().start(world.domains["a"])
    token = started.record_value[len(VALUE_PREFIX) :]
    assert (started.record_type, started.record_name) == ("TXT", RECORD)
    row = world.row()
    assert row.verification_token_hash == hash_token(token) != token
    expires = row.verification_token_expires_at
    assert expires is not None and expires.replace(tzinfo=UTC) == NOW + TTL
    assert row.verification_status == "unverified"
    assert started.state.pending and started.state.token_expires_at == NOW + TTL
    assert token not in repr(started) and token not in caplog.text


def test_reissue_invalidates_the_old_token(world: World) -> None:
    old = start(world)
    new = start(world)
    assert old != new
    world.publish([f"dt-verify={old}"])
    assert world.verify().outcome is VerifyOutcome.not_found
    world.publish([f"dt-verify={new}"])
    assert world.verify().outcome is VerifyOutcome.verified


# --- verify ---------------------------------------------------------------------------------------

# (case, answer builder from token, outcome, dns_state)
OUTCOMES: list[tuple[str, Any, VerifyOutcome, str | None]] = [
    ("match", lambda t: [[f"dt-verify={t}"]], VerifyOutcome.verified, "ok"),
    (
        "split across strings",
        lambda t: [["dt-verify=", t[:10], t[10:]]],
        VerifyOutcome.verified,
        "ok",
    ),
    (
        "several records",
        lambda t: [["v=spf1 -all"], ["dt-verify=old"], [f"dt-verify={t}"]],
        VerifyOutcome.verified,
        "ok",
    ),
    ("wrong token", lambda t: [["dt-verify=wrong"]], VerifyOutcome.not_found, "ok"),
    (
        "split across records",
        lambda t: [[f"dt-verify={t[:10]}"], [t[10:]]],
        VerifyOutcome.not_found,
        "ok",
    ),
    ("nxdomain", lambda t: ResultState.nxdomain, VerifyOutcome.not_found, "nxdomain"),
    ("nodata", lambda t: ResultState.nodata, VerifyOutcome.not_found, "nodata"),
    ("timeout", lambda t: ResultState.timeout, VerifyOutcome.error, "timeout"),
    ("servfail", lambda t: ResultState.servfail, VerifyOutcome.error, "servfail"),
    ("refused", lambda t: ResultState.refused, VerifyOutcome.error, "refused"),
    ("network error", lambda t: ResultState.network_error, VerifyOutcome.error, "network_error"),
    ("malformed", lambda t: ResultState.malformed, VerifyOutcome.error, "malformed"),
    ("blocked", lambda t: ResultState.blocked, VerifyOutcome.error, "blocked"),
]


@pytest.mark.parametrize(
    ("answer", "outcome", "dns_state"),
    [pytest.param(a, o, d, id=c) for c, a, o, d in OUTCOMES],
)
def test_verify_outcomes(
    world: World, answer: Any, outcome: VerifyOutcome, dns_state: str | None
) -> None:
    token = start(world)
    built = answer(token)
    world.resolver.answers[RECORD] = built
    result = world.verify()
    assert (result.outcome, result.dns_state) == (outcome, dns_state)
    assert world.resolver.asked == [RECORD]
    row = world.row()
    if outcome is VerifyOutcome.verified:
        assert row.verification_status == "verified" and result.state.verified
        assert row.verification_method == "dns_txt"
        assert row.verified_at is not None and row.verified_at.replace(tzinfo=UTC) == NOW
        assert row.verification_token_hash is None and row.verification_token_expires_at is None
    else:  # nothing changes: still unverified, token still pending
        assert row.verification_status == "unverified" and not result.state.verified
        assert row.verification_token_hash == hash_token(token)
        assert result.state.pending


def test_expired_token_is_not_verified_and_queries_nothing(world: World) -> None:
    token = start(world)
    world.publish([f"dt-verify={token}"])
    world.clock.at = NOW + TTL  # expiry is exclusive
    result = world.verify()
    assert result.outcome is VerifyOutcome.expired and not result.state.pending
    assert world.resolver.asked == []
    assert world.row().verification_status == "unverified"
    # Starting again gives a working token.
    fresh = start(world)
    world.publish([f"dt-verify={fresh}"])
    assert world.verify().outcome is VerifyOutcome.verified


def test_verify_without_start(world: World) -> None:
    result = world.verify()
    assert result.outcome is VerifyOutcome.not_started and world.resolver.asked == []
    token = start(world)
    world.publish([f"dt-verify={token}"])
    world.verify()
    again = world.verify()
    assert again.outcome is VerifyOutcome.verified and world.resolver.asked == [RECORD]


def test_restart_on_a_verified_domain_keeps_it_verified(world: World) -> None:
    token = start(world)
    world.publish([f"dt-verify={token}"])
    world.verify()
    start(world)
    assert world.row().verification_status == "verified"
    assert world.verify().outcome is VerifyOutcome.not_found  # old record, new token
    assert world.row().verification_status == "verified"


def test_rename_during_lookup_wins(world: World) -> None:
    """The conditional UPDATE: a rename between the lookup and the write is not verified."""
    token = start(world)
    world.publish([f"dt-verify={token}"])
    svc = world.service()
    plan = svc.prepare_verify(world.domains["a"])
    assert isinstance(plan, VerifyPlan)
    fetched = asyncio.run(lookup(world.resolver, plan.name))
    owner = world.principal("owner")
    DomainService(world.db, TenantContext(world.tenants["a"], None), owner).rename(
        world.domains["a"], "renamed.example.com"
    )
    result = svc.finish_verify(plan, fetched)
    assert result.outcome is VerifyOutcome.not_found
    assert world.row().verification_status == "unverified"


def test_name_too_long_to_query_is_error(world: World) -> None:
    long_name = ".".join(["a" * 61] * 4) + ".com"  # 251 characters: _dt-verify. makes it 262
    ctx = TenantContext(world.tenants["a"], None)
    world.domains["long"] = repo_for(ctx, world.db).domains.create(long_name).id
    world.db.commit()
    start(world, "long")
    result = world.verify(key="long")
    assert (result.outcome, result.dns_state) == (VerifyOutcome.error, "invalid_name")
    assert world.row("long").verification_status == "unverified" and world.resolver.asked == []


# --- rename ---------------------------------------------------------------------------------------


def _verified(world: World) -> None:
    token = start(world)
    world.publish([f"dt-verify={token}"])
    assert world.verify().outcome is VerifyOutcome.verified


def test_rename_resets_verification_and_clears_the_token(world: World) -> None:
    _verified(world)
    start(world)  # a pending token too
    owner = world.principal("owner")
    DomainService(world.db, TenantContext(world.tenants["a"], None), owner).rename(
        world.domains["a"], "other.example.com"
    )
    row = world.row()
    assert (row.verification_status, row.verified_at, row.verification_method) == (
        "unverified",
        None,
        None,
    )
    assert row.verification_token_hash is None and row.verification_token_expires_at is None
    assert world.verify().outcome is VerifyOutcome.not_started


def test_rename_to_the_same_name_keeps_verification(world: World) -> None:
    _verified(world)
    owner = world.principal("owner")
    DomainService(world.db, TenantContext(world.tenants["a"], None), owner).rename(
        world.domains["a"], NAME.upper() + "."
    )
    assert world.row().verification_status == "verified"


# --- permissions and tenancy ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "toggles", "error"),
    [
        ("analyst", None, Forbidden),
        ("client_viewer", None, Forbidden),  # assigned domain: visible, not verifiable
        ("owner", {"domain.verify": False}, Forbidden),
        ("admin", {"domain.verify": False}, Forbidden),
    ],
)
def test_denied_roles_change_nothing(
    world: World, role: str, toggles: dict[str, Any] | None, error: type[Exception]
) -> None:
    svc = world.service(role, toggles=toggles)
    with pytest.raises(error):
        svc.start(world.domains["a"])
    with pytest.raises(error):
        asyncio.run(verify(svc, world.resolver, world.domains["a"]))
    assert world.row().verification_token_hash is None and world.resolver.asked == []
    assert svc.status(world.domains["a"]).status == "unverified"  # domain.read suffices


def test_admin_may_verify(world: World) -> None:
    started = world.service("admin").start(world.domains["a"])
    assert started.record_value.startswith(VALUE_PREFIX)


@pytest.mark.parametrize("target", ["b", "missing", "malformed", "unassigned"])
def test_invisible_domains_are_not_found(world: World, target: str) -> None:
    ids = {"b": world.domains["b"], "missing": 99999, "malformed": "1x", "unassigned": None}
    role = "client_viewer" if target == "unassigned" else "owner"
    domain_id = world.domains["a2"] if target == "unassigned" else ids[target]
    svc = world.service(role)
    for call in (svc.start, svc.status, svc.check_verify):
        with pytest.raises(NotFound):
            call(domain_id)
    with pytest.raises(NotFound):
        asyncio.run(verify(svc, world.resolver, domain_id))
    assert world.row("b").verification_token_hash is None and world.resolver.asked == []


# --- scheduled-run hook of the http_fetch gate ----------------------------------------------------

HTTP_CHECK = {
    "check_key": "web.ok",
    "name": "Web",
    "kind": "http_fetch",
    "definition": {"host": "{domain}", "expected_status": [200]},
    "severity": "medium",
    "remediation_text": {"en": "Fix.", "it": "Correggi."},
}


@pytest.mark.parametrize("verified", [False, True])
def test_scheduled_run_through_run_checks_for_is_gated(
    world: World, monkeypatch: pytest.MonkeyPatch, verified: bool
) -> None:
    """Monitor targets accept built-in ids only today, so the scheduler never builds a custom
    check. If a custom id ever reaches the executor, its registry must come from
    `run_checks_for(..., domain_id=...)`: this drives the real executor that way and shows an
    unverified domain yields `domain_unverified` with no fetch."""
    calls: list[str] = []

    async def fake_fetch(url: str, **_: Any) -> FetchResult:
        calls.append(url)
        return FetchResult(url=url, status=200, headers={}, body=b"", truncated=False)

    monkeypatch.setattr(custom_module, "guarded_fetch", fake_fetch)
    ctx = TenantContext(world.tenants["a"], None)
    repo_for(ctx, world.db).custom_checks.create(HTTP_CHECK)
    if verified:
        world.db.get(Domain, world.domains["a"]).verification_status = "verified"  # type: ignore[union-attr]
    target = repo_for(ctx, world.db).monitor_targets.create(
        world.domains["a"],
        check_ids=["spf"],
        interval_seconds=3600,
        next_run_at=NOW + timedelta(hours=1),
    )
    assert target is not None
    world.db.commit()
    custom_id = "custom:tenant:web.ok"

    def prepare(c: TenantContext, db: Session, ids: Sequence[str]) -> CheckRegistry:
        custom = run_checks_for(c, db, FetchLimits(), domain_id=world.domains["a"])
        return default_registry().with_checks(custom)

    executor = MonitorRunExecutor(
        world.factory, world.resolver, world.clock, heartbeat=timedelta(hours=24), prepare=prepare
    )
    due = DueTarget(target.id, world.tenants["a"], world.domains["a"], (custom_id,), 3600, NOW)
    outcome = asyncio.run(executor.execute(ScheduledRun(due, (), NOW, NOW + timedelta(hours=1))))
    assert outcome is not None
    (result,) = outcome.results
    assert result.check_id == custom_id
    if verified:
        assert calls == [f"https://{NAME}/"] and result.status == "ok"
    else:
        assert calls == [] and result.status == "error"
        assert [f.code for f in result.findings] == ["CUSTOM_HTTP_DOMAIN_UNVERIFIED"]
    world.db.rollback()
    status = world.db.scalars(
        select(Domain.verification_status).where(Domain.id == world.domains["a"])
    ).one()
    assert status == ("verified" if verified else "unverified")  # the run changes no state
