"""M7-08 collecting and storing DNS snapshots. A scripted resolver stands in for DNS: no network.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture).
"""

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.core.config import (
    DEFAULT_DNS_SNAPSHOT_HEARTBEAT_HOURS,
    DNS_SNAPSHOT_HEARTBEAT_HOURS_MAX,
    DNS_SNAPSHOT_HEARTBEAT_HOURS_MIN,
    ConfigError,
    Settings,
)
from app.core.db import create_db_engine, create_session_factory
from app.core.domain_names import InvalidDomainName
from app.core.tenancy import TenantContext
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.models import DnsSnapshot, Tenant
from app.models.dns_snapshot import MAX_ENTRIES_BYTES
from app.repositories import repo_for
from app.services.dns_diff import MAX_VALUE_CHARS, diff_snapshots
from app.services.dns_snapshot import (
    MAX_SELECTORS,
    collect_snapshot,
    heartbeat_from_settings,
    load_snapshot,
    snapshot_domain,
    store_if_due,
)

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
HB = timedelta(hours=24)
DOMAIN = "example.com"
SPF = "v=spf1 include:_spf.example.net -all"
DMARC = "v=DMARC1; p=none"
SECRET = "s3cr3t-value-DO-NOT-LEAK-0123456789abcdef"
ENC = "enc-value-DO-NOT-LEAK-0123456789abcdef-xyz"


class Scripted:
    """Resolver by (name, type): records, or a ResultState; anything else is nxdomain."""

    identity = "scripted"

    def __init__(self, answers: dict[tuple[str, str], Any]) -> None:
        self.answers = answers
        self.questions: list[DnsQuestion] = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.questions.append(question)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        await asyncio.sleep(0)
        self.in_flight -= 1
        answer = self.answers.get((question.name, question.rdtype), ResultState.nxdomain)
        if isinstance(answer, ResultState):
            return DnsResult(question, answer)
        records = tuple(DnsRecord(question.name, question.rdtype, 300, text) for text in answer)
        return DnsResult(question, ResultState.ok, records)


def zone(extra: dict[tuple[str, str], Any] | None = None) -> dict[tuple[str, str], Any]:
    base: dict[tuple[str, str], Any] = {
        (DOMAIN, "TXT"): [SPF, "google-site-verification=abc"],
        (f"_dmarc.{DOMAIN}", "TXT"): [DMARC],
        (DOMAIN, "MX"): ["10 Mail.Example.COM.", "20 mail2.example.com."],
        (DOMAIN, "NS"): ["NS1.example.net.", "ns2.example.net."],
    }
    base.update(extra or {})
    return base


def collect(
    answers: dict[tuple[str, str], Any], selectors: list[str] | None = None, domain: str = DOMAIN
) -> Any:
    return asyncio.run(collect_snapshot(Scripted(answers), domain, selectors or ()))


def by_key(snapshot: Any) -> dict[tuple[str, str], Any]:
    return {(e.name, e.rdtype): e for e in snapshot.entries}


# --- collecting --------------------------------------------------------------------------------


def test_collect_normalises_and_filters_the_monitored_names() -> None:
    snap = collect(zone())
    entries = by_key(snap)
    assert set(entries) == {("@", "TXT"), ("_dmarc", "TXT"), ("@", "MX"), ("@", "NS")}
    # Only the SPF record of the apex TXT set is monitored, not site-verification tokens.
    assert [v.text for v in entries[("@", "TXT")].values] == [SPF]
    assert [v.text for v in entries[("_dmarc", "TXT")].values] == [DMARC]
    assert [v.text for v in entries[("@", "MX")].values] == [
        "10 mail.example.com",
        "20 mail2.example.com",
    ]
    assert [v.text for v in entries[("@", "NS")].values] == ["ns1.example.net", "ns2.example.net"]
    assert not snap.truncated


def test_collect_does_not_monitor_bimi_or_mta_sts() -> None:
    resolver = Scripted(zone())
    asyncio.run(collect_snapshot(resolver, DOMAIN, ["s1"]))
    assert {(q.name, q.rdtype) for q in resolver.questions} == {
        (DOMAIN, "TXT"),
        (f"_dmarc.{DOMAIN}", "TXT"),
        (DOMAIN, "MX"),
        (DOMAIN, "NS"),
        (f"s1._domainkey.{DOMAIN}", "TXT"),
    }


def test_collect_is_stable_across_record_order_and_txt_splitting() -> None:
    a = collect(zone())
    b = collect(
        zone(
            {
                (DOMAIN, "MX"): ["20 mail2.example.com.", "10 mail.example.com."],
                (DOMAIN, "TXT"): ['"v=spf1 include:_spf" ".example.net -all"'],
            }
        )
    )
    assert a.content_hash == b.content_hash
    assert diff_snapshots(a, b) == ()


def test_domain_is_normalised_but_a_bad_domain_is_a_caller_bug() -> None:
    assert collect(zone(), domain="EXAMPLE.com.").content_hash == collect(zone()).content_hash
    with pytest.raises(InvalidDomainName):
        collect(zone(), domain="not a domain")


def test_no_spf_among_apex_txt_is_nodata_not_removed_or_error() -> None:
    snap = collect(zone({(DOMAIN, "TXT"): ["only-a-token"]}))
    assert by_key(snap)[("@", "TXT")].state == "nodata"


@pytest.mark.parametrize(
    "state",
    [
        ResultState.servfail,
        ResultState.refused,
        ResultState.timeout,
        ResultState.truncated,
        ResultState.malformed,
        ResultState.network_error,
        ResultState.blocked,
        ResultState.error,
    ],
)
def test_every_failed_lookup_is_stored_as_error_never_as_removed(state: ResultState) -> None:
    good = collect(zone())
    bad = collect(zone({(f"_dmarc.{DOMAIN}", "TXT"): state}))
    assert by_key(bad)[("_dmarc", "TXT")].state == "error"
    (change,) = diff_snapshots(good, bad)
    assert (change.name, change.kind) == ("_dmarc", "inconclusive")


@pytest.mark.parametrize("state", [ResultState.nxdomain, ResultState.nodata])
def test_definitive_absence_is_stored_as_such(state: ResultState) -> None:
    snap = collect(zone({(f"_dmarc.{DOMAIN}", "TXT"): state}))
    assert by_key(snap)[("_dmarc", "TXT")].state == state.value


def test_dkim_selectors_are_deduplicated_sorted_and_relative() -> None:
    key = "v=DKIM1; k=rsa; p=AAAA"
    snap = collect(zone({(f"b._domainkey.{DOMAIN}", "TXT"): [key]}), ["b", "a", "b"])
    entries = by_key(snap)
    assert ("a._domainkey", "TXT") in entries and ("b._domainkey", "TXT") in entries
    assert entries[("a._domainkey", "TXT")].state == "nxdomain"
    assert [v.text for v in entries[("b._domainkey", "TXT")].values] == [key]


@pytest.mark.parametrize("bad", ["", "A", "a.b", "a b", "x" * 64, "\x00", "é", "a\n", None, 5])
def test_a_bad_selector_is_a_caller_bug(bad: Any) -> None:
    with pytest.raises(ValueError):
        collect(zone(), [bad])


def test_selectors_over_the_cap_are_dropped_and_flagged() -> None:
    names = [f"s{i:04d}" for i in range(MAX_SELECTORS + 5)]
    resolver = Scripted(zone())
    snap = asyncio.run(collect_snapshot(resolver, DOMAIN, names))
    assert snap.truncated
    assert len(snap.entries) == 4 + MAX_SELECTORS
    assert ("s0000._domainkey", "TXT") in by_key(snap)
    assert ("s0261._domainkey", "TXT") not in by_key(snap)
    assert resolver.max_in_flight <= 8  # bounded concurrency


def test_longest_names_are_queried_and_stored() -> None:
    # A 253-character domain: the DKIM owner name no longer fits, so it is an `error` entry (the
    # name cannot exist), while the other names still work.
    labels = ["a" * 61] * 3 + ["b" * 63, "com"]
    long_domain = ".".join(labels)
    assert len(long_domain) == 253
    selector = "s" * 63
    answers = {(long_domain, "NS"): ["ns1.example.net."], (f"_dmarc.{long_domain}", "TXT"): [DMARC]}
    snap = collect(answers, [selector], domain=long_domain)
    entries = by_key(snap)
    assert entries[("@", "NS")].state == "ok"
    # `_dmarc.` + 253 characters is over the limit: error, not a crash and not "removed".
    assert entries[("_dmarc", "TXT")].state == "error"
    assert entries[(f"{selector}._domainkey", "TXT")].state == "error"
    assert max(len(e.name) for e in snap.entries) == 63 + len("._domainkey")


def test_hostile_answers_are_bounded_and_safe() -> None:
    hostile = [
        "v=spf1 " + "\x00\x1b[31m" * 5000 + "-all",
        "v=spf1 " + "‮" * 100000,
        "v=spf1 " + "中" * 100000,
        "v=spf1 " + "x" * 1000000,
        "v=spf1 \ud800",
    ]
    many_mx = [f"{i} mx{i}.example.com." for i in range(500)]
    snap = collect(zone({(DOMAIN, "TXT"): hostile, (DOMAIN, "MX"): many_mx}))
    entries = by_key(snap)
    assert all(len(v.text or "") <= MAX_VALUE_CHARS for e in snap.entries for v in e.values)
    assert entries[("@", "MX")].count == 500 and len(entries[("@", "MX")].values) <= 16
    assert snap.truncated
    from app.services.dns_diff import to_stored

    stored, _ = to_stored(snap)
    assert len(json.dumps(stored)) <= MAX_ENTRIES_BYTES
    assert "\\u0000" not in json.dumps(stored)


# --- settings ----------------------------------------------------------------------------------


def _settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    monkeypatch.delenv("DNS_SNAPSHOT_HEARTBEAT_HOURS", raising=False)
    for name, value in {"SECRET_KEY": SECRET, "ENCRYPTION_KEY": ENC, **env}.items():
        monkeypatch.setenv(name, value)
    return Settings()  # type: ignore[call-arg]


def test_heartbeat_setting_default_and_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    default = heartbeat_from_settings(_settings(monkeypatch))
    assert default == timedelta(hours=DEFAULT_DNS_SNAPSHOT_HEARTBEAT_HOURS)
    for hours in (DNS_SNAPSHOT_HEARTBEAT_HOURS_MIN, 12, DNS_SNAPSHOT_HEARTBEAT_HOURS_MAX):
        s = _settings(monkeypatch, DNS_SNAPSHOT_HEARTBEAT_HOURS=str(hours))
        assert heartbeat_from_settings(s) == timedelta(hours=hours)


@pytest.mark.parametrize(
    "raw", ["0", "-1", str(DNS_SNAPSHOT_HEARTBEAT_HOURS_MAX + 1), "abc", "", "1.5", "NaN"]
)
def test_heartbeat_setting_rejects_out_of_range_and_malformed(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    with pytest.raises(ConfigError) as exc:
        _settings(monkeypatch, DNS_SNAPSHOT_HEARTBEAT_HOURS=raw)
    assert exc.value.params == {"name": "DNS_SNAPSHOT_HEARTBEAT_HOURS"}


# --- storing -----------------------------------------------------------------------------------


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@dataclass
class World:
    session: Session
    tenant_a: int
    tenant_b: int
    domains: dict[str, int]

    def repos(self, tenant: str = "a") -> Any:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return repo_for(TenantContext(tid, None), self.session)

    def count(self) -> int:
        self.session.expire_all()
        return int(self.session.scalar(select(func.count()).select_from(DnsSnapshot)) or 0)


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        session.add_all([ta, tb])
        session.flush()
        domains = {
            "a": repo_for(TenantContext(ta.id, None), session).domains.create(DOMAIN).id,
            "b": repo_for(TenantContext(tb.id, None), session).domains.create("b.example").id,
        }
        session.commit()
        yield World(session, ta.id, tb.id, domains)
    finally:
        session.close()


def store(
    world: World, snap: Any, at: datetime = NOW, tenant: str = "a", hb: timedelta = HB
) -> Any:
    domain = world.domains[tenant]
    return store_if_due(world.repos(tenant).dns_snapshots, domain, snap, at, hb)


def test_first_snapshot_is_stored_then_unchanged_is_not(world: World) -> None:
    snap = collect(zone())
    first = store(world, snap)
    assert first.reason == "first" and first.record is not None
    again = store(world, snap, NOW + timedelta(hours=1))
    assert again.reason == "unchanged" and again.record is None
    assert world.count() == 1


def test_a_change_is_stored_immediately(world: World) -> None:
    store(world, collect(zone()))
    changed = store(
        world, collect(zone({(DOMAIN, "NS"): ["ns9.example.net."]})), NOW + timedelta(minutes=1)
    )
    assert changed.reason == "changed" and world.count() == 2


def test_an_unchanged_snapshot_is_stored_again_after_the_heartbeat(world: World) -> None:
    snap = collect(zone())
    store(world, snap)
    assert store(world, snap, NOW + HB - timedelta(seconds=1)).reason == "unchanged"
    beat = store(world, snap, NOW + HB)
    assert beat.reason == "heartbeat" and world.count() == 2
    # The heartbeat restarts from the new row.
    assert store(world, snap, NOW + HB + timedelta(hours=1)).reason == "unchanged"
    assert store(world, snap, NOW + 2 * HB).reason == "heartbeat"


def test_a_clock_that_went_back_does_not_store_an_unchanged_snapshot(world: World) -> None:
    snap = collect(zone())
    store(world, snap)
    assert store(world, snap, NOW - timedelta(days=3)).reason == "unchanged"


@pytest.mark.parametrize("hb", [timedelta(0), timedelta(seconds=-1), 24, None])
def test_a_bad_heartbeat_is_rejected(world: World, hb: Any) -> None:
    with pytest.raises(ValueError):
        store(world, collect(zone()), hb=hb)
    assert world.count() == 0


def test_error_then_ok_is_stored_and_diffs_as_inconclusive(world: World) -> None:
    ok = collect(zone())
    err = collect(zone({(f"_dmarc.{DOMAIN}", "TXT"): ResultState.timeout}))
    store(world, ok)
    assert store(world, err, NOW + timedelta(minutes=5)).reason == "changed"
    repo = world.repos().dns_snapshots
    newest, older = repo.list_for_domain(world.domains["a"])[:2]
    (change,) = diff_snapshots(load_snapshot(older), load_snapshot(newest))
    assert (change.name, change.kind) == ("_dmarc", "inconclusive")


def test_stored_snapshot_loads_back_equal_in_content(world: World) -> None:
    snap = collect(zone())
    record = store(world, snap).record
    loaded = load_snapshot(record)
    assert loaded.content_hash == snap.content_hash
    assert diff_snapshots(snap, loaded) == ()


def test_a_foreign_or_unknown_domain_stores_nothing(world: World) -> None:
    snap = collect(zone())
    repo_b = world.repos("b").dns_snapshots
    assert store_if_due(repo_b, world.domains["a"], snap, NOW, HB) is None
    assert store_if_due(repo_b, 999_999, snap, NOW, HB) is None
    assert store_if_due(repo_b, "1", snap, NOW, HB) is None
    assert world.count() == 0


def test_the_previous_snapshot_is_per_tenant_domain(world: World) -> None:
    snap = collect(zone())
    store(world, snap, tenant="a")
    # Tenant B's domain has no snapshot of its own, whatever tenant A stored.
    assert store(world, snap, tenant="b").reason == "first"
    assert world.count() == 2


# --- snapshot_domain (selectors from the tenant's repository) --------------------------------


def test_snapshot_domain_uses_only_the_tenants_enabled_selectors(world: World) -> None:
    a, b = world.repos("a"), world.repos("b")
    a.dkim_selectors.create({"selector": "mine", "record_type": "txt"})
    off = a.dkim_selectors.create({"selector": "off", "record_type": "txt"})
    a.dkim_selectors.update(off.id, {"enabled": False})
    b.dkim_selectors.create({"selector": "theirs", "record_type": "txt"})
    world.session.commit()
    resolver = Scripted(zone())
    out = asyncio.run(snapshot_domain(a, resolver, world.domains["a"], NOW, HB))
    assert out is not None and out.reason == "first"
    queried = {q.name for q in resolver.questions}
    assert f"mine._domainkey.{DOMAIN}" in queried
    assert not any("theirs" in n or n.startswith("off.") for n in queried)


def test_snapshot_domain_of_a_foreign_domain_makes_no_lookup(world: World) -> None:
    resolver = Scripted(zone())
    assert (
        asyncio.run(snapshot_domain(world.repos("b"), resolver, world.domains["a"], NOW, HB))
        is None
    )
    assert asyncio.run(snapshot_domain(world.repos("a"), resolver, "x", NOW, HB)) is None
    assert resolver.questions == [] and world.count() == 0
