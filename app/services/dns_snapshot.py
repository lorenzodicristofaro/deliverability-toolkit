"""Collect and store DNS snapshots (M7-08).

`collect_snapshot` queries the monitored names through the shared resolver (no new DNS code: the
`Resolver` protocol and `app.checks.dnsutil.classify`, so the state mapping is the one checks
use): apex TXT filtered to SPF records, `_dmarc` TXT filtered to DMARC records, apex MX, apex NS
and the TXT of every configured DKIM selector name. Lookup states map to the four stored states:
ok, nxdomain, nodata and `error` (everything that did not complete, never "removed"). A TXT
lookup that answered but holds no SPF/DMARC record is `nodata` for that entry. A name that cannot
be queried (invalid, or over 253 characters) is `error`. At most `MAX_SELECTORS` selectors are
probed (sorted, de-duplicated; the snapshot is flagged truncated when more were configured).

`store_if_due` stores a snapshot in full only when the content hash differs from the newest one
of the domain, or a heartbeat interval has passed since it, or there is none. `snapshot_domain`
runs both for one tenant domain, with the selectors from the tenant's own repository (global and
tenant selectors visible to it, enabled only).

Scheduling and alerting are out of scope. The clock is a parameter, never read here.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from app.checks.dnsutil import classify
from app.core.config import (
    DNS_SNAPSHOT_HEARTBEAT_HOURS_MAX,
    DNS_SNAPSHOT_HEARTBEAT_HOURS_MIN,
    Settings,
)
from app.core.domain_names import InvalidDomainName, to_ascii_domain, to_dns_name
from app.dns.types import DnsQuestion, DnsResult, Resolver, ResultState
from app.repositories import TenantRepositories
from app.repositories.base import MAX_LIMIT
from app.repositories.dns_snapshots import DnsSnapshotRecord, DnsSnapshotRepository
from app.services.dns_diff import (
    MAX_NAME_LENGTH,
    Entry,
    Snapshot,
    SnapshotFormatError,
    build_entry,
    build_snapshot,
    from_stored,
    is_dmarc,
    is_spf,
    normalise_mx,
    normalise_ns,
    normalise_txt,
    to_stored,
)

MAX_SELECTORS: Final = 256
MAX_CONCURRENCY: Final = 8
MAX_SELECTOR_LENGTH: Final = 63  # one DNS label
DKIM_SUFFIX: Final = "._domainkey"


def heartbeat_from_settings(settings: Settings) -> timedelta:
    hours = settings.dns_snapshot_heartbeat_hours
    if not DNS_SNAPSHOT_HEARTBEAT_HOURS_MIN <= hours <= DNS_SNAPSHOT_HEARTBEAT_HOURS_MAX:
        raise ValueError("dns_snapshot_heartbeat_hours out of range")
    return timedelta(hours=hours)


def _valid_selector(selector: object) -> str:
    if (
        not isinstance(selector, str)
        or not 1 <= len(selector) <= MAX_SELECTOR_LENGTH
        or selector != selector.lower()
        or not selector.isascii()
        or not selector.isprintable()
        or any(c in selector for c in " .")
    ):
        raise ValueError("selector must be one lowercase printable ASCII DNS label")
    return selector


async def _lookup(resolver: Resolver, fqdn: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
    """(state, raw rdata texts). An unqueryable name is `error`."""
    try:
        question = DnsQuestion(to_dns_name(fqdn), rdtype)
    except (InvalidDomainName, ValueError):
        return "error", ()
    result: DnsResult = await resolver.resolve(question)
    state, evaluated, texts, _ttl = classify(result, rdtype)
    if not evaluated:
        return "error", ()
    if state is ResultState.ok:
        return "ok", tuple(texts)
    return state.value, ()  # nxdomain / nodata


def _entry(name: str, rdtype: str, state: str, values: Iterable[str], keep: bool = True) -> Entry:
    items = list(values)
    if state == "ok" and not items:
        state = "nodata"  # the lookup answered, but nothing of the kind we monitor
    return build_entry(name, rdtype, state, items if keep else ())


async def collect_snapshot(
    resolver: Resolver, domain: str, selectors: Iterable[str] = ()
) -> Snapshot:
    """The snapshot of `domain` now. `domain` must be a valid domain name (InvalidDomainName
    otherwise: a caller bug, not a DNS outcome); a bad selector is a ValueError."""
    apex = to_ascii_domain(domain)
    chosen = sorted({_valid_selector(s) for s in selectors})
    dropped = len(chosen) > MAX_SELECTORS
    chosen = chosen[:MAX_SELECTORS]

    plan: list[tuple[str, str, str, str]] = [  # (relative name, rdtype, fqdn, kind)
        ("@", "TXT", apex, "spf"),
        ("_dmarc", "TXT", f"_dmarc.{apex}", "dmarc"),
        ("@", "MX", apex, "mx"),
        ("@", "NS", apex, "ns"),
        *((f"{s}{DKIM_SUFFIX}", "TXT", f"{s}{DKIM_SUFFIX}.{apex}", "dkim") for s in chosen),
    ]
    gate = asyncio.Semaphore(MAX_CONCURRENCY)

    async def one(item: tuple[str, str, str, str]) -> Entry:
        name, rdtype, fqdn, kind = item
        async with gate:
            state, raw = await _lookup(resolver, fqdn, rdtype)
        if kind == "mx":
            return _entry(name, rdtype, state, (normalise_mx(r) for r in raw))
        if kind == "ns":
            return _entry(name, rdtype, state, (normalise_ns(r) for r in raw))
        texts = [normalise_txt(r) for r in raw]
        if kind == "spf":
            texts = [t for t in texts if is_spf(t)]
        elif kind == "dmarc":
            texts = [t for t in texts if is_dmarc(t)]
        return _entry(name, rdtype, state, texts)

    entries = await asyncio.gather(*(one(item) for item in plan))
    return build_snapshot(entries, truncated=dropped)


# --- storing ----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StoreOutcome:
    """`reason`: first, changed, heartbeat (a row was stored) or unchanged (nothing stored)."""

    record: DnsSnapshotRecord | None
    reason: str


def store_if_due(
    repo: DnsSnapshotRepository,
    domain_id: object,
    snapshot: Snapshot,
    now: datetime,
    heartbeat: timedelta,
) -> StoreOutcome | None:
    """Store `snapshot` when due. None if the domain is missing, foreign or malformed (nothing
    written). `now` must be timezone-aware."""
    if not isinstance(heartbeat, timedelta) or heartbeat <= timedelta(0):
        raise ValueError("heartbeat must be a positive timedelta")
    previous = repo.latest(domain_id)
    if previous is None:
        reason = "first"
    elif previous.content_hash != snapshot.content_hash:
        reason = "changed"
    elif now - previous.taken_at >= heartbeat:
        reason = "heartbeat"
    else:
        return StoreOutcome(None, "unchanged")
    entries, truncated = to_stored(snapshot)
    record = repo.record(
        domain_id,
        taken_at=now,
        content_hash=snapshot.content_hash,
        entries=entries,
        truncated=truncated,
    )
    return None if record is None else StoreOutcome(record, reason)


def load_snapshot(record: DnsSnapshotRecord) -> Snapshot:
    """The stored snapshot as diff input. SnapshotFormatError if the stored content is malformed."""
    return from_stored(list(record.entries), record.content_hash, record.truncated)


async def snapshot_domain(
    repos: TenantRepositories,
    resolver: Resolver,
    domain_id: object,
    now: datetime,
    heartbeat: timedelta,
) -> StoreOutcome | None:
    """Collect and store (when due) the snapshot of one domain of the repositories' tenant.
    None if the domain is missing, foreign or malformed: no lookup is made then."""
    domain = repos.domains.get(domain_id)
    if domain is None:
        return None
    selectors = [s.selector for s in repos.dkim_selectors.list(enabled_only=True, limit=MAX_LIMIT)]
    snapshot = await collect_snapshot(resolver, domain.name, selectors)
    return store_if_due(repos.dns_snapshots, domain_id, snapshot, now, heartbeat)


__all__ = [
    "MAX_NAME_LENGTH",
    "MAX_SELECTORS",
    "SnapshotFormatError",
    "StoreOutcome",
    "collect_snapshot",
    "heartbeat_from_settings",
    "load_snapshot",
    "snapshot_domain",
    "store_if_due",
]
