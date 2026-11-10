"""The DKIM selector list of a tenant-scoped check (M5-20).

`CheckContext` has no database handle by design, so the caller resolves the list here and hands it
to the check (`DkimCheck(selectors=...)`, `dkim_events(selectors=...)`). Tenant-less surfaces (free
checks, CLI `check`) do not come here: they stay on the seed file.

The list is the enabled global rows plus the context tenant's enabled rows, read only through the
tenant repository, deduplicated and sorted in Python, because the seed is sorted the same way and
SQL collation can differ. With only the synced seed it equals the seed list, so the results do not
change. A disabled tenant row does not hide an enabled global row of the same name.

Fallback: no global row at all, enabled or not, means the seed sync failed or never ran, and the
seed file stands in for the global rows. Global rows that exist but are all disabled are the
admin's choice: the list can then be empty, which the check reports as "nothing probed". A seed
file that cannot be read gives `names=None`: the check, or the SSE stream, then tries to load it and
reports status `error`.

At most `MAX_PROBE_SELECTORS` names are probed, on API and SSE alike. The admin caps normally keep
the list under it; concurrent creates can overshoot, and then the last names in sort order are
dropped and `dropped` makes the result incomplete.

Providers (M5-23b): `providers` maps each probed name to the provider shown next to it in the
result, for every role that can see the domain (`notes` never leaves the admin surfaces). Only
enabled rows count; a disabled row contributes neither a probe nor a provider. When an enabled
tenant row and an enabled global row share a name, the tenant row's non-empty provider wins: it is
more specific and is only ever read inside its own tenant. An empty (NULL or blank) tenant provider
falls back to the global one. In the seed fallback the seed's provider stands in for the global
row's. A name with no provider has no entry.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from sqlalchemy.orm import Session

from app.checks.dkim import DkimCheck
from app.checks.dkim_selectors import KnowledgeError, list_selectors
from app.checks.registry import CheckRegistry
from app.core.tenancy import TenantContext
from app.repositories import repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.dkim_selectors import DkimSelectorRecord, DkimSelectorRepository
from app.services.checks import default_registry

MAX_PROBE_SELECTORS: Final = 250


@dataclass(frozen=True, slots=True)
class ProbeSelectors:
    names: tuple[str, ...] | None  # None: the check or stream loads the seed file itself
    dropped: int = 0
    # name -> provider of the probed names; None (with names None): the seed's providers
    providers: Mapping[str, str] | None = None


def all_visible(store: DkimSelectorRepository) -> list[DkimSelectorRecord]:
    """Every row the tenant repository can see, enabled or not, paging past its limit."""
    rows: list[DkimSelectorRecord] = []
    while True:
        page = store.list(limit=MAX_LIMIT, offset=len(rows))
        rows.extend(page)
        if len(page) < MAX_LIMIT:
            return rows


def _providers(
    rows: Iterable[DkimSelectorRecord], seed: Mapping[str, str], names: Iterable[str]
) -> Mapping[str, str]:
    """name -> provider for `names`: enabled tenant row, else enabled global row, else seed."""
    by_scope: dict[str, dict[str, str]] = {"global": {}, "tenant": {}}
    for r in rows:
        if r.enabled and r.provider and r.provider.strip() and r.scope in by_scope:
            by_scope[r.scope][r.selector] = r.provider
    out: dict[str, str] = {}
    for name in names:
        provider = by_scope["tenant"].get(name) or by_scope["global"].get(name) or seed.get(name)
        if provider:
            out[name] = provider
    return MappingProxyType(out)


def resolve_probe_selectors(ctx: TenantContext, db: Session) -> ProbeSelectors:
    rows = all_visible(repo_for(ctx, db).dkim_selectors)
    names = {r.selector for r in rows if r.enabled}
    seed: dict[str, str] = {}
    if not any(r.scope == "global" for r in rows):
        try:
            entries = list_selectors()
        except KnowledgeError:
            return ProbeSelectors(None)
        names.update(s.name for s in entries)
        seed = {s.name: s.provider for s in entries if s.provider}
    ordered = sorted(names)
    probed = tuple(ordered[:MAX_PROBE_SELECTORS])
    return ProbeSelectors(
        probed,
        max(0, len(ordered) - MAX_PROBE_SELECTORS),
        _providers(rows, seed, probed),
    )


def resolve_and_release(ctx: TenantContext, db: Session) -> ProbeSelectors:
    """Resolve the list and end the transaction, so no connection is held during DNS work."""
    try:
        return resolve_probe_selectors(ctx, db)
    finally:
        db.rollback()


def registry_for(probe: ProbeSelectors) -> CheckRegistry:
    """The default checks, with DKIM probing `probe`."""
    base = default_registry()
    registry = CheckRegistry()
    for check_id in base.all_ids():
        if check_id == DkimCheck.id:
            registry.register(
                DkimCheck(selectors=probe.names, dropped=probe.dropped, providers=probe.providers)
            )
        else:
            registry.register(base.get(check_id))
    return registry
