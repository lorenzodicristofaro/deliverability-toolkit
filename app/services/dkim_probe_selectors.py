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
file that cannot be read gives `names=None`, so the check loads it and reports its own `error`.

At most `MAX_PROBE_SELECTORS` names are probed, on API and SSE alike. The admin caps normally keep
the list under it; concurrent creates can overshoot, and then the last names in sort order are
dropped and `dropped` makes the result incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    names: tuple[str, ...] | None  # None: the check uses the seed file itself
    dropped: int = 0


def all_visible(store: DkimSelectorRepository) -> list[DkimSelectorRecord]:
    """Every row the tenant repository can see, enabled or not, paging past its limit."""
    rows: list[DkimSelectorRecord] = []
    while True:
        page = store.list(limit=MAX_LIMIT, offset=len(rows))
        rows.extend(page)
        if len(page) < MAX_LIMIT:
            return rows


def resolve_probe_selectors(ctx: TenantContext, db: Session) -> ProbeSelectors:
    rows = all_visible(repo_for(ctx, db).dkim_selectors)
    names = {r.selector for r in rows if r.enabled}
    if not any(r.scope == "global" for r in rows):
        try:
            names.update(s.name for s in list_selectors())
        except KnowledgeError:
            return ProbeSelectors(None)
    ordered = sorted(names)
    return ProbeSelectors(
        tuple(ordered[:MAX_PROBE_SELECTORS]), max(0, len(ordered) - MAX_PROBE_SELECTORS)
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
            registry.register(DkimCheck(selectors=probe.names, dropped=probe.dropped))
        else:
            registry.register(base.get(check_id))
    return registry
