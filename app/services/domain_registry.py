"""The check registry of a domain run (M7-10b): one preparation shared by the API domain routes
(`app.api.v1.checks._prepare`) and the scheduled run executor (`app.services.monitor_run`).

- DKIM (when requested): probes the global selectors plus the tenant's
  (`dkim_probe_selectors.registry_for(resolve_probe_selectors(ctx, db))`).
- DNSBL (when requested): runs the instance's enabled list ids read for this run
  (`dnsbl_admin.enabled_list_ids`, M7-05c).

Failure behaviour, decided per caller (`strict`):
- `strict=True` (the API): any failure propagates unchanged, so the route keeps answering exactly
  as before this helper existed (its typed error response; nothing is half-run).
- `strict=False` (the executor): an unreadable DNSBL enablement does not abort the run; the DNSBL
  check gets `enabled_ids=None`, so it is recorded as `error` (`DNSBL_ENABLEMENT_UNAVAILABLE`),
  never skipped and never `ok`. A failure reading the DKIM selectors still propagates in both
  modes (it is tenant data the run cannot do without; the executor's load fails as before).

The ESP check and custom checks stay with the API (`_prepare` / `_prepare_all`): the executor
does not run them. The caller owns the session and ends its transaction.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from sqlalchemy.orm import Session

from app.checks.dkim import DkimCheck
from app.checks.dnsbl import DnsblCheck
from app.checks.registry import CheckRegistry
from app.core.tenancy import TenantContext
from app.services.checks import default_registry, with_dnsbl_enabled
from app.services.dkim_probe_selectors import registry_for, resolve_probe_selectors
from app.services.dnsbl_admin import enabled_list_ids

logger = logging.getLogger("app.domain_registry")


def prepare_domain_registry(
    ctx: TenantContext, db: Session, ids: Sequence[str], *, strict: bool
) -> CheckRegistry | None:
    """The registry for running `ids` on a domain of `ctx`'s tenant; None when neither DKIM nor
    DNSBL is requested (the default registry applies). See the module docstring for `strict`."""
    registry: CheckRegistry | None = None
    if DkimCheck.id in ids:
        registry = registry_for(resolve_probe_selectors(ctx, db))
    if DnsblCheck.id in ids:
        enabled: frozenset[str] | None
        if strict:
            enabled = enabled_list_ids(db)
        else:
            try:
                enabled = enabled_list_ids(db)
            except Exception as exc:  # noqa: BLE001 - the DNSBL check then reports `error`
                logger.warning(
                    "dnsbl enablement unreadable (%s)",
                    type(exc).__name__,
                    extra={"event": "monitor_run.dnsbl_enablement_failed"},
                )
                enabled = None
        registry = with_dnsbl_enabled(registry or default_registry(), enabled)
    return registry


__all__ = ["prepare_domain_registry"]
