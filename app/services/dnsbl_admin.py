"""DNSBL list enablement by the instance admin (M7-05c): list, enable, disable.

Every operation needs `instance.manage` on the instance (`can()` BEFORE any repository is built),
which only the instance admin flag grants: every tenant role, whatever its tenant, is refused
(`ListsForbidden`, 403). The REST API (`app.api.v1.dnsbl_lists`) and the admin page
(`app.web.dnsbl_lists`) both go through this service.

What is shown comes from `seeds/dnsbl.yaml` only (name, zone, kind, status, unverified fields,
verified_on, sources, usage_policy, default_enabled); nothing about a list's policy is written in
code. A list without `usage_policy` has `usage_policy=None` and the surfaces say that the list data
has no policy text.

Rules:
- enable needs `policy_acknowledged is True` (`PolicyNotAcknowledged`, 422), and for a list whose
  status is not `verified` also `unverified_confirmed is True` (`UnverifiedNotConfirmed`, 422).
  The acknowledgement is checked before the confirmation. Re-enabling refreshes actor, time and
  acknowledgement. The stored `unverified_confirmed` is True only for an unverified list;
- disable deletes the row; disabling a list that is not enabled succeeds and changes nothing;
- a `default_enabled: true` list always runs (`app.checks.dnsbl.is_enabled`), so enabling or
  disabling it is refused (`AlwaysEnabled`, 409) instead of storing a row that does nothing;
- an id that is not a list of the seed file is `ListNotFound` (404), checked after the permission;
- a seed file that cannot be loaded is `ListsUnavailable` (503): nothing can be shown or enabled.

Audit: there is no audit log table yet (domains TODO(M10)); like the other admin services, enable
and disable are logged as structured events with the actor and the list id only.

`enabled_list_ids(db)` is the read used by every check run (API, CLI): the enabled ids of the
instance, no permission needed beyond the one to run the check.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy.orm import Session

from app.checks.dnsbl import is_enabled
from app.checks.dnsbl_schema import DnsblList, DnsblSchemaError, load_dnsbl_lists
from app.core.permissions import Action, InstanceResource, Principal, can
from app.repositories.dnsbl_enablement import (
    DnsblEnablementRecord,
    DnsblEnablementRepository,
    EnablementConflict,
)

logger = logging.getLogger("app.dnsbl_lists")

FORBIDDEN_KEY: Final = "api.dnsbl_lists.error.forbidden"
NOT_FOUND_KEY: Final = "api.dnsbl_lists.error.not_found"
POLICY_KEY: Final = "api.dnsbl_lists.error.policy_not_acknowledged"
UNVERIFIED_KEY: Final = "api.dnsbl_lists.error.unverified_not_confirmed"
ALWAYS_ENABLED_KEY: Final = "api.dnsbl_lists.error.always_enabled"
UNAVAILABLE_KEY: Final = "api.dnsbl_lists.error.unavailable"


class DnsblAdminError(Exception):
    """Base error. `status` is the HTTP status, `key` the i18n key; never carries user input."""

    status = 500
    key = "ui.error.server.detail"


class ListsForbidden(DnsblAdminError):
    status = 403
    key = FORBIDDEN_KEY


class ListNotFound(DnsblAdminError):
    status = 404
    key = NOT_FOUND_KEY


class PolicyNotAcknowledged(DnsblAdminError):
    status = 422
    key = POLICY_KEY


class UnverifiedNotConfirmed(DnsblAdminError):
    status = 422
    key = UNVERIFIED_KEY


class AlwaysEnabled(DnsblAdminError):
    status = 409
    key = ALWAYS_ENABLED_KEY


class ListsUnavailable(DnsblAdminError):
    status = 503
    key = UNAVAILABLE_KEY


@dataclass(frozen=True, slots=True)
class DnsblListView:
    """One list of the seed file with its instance enablement."""

    entry: DnsblList
    record: DnsblEnablementRecord | None

    @property
    def enabled(self) -> bool:
        """Whether runs query it: `default_enabled`, or enabled by the instance admin."""
        return is_enabled(
            self.entry, frozenset() if self.record is None else frozenset({self.entry.id})
        )


def enabled_list_ids(db: Session) -> frozenset[str]:
    """The ids the instance admin enabled (read per check run)."""
    return DnsblEnablementRepository(db).enabled_ids()


def _now() -> datetime:
    return datetime.now(UTC)


class DnsblAdminService:
    """One request's enablement operations."""

    def __init__(
        self,
        db: Session,
        principal: Principal,
        *,
        lists: Callable[[], tuple[DnsblList, ...]] | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._db = db
        self._principal = principal
        self._lists = lists
        self._clock = clock

    # --- authorization ------------------------------------------------------------------------

    def check_manage(self) -> None:
        """`instance.manage` on the instance. No repository use."""
        if not can(self._principal, Action.INSTANCE_MANAGE, InstanceResource()):
            raise ListsForbidden

    # --- helpers ------------------------------------------------------------------------------

    def _seed(self) -> tuple[DnsblList, ...]:
        try:
            return (self._lists or load_dnsbl_lists)()
        except DnsblSchemaError:
            logger.warning("dnsbl list data unavailable")
            raise ListsUnavailable from None

    def find(self, list_id: object) -> DnsblList:
        """The list `list_id` of the seed file (permission first)."""
        self.check_manage()
        for lst in self._seed():
            if lst.id == list_id:
                return lst
        raise ListNotFound

    def _view(self, lst: DnsblList) -> DnsblListView:
        return DnsblListView(lst, DnsblEnablementRepository(self._db).get(lst.id))

    def _audit(self, event: str, list_id: str) -> None:
        logger.info(
            "dnsbl list enablement changed",
            extra={
                "event": f"dnsbl_lists.{event}",
                "actor": self._principal.user_id,
                "list_id": list_id,
            },
        )

    # --- reads --------------------------------------------------------------------------------

    def views(self) -> list[DnsblListView]:
        """Every list of the seed file, sorted by id, with its enablement."""
        self.check_manage()
        lists = self._seed()
        records = {r.list_id: r for r in DnsblEnablementRepository(self._db).records()}
        return [
            DnsblListView(lst, records.get(lst.id)) for lst in sorted(lists, key=lambda x: x.id)
        ]

    # --- writes -------------------------------------------------------------------------------

    def enable(
        self, list_id: object, *, policy_acknowledged: object, unverified_confirmed: object
    ) -> DnsblListView:
        lst = self.find(list_id)
        if lst.default_enabled:
            raise AlwaysEnabled
        if policy_acknowledged is not True:
            raise PolicyNotAcknowledged
        if not lst.verified and unverified_confirmed is not True:
            raise UnverifiedNotConfirmed
        repository = DnsblEnablementRepository(self._db)
        try:
            repository.enable(
                lst.id,
                actor=self._principal.user_id,
                policy_acknowledged=True,
                unverified_confirmed=not lst.verified,
                now=self._clock(),
            )
        except EnablementConflict:
            self._db.rollback()  # a concurrent enable of the same list won: it is enabled
        else:
            self._db.commit()
            self._audit("enabled", lst.id)
        return self._view(lst)

    def disable(self, list_id: object) -> DnsblListView:
        lst = self.find(list_id)
        if lst.default_enabled:
            raise AlwaysEnabled
        removed = DnsblEnablementRepository(self._db).disable(lst.id)
        self._db.commit()
        if removed:
            self._audit("disabled", lst.id)
        return self._view(lst)
