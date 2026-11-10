"""ESP assignments of a domain, and the ESP profile catalogue (M6-03).

Authorization reuses the domain actions, decided with `can()` before any repository is built:
- catalogue: `domain.list` on the active tenant;
- read (list a domain's assignments): `domain.read` on the domain;
- write (assign, change hosts, remove): `domain.read` and `domain.update` on the domain.
Client viewers get none of it, whatever their DomainAccess grants (SPEC section 3, GM decision
2026-11-10): `domain.read` alone would admit them, so a role that `is_domain_restricted` is refused
too. This uses the existing helper of `app.core.permissions` (no new action). Per-user toggles keyed
by those actions deny as elsewhere.

Outcomes (every error carries an i18n key, never user input or another tenant's data):
- no active tenant, a malformed id, a domain the principal may not read (unassigned for a viewer,
  `domain.read` toggled off) or that is missing or of another tenant: `EspNotFound` (404). The
  `can()` answers are computed first; a write denial is raised only after the domain was found, so
  a missing or foreign domain answers 404 to every role, as on the other domain routes;
- a client viewer on a domain it can see, or a reader without `domain.update` on a write: 403;
- `esp_id` that names no loaded profile (`app.esp.profile`): 422 `unknown_esp` on assign. Removing
  does not need a loaded profile, so an assignment whose profile file was removed can be cleaned
  up; a pair that is not assigned is a 404;
- hosts are the repository's rules (`DomainEspInvalid`): 422 `host_outside_domain` or
  `invalid_host` with the field and reason; `MAX_ESPS_PER_DOMAIN` reached: 422 `too_many`.

Assign is a PUT: the stored hosts become exactly the given ones (None clears one). A new pair is
added (`created` True); an existing pair goes through `update_hosts`, never through the idempotent
`add`, which would keep the old hosts. Resending the same values changes nothing and adds no row.
A concurrent add of the same pair surfaces as an IntegrityError at flush: the session is rolled
back and the assign retried once on fresh state (it then finds the row and updates it); a second
failure is a 409, never a 500.

Renaming a domain does not re-check stored hosts (noted in the repository; the renaming ticket
decides what to do with them).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.permissions import (
    Action,
    DomainResource,
    Principal,
    TenantResource,
    can,
    is_domain_restricted,
)
from app.core.tenancy import TenantContext
from app.esp.profile import EspProfile, load_esp_profiles
from app.repositories import repo_for
from app.repositories.base import coerce_id
from app.repositories.domain_esps import (
    DomainEspInvalid,
    DomainEspLimitReached,
    DomainEspRecord,
    DomainEspRepository,
)

logger = logging.getLogger("app.domain_esps")

UNKNOWN_ESP_KEY: Final = "api.domain_esps.error.unknown_esp"
INVALID_HOST_KEY: Final = "api.domain_esps.error.invalid_host"
HOST_OUTSIDE_DOMAIN_KEY: Final = "api.domain_esps.error.host_outside_domain"
TOO_MANY_KEY: Final = "api.domain_esps.error.too_many"
NOT_FOUND_KEY: Final = "api.domain_esps.error.not_found"
FORBIDDEN_KEY: Final = "api.error.forbidden"
CONFLICT_KEY: Final = "api.error.conflict"

ProfileSource = Callable[[], Sequence[EspProfile]]


def field_key(field: str, reason: str) -> str:
    """The i18n key of a rejected field."""
    if field == "esp_id":
        return TOO_MANY_KEY if reason == "too_many" else UNKNOWN_ESP_KEY
    return HOST_OUTSIDE_DOMAIN_KEY if reason == "not_in_domain" else INVALID_HOST_KEY


class DomainEspError(Exception):
    """Base error. `status` is the HTTP status, `key` the i18n key; never carries user input."""

    status = 500
    key = "ui.error.server.detail"


class EspNotFound(DomainEspError):
    status = 404
    key = NOT_FOUND_KEY


class EspForbidden(DomainEspError):
    status = 403
    key = FORBIDDEN_KEY


class EspConflict(DomainEspError):
    status = 409
    key = CONFLICT_KEY


class EspFieldInvalid(DomainEspError):
    """A rejected field: its name and a stable reason code, never its value."""

    status = 422

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason
        self.key = field_key(field, reason)


@dataclass(frozen=True, slots=True)
class AssignResult:
    record: DomainEspRecord
    created: bool


class DomainEspService:
    """One request's ESP operations. `ctx` is None when the session has no active tenant;
    `profiles` returns the loaded ESP profiles (tests pass a fixture directory's)."""

    def __init__(
        self,
        db: Session,
        ctx: TenantContext | None,
        principal: Principal,
        profiles: ProfileSource = load_esp_profiles,
    ) -> None:
        self._db = db
        self._ctx = ctx
        self._principal = principal
        self._profiles = profiles

    # --- authorization (no repository use) -----------------------------------------------------

    def _tenant_id(self) -> int:
        if self._ctx is None:
            raise EspNotFound
        return self._ctx.tenant_id

    def _restricted(self, tenant_id: int) -> bool:
        """True unless the principal holds exactly one membership in the tenant with a role that
        sees every domain (a client viewer is restricted; fail closed)."""
        grants = [m for m in self._principal.memberships if m.tenant_id == tenant_id]
        return len(grants) != 1 or is_domain_restricted(grants[0].role)

    def check_catalogue(self) -> None:
        tenant_id = self._tenant_id()
        if not can(self._principal, Action.DOMAIN_LIST, TenantResource(tenant_id)):
            raise EspForbidden
        if self._restricted(tenant_id):
            raise EspForbidden

    def _authorize(self, domain_id: object, *, write: bool) -> tuple[int, bool]:
        """The domain id and whether a write is allowed; EspNotFound / EspForbidden for what can
        be decided without data."""
        tenant_id = self._tenant_id()
        did = coerce_id(domain_id)
        if did is None:
            raise EspNotFound
        resource = DomainResource(tenant_id, did)
        if not can(self._principal, Action.DOMAIN_READ, resource):
            raise EspNotFound
        if self._restricted(tenant_id):
            raise EspForbidden
        writable = can(self._principal, Action.DOMAIN_UPDATE, resource) if write else False
        return did, writable

    def _existing_domain(self, domain_id: object, *, write: bool) -> int:
        did, writable = self._authorize(domain_id, write=write)
        assert self._ctx is not None  # guaranteed by _authorize
        if repo_for(self._ctx, self._db).domains.get(did) is None:
            raise EspNotFound
        if write and not writable:
            raise EspForbidden
        return did

    def check_read(self, domain_id: object) -> int:
        """Router pre-check: the domain id the caller may read ESP assignments of."""
        return self._existing_domain(domain_id, write=False)

    def check_write(self, domain_id: object) -> int:
        """Router pre-check (before the body is parsed): the domain id the caller may change."""
        return self._existing_domain(domain_id, write=True)

    # --- helpers ------------------------------------------------------------------------------

    def _repo(self) -> DomainEspRepository:
        assert self._ctx is not None  # guaranteed by the permission checks
        return repo_for(self._ctx, self._db).domain_esps

    def _known_esp(self, esp_id: object) -> str:
        if isinstance(esp_id, str):
            for profile in self._profiles():
                if profile.id == esp_id:
                    return profile.id
        raise EspFieldInvalid("esp_id", "unknown")

    def _audit(self, event: str, domain_id: int, esp_id: str) -> None:
        logger.info(
            "domain esp changed",
            extra={
                "event": f"domain_esps.{event}",
                "actor": self._principal.user_id,
                "domain_id": domain_id,
                "esp_id": esp_id,
            },
        )

    # --- reads --------------------------------------------------------------------------------

    def catalogue(self) -> Sequence[EspProfile]:
        self.check_catalogue()
        return tuple(sorted(self._profiles(), key=lambda p: p.id))

    def profile_names(self) -> dict[str, str]:
        """Profile id -> display name, for the list response. No permission of its own."""
        return {p.id: p.name for p in self._profiles()}

    def list_for_domain(self, domain_id: object) -> Sequence[DomainEspRecord]:
        did = self.check_read(domain_id)
        return self._repo().list_for_domain(did)

    # --- writes -------------------------------------------------------------------------------

    def assign(
        self,
        domain_id: object,
        esp_id: object,
        *,
        return_path_host: object = None,
        tracking_host: object = None,
    ) -> AssignResult:
        did = self.check_write(domain_id)
        esp = self._known_esp(esp_id)
        for attempt in (1, 2):
            try:
                result = self._assign_once(did, esp, return_path_host, tracking_host)
            except IntegrityError:
                # A concurrent add of the same pair (or the domain deleted meanwhile).
                self._db.rollback()
                if attempt == 2:
                    raise EspConflict from None
                continue
            except DomainEspInvalid as exc:
                self._db.rollback()
                raise EspFieldInvalid(exc.field, exc.reason) from None
            except DomainEspLimitReached:
                self._db.rollback()
                raise EspFieldInvalid("esp_id", "too_many") from None
            self._audit("created" if result.created else "updated", did, esp)
            return result
        raise EspConflict  # pragma: no cover - the loop always returns or raises

    def _assign_once(
        self, did: int, esp: str, return_path_host: object, tracking_host: object
    ) -> AssignResult:
        repo = self._repo()
        exists = any(r.esp_id == esp for r in repo.list_for_domain(did))
        if exists:
            record = repo.update_hosts(
                did, esp, return_path_host=return_path_host, tracking_host=tracking_host
            )
            created = False
        else:
            record = repo.add(
                did, esp, return_path_host=return_path_host, tracking_host=tracking_host
            )
            created = True
        if record is None:  # the domain or the pair vanished concurrently
            self._db.rollback()
            raise EspNotFound
        self._db.commit()
        return AssignResult(record, created)

    def remove(self, domain_id: object, esp_id: object) -> None:
        did = self.check_write(domain_id)
        if not self._repo().remove(did, esp_id):
            raise EspNotFound
        self._db.commit()
        self._audit("deleted", did, str(esp_id))
