"""ESP assignments of a domain, and the ESP profile catalogue (M6-03).

Authorization reuses the domain actions, decided with `can()` before any repository is built:
- catalogue: `domain.list` on the active tenant (public profile data, no tenant content);
- read (list a domain's assignments): `domain.read` on the domain;
- write (assign, change hosts, remove): `domain.read` and `domain.update` on the domain.
This is the read rule of the other domain data (as the DKIM providers of M5-23b): whoever may read
the domain reads its ESP assignments, so a client viewer reads them, read-only, on the domains
assigned to it (maintainer decision 2026-11-10, M6-06c); it never has `domain.update`. Per-user
toggles keyed by those actions deny as elsewhere. No new action.

Outcomes (every error carries an i18n key, never user input or another tenant's data):
- no active tenant, a malformed id, a domain the principal may not read (unassigned for a viewer,
  `domain.read` toggled off) or that is missing or of another tenant: `EspNotFound` (404). The
  `can()` answers are computed first; a write denial is raised only after the domain was found, so
  a missing or foreign domain answers 404 to every role, as on the other domain routes. A client
  viewer is the exception that needs no lookup: its `domain.read` comes from its own assignment
  of that domain, so its write denial (403) is raised before any repository and reveals nothing
  beyond that assignment;
- a reader without `domain.update` on a write: 403;
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

Profiles that cannot be loaded (`KnowledgeError`, of which `EspProfileError` is a subclass; the
loader caches only successful loads, so every call retries) are logged as a warning and answer
`EspProfilesUnavailable` (503, `api.domain_esps.error.profiles_unavailable`) on the routes that
need them: the catalogue, the list (profile names) and assign. Remove needs no profile.

Domain runs (M6-06): `resolve_esp_run` builds the `esp` check of one domain run from the
domain's assignments, read through the tenant repository with the caller's `TenantContext`, and
the loaded profiles. Profiles are loaded only when the domain has an assignment, so a run of a
domain without ESPs never depends on them. Every role that may run checks on the domain gets the
full result, client viewers included (M6-06c). Outcomes:
- no assignment: `EspProfileCheck` with no profile (the M6-04 `ESP_NONE_ASSIGNED` info result),
  `assigned` False (not part of `all`);
- the repository fails (SQLAlchemyError) or the profiles cannot be loaded: a check that returns
  `error` with `CHECK_INTERNAL_ERROR` (not evaluated), `assigned` True so `all` shows it; the
  other checks of the run are unaffected;
- an assigned profile id that is no longer loaded (file removed or renamed): the loaded ones are
  evaluated, and each missing one adds `ESP_PROFILE_UNAVAILABLE` (param `esp`: the stored id) and
  is listed in `data["unavailable"]`; the result is `error`, never `ok`.
`esp` cannot collide with a custom check: those are registered as `custom:<scope>:<key>`.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.checks.esp_profile import EspHosts, EspProfileCheck
from app.checks.models import Check, CheckContext, CheckResult, Finding, Target, finding
from app.core.permissions import (
    Action,
    DomainResource,
    Principal,
    TenantResource,
    can,
    is_domain_restricted,
)
from app.core.tenancy import TenantContext
from app.dns.knowledge import KnowledgeError
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
PROFILES_UNAVAILABLE_KEY: Final = "api.domain_esps.error.profiles_unavailable"

ESP_CHECK_ID: Final = EspProfileCheck.id
# Finding codes added by the domain-run wiring (title/detail/remediation keys in en and it).
CODES: tuple[str, ...] = ("ESP_PROFILE_UNAVAILABLE",)

ProfileSource = Callable[[], Sequence[EspProfile]]


def _reads_by_assignment(principal: Principal, tenant_id: int) -> bool:
    """True when the principal's only membership in the tenant is domain-restricted (a client
    viewer): `domain.read` then comes from its own assignment of the domain. Anything else
    (no or several memberships) is False, which only costs a domain lookup."""
    grants = [m for m in principal.memberships if m.tenant_id == tenant_id]
    return len(grants) == 1 and is_domain_restricted(grants[0].role)


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


class EspProfilesUnavailable(DomainEspError):
    """The ESP profiles could not be loaded (broken profile directory)."""

    status = 503
    key = PROFILES_UNAVAILABLE_KEY


def load_profiles(source: ProfileSource) -> Sequence[EspProfile]:
    """The profiles of `source`; a load failure is logged and raised as EspProfilesUnavailable."""
    try:
        return source()
    except KnowledgeError:
        logger.warning(
            "esp profiles unreadable", extra={"event": "domain_esps.profiles_unreadable"}
        )
        raise EspProfilesUnavailable from None


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

    def check_catalogue(self) -> None:
        tenant_id = self._tenant_id()
        if not can(self._principal, Action.DOMAIN_LIST, TenantResource(tenant_id)):
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
        writable = can(self._principal, Action.DOMAIN_UPDATE, resource) if write else False
        if write and not writable and _reads_by_assignment(self._principal, tenant_id):
            raise EspForbidden
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
            for profile in load_profiles(self._profiles):
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
        return tuple(sorted(load_profiles(self._profiles), key=lambda p: p.id))

    def profile_names(self) -> dict[str, str]:
        """Profile id -> display name, for the list response. No permission of its own."""
        return {p.id: p.name for p in load_profiles(self._profiles)}

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


# --- domain runs (M6-06) ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EspRun:
    """The `esp` check of one domain run; `assigned` False means it stays out of `all`."""

    check: Check
    assigned: bool


class _UnavailableEspCheck:
    """The assignments or the profiles could not be loaded: `error`, never `ok`."""

    id = ESP_CHECK_ID

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=[finding("CHECK_INTERNAL_ERROR", "medium", remediation=False)],
            evaluated=False,
            started_at=ctx.clock(),
            duration_ms=0,
            data={"esps": []},
        )


class _AssignedEspCheck:
    """`EspProfileCheck` on the loaded profiles; profile ids no longer loaded make it `error`."""

    id = ESP_CHECK_ID

    def __init__(
        self,
        profiles: Sequence[EspProfile],
        hosts: dict[str, EspHosts],
        missing: Sequence[str],
    ) -> None:
        self._check = EspProfileCheck(profiles, hosts) if profiles else None
        self._missing = tuple(missing)

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        if self._check is not None:
            result = await self._check.run(ctx, target)
            if not self._missing:
                return result
            findings: list[Finding] = list(result.findings)
            data = dict(result.data)
            started, duration = result.started_at, result.duration_ms
        else:
            findings, data = [], {"esps": []}
            started, duration = ctx.clock(), 0
        findings.extend(
            finding("ESP_PROFILE_UNAVAILABLE", "low", {"esp": esp_id}) for esp_id in self._missing
        )
        data["unavailable"] = list(self._missing)
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=findings,
            evaluated=False,
            started_at=started,
            duration_ms=duration,
            data=data,
        )


def resolve_esp_run(
    ctx: TenantContext,
    db: Session,
    domain_id: int,
    profiles: ProfileSource = load_esp_profiles,
) -> EspRun:
    """The `esp` check of a run on `domain_id` (already authorized by the caller). Reads only
    through the tenant repository of `ctx`; never raises for a repository or profile failure.

    A repository failure is caught but not rolled back here: after a failed statement a
    PostgreSQL transaction is aborted, so the caller must roll back `db` before using it again
    (the checks API does, in `finally`, and reads the assignments last)."""
    try:
        records = repo_for(ctx, db).domain_esps.list_for_domain(domain_id)
    except SQLAlchemyError:
        logger.warning(
            "esp assignments unreadable", extra={"event": "domain_esps.assignments_unreadable"}
        )
        return EspRun(_UnavailableEspCheck(), assigned=True)
    if not records:
        return EspRun(EspProfileCheck(()), assigned=False)
    try:
        by_id = {p.id: p for p in load_profiles(profiles)}
    except EspProfilesUnavailable:
        return EspRun(_UnavailableEspCheck(), assigned=True)
    # Records are unique per (domain, esp_id), so `known` has no duplicate and every host entry
    # names a profile in it: EspProfileCheck's ValueError cases cannot occur.
    known = [by_id[r.esp_id] for r in records if r.esp_id in by_id]
    hosts = {
        r.esp_id: EspHosts(r.return_path_host, r.tracking_host)
        for r in records
        if r.esp_id in by_id
    }
    missing = sorted(r.esp_id for r in records if r.esp_id not in by_id)
    check = _AssignedEspCheck(known, hosts, missing)
    if missing:
        logger.warning(
            "assigned esp profile not loaded",
            extra={"event": "domain_esps.profile_missing", "domain_id": domain_id},
        )
    return EspRun(check, assigned=True)
