"""Tenant-scoped repository for domain ESP assignments (M6-02). The only access path to
`domain_esps`.

Same rules as `DomainAccessRepository` (no `TenantScopedRepository` base: its generic
`add(obj)` / `update(id, values)` would bypass the validation and the cap below):
- built only with a `TenantContext`; every query is filtered on `tenant_id = ctx.tenant_id` and
  every row is written with the context tenant, never a tenant taken from arguments;
- a domain of another tenant behaves exactly like a missing or malformed one (None / False /
  empty), with no exception that reveals it exists;
- the composite FK (domain_id, tenant_id) -> domains(id, tenant_id) makes a cross-tenant row
  impossible in the database too, and an attribute listener refuses moving a persisted row to
  another tenant.

Validation before the database (identical outcome on SQLite and PostgreSQL), raising
`DomainEspInvalid` with the field and a stable reason, never the value:
- `esp_id`: the ESP profile slug `[a-z0-9][a-z0-9-]{0,39}` (same as the M6-01 profile id). Whether
  a profile with that id exists is the service's concern: profiles live in YAML, not here.
- `return_path_host` / `tracking_host`: optional; ASCII only (an IDN U-label is rejected, its
  A-label is accepted), then normalised by `app.core.domain_names.to_ascii_domain` (surrounding
  whitespace trimmed, lowercase, one trailing dot removed, NUL/control characters, IPs,
  single labels and over-long names rejected), and it must equal the domain name or end with
  `.<domain name>`.

At most `MAX_ESPS_PER_DOMAIN` assignments per domain (`DomainEspLimitReached`). The cap is checked
by a count before the insert, so two concurrent adds could exceed it by one; a concurrent add of
the same (domain, esp) surfaces as an IntegrityError from the flush (session must roll back).

Callers get immutable `DomainEspRecord`s, never ORM objects. When a domain is renamed the service
calls `rewrite_host_suffix` in the same transaction: a host equal to the old name becomes the new
name and `<label>.<old>` becomes `<label>.<new>`. A stored host that does not satisfy the rule for
the old name (legacy data), or whose rewrite would not be a valid host, is left untouched and
counted as `unmatched`, so the caller can report it.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import ColumnElement, Select, func, select
from sqlalchemy.orm import Session

from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.core.tenancy import TenantContext
from app.models import Domain, DomainEsp
from app.models.domain_esp import MAX_ESP_ID_LENGTH
from app.repositories.base import MAX_LIMIT, _install_tenant_guard, coerce_id

MAX_ESPS_PER_DOMAIN: Final = 10
# Same slug as the M6-01 ESP profile id; keep the two in step.
ESP_ID_PATTERN: Final = re.compile(rf"[a-z0-9][a-z0-9-]{{0,{MAX_ESP_ID_LENGTH - 1}}}")

_install_tenant_guard(DomainEsp.tenant_id)


class DomainEspInvalid(ValueError):
    """A value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"domain esp {field} rejected: {reason}")
        self.field = field
        self.reason = reason


class DomainEspLimitReached(Exception):
    """The domain already has MAX_ESPS_PER_DOMAIN ESP assignments."""


@dataclass(frozen=True, slots=True)
class DomainEspRecord:
    id: int
    domain_id: int
    esp_id: str
    return_path_host: str | None
    tracking_host: str | None
    created_at: datetime

    @classmethod
    def from_model(cls, row: DomainEsp) -> DomainEspRecord:
        return cls(
            id=row.id,
            domain_id=row.domain_id,
            esp_id=row.esp_id,
            return_path_host=row.return_path_host,
            tracking_host=row.tracking_host,
            created_at=row.created_at,
        )


def validate_esp_id(value: object) -> str:
    """The ESP profile slug, unchanged; DomainEspInvalid if it is not one."""
    if not isinstance(value, str):
        raise DomainEspInvalid("esp_id", "not_a_string")
    if not ESP_ID_PATTERN.fullmatch(value):
        raise DomainEspInvalid("esp_id", "format")
    return value


def normalize_host(field: str, value: object, domain_name: str) -> str | None:
    """The normalised host name for `field` of a domain called `domain_name` (None stays None)."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise DomainEspInvalid(field, "not_a_string")
    if not value.isascii():
        raise DomainEspInvalid(field, "not_ascii")
    try:
        host = to_ascii_domain(value)
    except InvalidDomainName as exc:
        raise DomainEspInvalid(field, exc.reason) from None
    if host != domain_name and not host.endswith("." + domain_name):
        raise DomainEspInvalid(field, "not_in_domain")
    return host


@dataclass(frozen=True, slots=True)
class HostRewrite:
    """Outcome of `rewrite_host_suffix`: host values rewritten, and host values left untouched
    because they were not under the old name (or the rewrite was not a valid host)."""

    rewritten: int = 0
    unmatched: int = 0


class DomainEspRepository:
    """ESP assignments of the context tenant's domains."""

    __slots__ = ("_ctx", "_session")

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        self._ctx = ctx
        self._session = session

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def _select(self, *criteria: ColumnElement[bool]) -> Select[DomainEsp]:
        return select(DomainEsp).where(DomainEsp.tenant_id == self._ctx.tenant_id, *criteria)

    def _domain_name(self, domain_id: int) -> str | None:
        stmt = select(Domain.name).where(
            Domain.id == domain_id, Domain.tenant_id == self._ctx.tenant_id
        )
        return self._session.scalar(stmt)

    def _get(self, domain_id: int, esp_id: str) -> DomainEsp | None:
        stmt = self._select(DomainEsp.domain_id == domain_id, DomainEsp.esp_id == esp_id)
        return self._session.scalars(stmt).one_or_none()

    def _count(self, domain_id: int) -> int:
        stmt = select(func.count()).where(
            DomainEsp.tenant_id == self._ctx.tenant_id, DomainEsp.domain_id == domain_id
        )
        return int(self._session.scalar(stmt) or 0)

    # --- reads ------------------------------------------------------------------------------

    def list_for_domain(self, domain_id: object) -> Sequence[DomainEspRecord]:
        """Assignments of the domain ordered by esp_id (empty if missing/foreign/malformed)."""
        did = coerce_id(domain_id)
        if did is None:
            return []
        stmt = self._select(DomainEsp.domain_id == did).order_by(DomainEsp.esp_id)
        return [DomainEspRecord.from_model(row) for row in self._session.scalars(stmt)]

    def list_for_domains(
        self, domain_ids: Collection[object]
    ) -> Mapping[int, Sequence[DomainEspRecord]]:
        """Assignments per domain id, each ordered by esp_id. Only domains of the context tenant
        with at least one assignment appear; malformed and foreign ids are ignored. At most
        MAX_LIMIT ids per call (ValueError beyond it)."""
        if len(domain_ids) > MAX_LIMIT:
            raise ValueError(f"at most {MAX_LIMIT} domain ids per call")
        wanted = {did for did in (coerce_id(d) for d in domain_ids) if did is not None}
        if not wanted:
            return {}
        stmt = self._select(DomainEsp.domain_id.in_(sorted(wanted))).order_by(
            DomainEsp.domain_id, DomainEsp.esp_id
        )
        result: dict[int, list[DomainEspRecord]] = {}
        for row in self._session.scalars(stmt):
            result.setdefault(row.domain_id, []).append(DomainEspRecord.from_model(row))
        return result

    # --- writes -----------------------------------------------------------------------------

    def add(
        self,
        domain_id: object,
        esp_id: object,
        *,
        return_path_host: object = None,
        tracking_host: object = None,
    ) -> DomainEspRecord | None:
        """Assign the ESP to the domain. Idempotent: if the pair exists, the existing row is
        returned unchanged (use `update_hosts` to change its hosts). None (nothing written) if
        the domain is missing, foreign or malformed. DomainEspInvalid for a bad esp_id or host,
        DomainEspLimitReached if the domain already has MAX_ESPS_PER_DOMAIN assignments."""
        esp = validate_esp_id(esp_id)
        did = coerce_id(domain_id)
        if did is None:
            return None
        name = self._domain_name(did)
        if name is None:
            return None
        rp_host = normalize_host("return_path_host", return_path_host, name)
        tr_host = normalize_host("tracking_host", tracking_host, name)
        existing = self._get(did, esp)
        if existing is not None:
            return DomainEspRecord.from_model(existing)
        if self._count(did) >= MAX_ESPS_PER_DOMAIN:
            raise DomainEspLimitReached
        row = DomainEsp(
            tenant_id=self._ctx.tenant_id,
            domain_id=did,
            esp_id=esp,
            return_path_host=rp_host,
            tracking_host=tr_host,
        )
        self._session.add(row)
        self._session.flush()
        self._session.refresh(row)
        return DomainEspRecord.from_model(row)

    def update_hosts(
        self,
        domain_id: object,
        esp_id: object,
        *,
        return_path_host: object,
        tracking_host: object,
    ) -> DomainEspRecord | None:
        """Set both hosts of the assignment (None clears one). None (nothing changes) if the
        domain or the assignment is missing, foreign or malformed; DomainEspInvalid for a bad
        esp_id or host."""
        esp = validate_esp_id(esp_id)
        did = coerce_id(domain_id)
        if did is None:
            return None
        name = self._domain_name(did)
        if name is None:
            return None
        rp_host = normalize_host("return_path_host", return_path_host, name)
        tr_host = normalize_host("tracking_host", tracking_host, name)
        row = self._get(did, esp)
        if row is None:
            return None
        row.return_path_host = rp_host
        row.tracking_host = tr_host
        self._session.flush()
        return DomainEspRecord.from_model(row)

    def rewrite_host_suffix(self, domain_id: object, old_name: str, new_name: str) -> HostRewrite:
        """Move every host of the domain's assignments from `old_name` to `new_name` (both
        normalised ASCII names): the old name itself becomes the new name, `<label>.<old>`
        becomes `<label>.<new>`. Does not commit. Nothing happens for a missing, foreign or
        malformed domain or an unchanged name. Hosts outside the old name are untouched and
        counted in `unmatched`."""
        did = coerce_id(domain_id)
        if did is None or old_name == new_name or self._domain_name(did) is None:
            return HostRewrite()
        rewritten = unmatched = 0
        for row in self._session.scalars(self._select(DomainEsp.domain_id == did)):
            for field in ("return_path_host", "tracking_host"):
                host = getattr(row, field)
                if host is None:
                    continue
                if host == old_name:
                    candidate = new_name
                elif host.endswith("." + old_name):
                    candidate = host[: -len(old_name)] + new_name
                else:
                    unmatched += 1
                    continue
                try:
                    setattr(row, field, normalize_host(field, candidate, new_name))
                except DomainEspInvalid:
                    unmatched += 1
                else:
                    rewritten += 1
        self._session.flush()
        return HostRewrite(rewritten, unmatched)

    def remove(self, domain_id: object, esp_id: object) -> bool:
        """Remove the assignment. False if there was no such row in the context tenant (a
        malformed esp_id is simply not found)."""
        did = coerce_id(domain_id)
        if did is None or not isinstance(esp_id, str) or not ESP_ID_PATTERN.fullmatch(esp_id):
            return False
        row = self._get(did, esp_id)
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True
