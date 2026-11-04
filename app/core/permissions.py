"""Permission layer: `can(principal, action, resource)` (ARCHITECTURE section 4 item 3).

Pure: no DB session, no I/O. The caller loads the user, their memberships and domain access and
builds a `Principal` (see `principal_from_models`); web, API and CLI all call `can`/`require`.

Rules (SPEC section 3, ARCHITECTURE section 4 items 3 and 6):
- Deny by default: unknown action, unknown role, wrong resource kind, malformed input -> False.
- Inactive users are denied everything.
- Tenant-scoped resources are allowed only when their `tenant_id` equals the principal's active
  tenant and the principal holds a membership there; any other tenant is denied for every role.
- The instance admin flag grants only `INSTANCE_ADMIN_ACTIONS` (instance-level resources). It adds
  nothing inside a tenant: there the membership role and domain access decide, like for anyone
  else (maintainer decision 2026-11-04). This rule lives only in `_instance_flag_allows`.
- Client viewers read only domains assigned through DomainAccess.
- Per-user feature toggles can only deny: a toggle keyed by the action value that is not exactly
  `True` denies that action; toggles never grant anything.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from app.models.membership import MembershipRole

if TYPE_CHECKING:
    from app.models.membership import DomainAccess, Membership
    from app.models.user import User


class Action(enum.StrEnum):
    TENANT_READ = "tenant.read"
    TENANT_MANAGE = "tenant.manage"
    USER_MANAGE = "user.manage"
    DOMAIN_LIST = "domain.list"
    DOMAIN_READ = "domain.read"
    DOMAIN_CREATE = "domain.create"
    DOMAIN_UPDATE = "domain.update"
    DOMAIN_DELETE = "domain.delete"
    INSTANCE_MANAGE = "instance.manage"


# --- Resources -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InstanceResource:
    """The instance itself (instance settings, tenant lifecycle, global knowledge)."""


@dataclass(frozen=True, slots=True)
class TenantResource:
    tenant_id: int


@dataclass(frozen=True, slots=True)
class DomainResource:
    tenant_id: int
    domain_id: int


Resource = InstanceResource | TenantResource | DomainResource

# Which resource kind each action applies to; any other kind is denied.
_RESOURCE_KIND: Mapping[Action, type[Resource]] = MappingProxyType(
    {
        Action.INSTANCE_MANAGE: InstanceResource,
        Action.TENANT_READ: TenantResource,
        Action.TENANT_MANAGE: TenantResource,
        Action.USER_MANAGE: TenantResource,
        Action.DOMAIN_LIST: TenantResource,
        Action.DOMAIN_CREATE: TenantResource,
        Action.DOMAIN_READ: DomainResource,
        Action.DOMAIN_UPDATE: DomainResource,
        Action.DOMAIN_DELETE: DomainResource,
    }
)

# --- Role matrix (SPEC section 3) ------------------------------------------------------------

_DOMAIN_ALL = frozenset(
    {
        Action.DOMAIN_LIST,
        Action.DOMAIN_READ,
        Action.DOMAIN_CREATE,
        Action.DOMAIN_UPDATE,
        Action.DOMAIN_DELETE,
    }
)

ROLE_ACTIONS: Mapping[MembershipRole, frozenset[Action]] = MappingProxyType(
    {
        # Everything inside the tenant, including billing-like owner settings.
        MembershipRole.OWNER: frozenset(
            {Action.TENANT_READ, Action.TENANT_MANAGE, Action.USER_MANAGE}
        )
        | _DOMAIN_ALL,
        # Domains and inviting users; not owner settings.
        MembershipRole.ADMIN: frozenset({Action.TENANT_READ, Action.USER_MANAGE}) | _DOMAIN_ALL,
        # Sees all domains; no user/integration management, no domain changes.
        MembershipRole.ANALYST: frozenset(
            {Action.TENANT_READ, Action.DOMAIN_LIST, Action.DOMAIN_READ}
        ),
        # Read-only, assigned domains only (enforced in `_domain_allowed`).
        MembershipRole.CLIENT_VIEWER: frozenset(
            {Action.TENANT_READ, Action.DOMAIN_LIST, Action.DOMAIN_READ}
        ),
    }
)

# Roles whose domain access is restricted to DomainAccess rows.
_DOMAIN_RESTRICTED_ROLES = frozenset({MembershipRole.CLIENT_VIEWER})

# The only actions the instance admin flag grants (instance-level resources only).
INSTANCE_ADMIN_ACTIONS = frozenset({Action.INSTANCE_MANAGE})


# --- Principal -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MembershipGrant:
    """One membership as loaded by the caller. `domain_ids` are the DomainAccess rows of this
    membership (used only for domain-restricted roles)."""

    tenant_id: int
    role: MembershipRole
    domain_ids: frozenset[int] = frozenset()
    feature_toggles: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: int
    is_active: bool
    is_instance_admin: bool = False
    active_tenant_id: int | None = None
    memberships: tuple[MembershipGrant, ...] = ()


def principal_from_models(
    user: User,
    memberships: Iterable[Membership],
    domain_access: Iterable[DomainAccess],
    active_tenant_id: int | None,
) -> Principal:
    """Build a Principal from already-loaded ORM rows (no queries). Memberships of other users
    and DomainAccess rows whose tenant does not match their membership are ignored."""
    own = [m for m in memberships if m.user_id == user.id]
    tenant_of = {m.id: m.tenant_id for m in own}
    domains: dict[int, set[int]] = {m.id: set() for m in own}
    for da in domain_access:
        if tenant_of.get(da.membership_id) == da.tenant_id:
            domains[da.membership_id].add(da.domain_id)
    grants = tuple(
        MembershipGrant(
            tenant_id=m.tenant_id,
            role=m.role,
            domain_ids=frozenset(domains[m.id]),
            feature_toggles=MappingProxyType(dict(m.feature_toggles or {})),
        )
        for m in own
    )
    return Principal(
        user_id=user.id,
        is_active=user.is_active,
        is_instance_admin=user.is_instance_admin,
        active_tenant_id=active_tenant_id,
        memberships=grants,
    )


# --- Errors ----------------------------------------------------------------------------------


class PermissionDenied(Exception):
    """Raised by `require`. `code` is a stable machine code; user-facing text is the caller's
    job (i18n). Callers map this to 404 for cross-tenant resources (ARCHITECTURE section 4)."""

    code = "permission_denied"

    def __init__(self, action: object, resource: object) -> None:
        super().__init__(f"{self.code}: {action!r} on {resource!r}")
        self.action = action
        self.resource = resource


# --- Evaluation ------------------------------------------------------------------------------


def _is_id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _coerce_action(action: object) -> Action | None:
    if isinstance(action, Action):
        return action
    if isinstance(action, str):
        try:
            return Action(action)
        except ValueError:
            return None
    return None


def _coerce_role(role: object) -> MembershipRole | None:
    if isinstance(role, MembershipRole):
        return role
    if isinstance(role, str):
        try:
            return MembershipRole(role)
        except ValueError:
            return None
    return None


def _resource_well_formed(resource: object) -> bool:
    if isinstance(resource, InstanceResource):
        return True
    if isinstance(resource, TenantResource):
        return _is_id(resource.tenant_id)
    if isinstance(resource, DomainResource):
        return _is_id(resource.tenant_id) and _is_id(resource.domain_id)
    return False


def _instance_flag_allows(principal: Principal, action: Action) -> bool:
    """The single place deciding what the instance admin flag grants. Today: only instance-level
    actions, never tenant data (GM Q4b / maintainer decision 2026-11-04)."""
    return principal.is_instance_admin is True and action in INSTANCE_ADMIN_ACTIONS


def _active_membership(principal: Principal) -> MembershipGrant | None:
    tenant_id = principal.active_tenant_id
    if not _is_id(tenant_id) or not isinstance(principal.memberships, tuple):
        return None
    matches = [
        m
        for m in principal.memberships
        if isinstance(m, MembershipGrant) and _is_id(m.tenant_id) and m.tenant_id == tenant_id
    ]
    # Zero or ambiguous (duplicate memberships for one tenant): deny.
    return matches[0] if len(matches) == 1 else None


def _toggle_denies(grant: MembershipGrant, action: Action) -> bool:
    toggles = grant.feature_toggles
    if not isinstance(toggles, Mapping):
        return True
    return action.value in toggles and toggles[action.value] is not True


def _domain_allowed(grant: MembershipGrant, role: MembershipRole, domain_id: int) -> bool:
    if role not in _DOMAIN_RESTRICTED_ROLES:
        return True
    ids = grant.domain_ids
    return isinstance(ids, frozenset | set) and domain_id in ids


def can(principal: object, action: object, resource: object) -> bool:
    """True only if `principal` may perform `action` on `resource`; False otherwise."""
    if not isinstance(principal, Principal) or principal.is_active is not True:
        return False
    act = _coerce_action(action)
    if act is None or not _resource_well_formed(resource):
        return False
    if not isinstance(resource, _RESOURCE_KIND[act]):
        return False

    if isinstance(resource, InstanceResource):
        return _instance_flag_allows(principal, act)

    assert isinstance(resource, TenantResource | DomainResource)
    grant = _active_membership(principal)
    if grant is None or resource.tenant_id != grant.tenant_id:
        return False
    role = _coerce_role(grant.role)
    if role is None or act not in ROLE_ACTIONS.get(role, frozenset()):
        return False
    if _toggle_denies(grant, act):
        return False
    if isinstance(resource, DomainResource):
        return _domain_allowed(grant, role, resource.domain_id)
    return True


def require(principal: object, action: object, resource: object) -> None:
    """Raise `PermissionDenied` unless `can(principal, action, resource)`."""
    if not can(principal, action, resource):
        raise PermissionDenied(action, resource)
