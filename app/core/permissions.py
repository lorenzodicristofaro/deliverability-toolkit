"""Permission layer: `can(principal, action, resource)` (ARCHITECTURE section 4 item 3).

Pure: no DB session, no I/O, no tenant models. The caller loads the user, their memberships and
domain access and builds a `Principal` (see `app.repositories.principal_from_models`); web, API
and CLI all call `can`/`require`.

Rules (SPEC section 3, ARCHITECTURE section 4 items 3 and 6):
- Deny by default: unknown action, unknown role, wrong resource kind, malformed input -> False.
- Inactive users are denied everything.
- Tenant-scoped resources are allowed only when their `tenant_id` equals the principal's active
  tenant and the principal holds a membership there; any other tenant is denied for every role.
- The instance admin flag grants only `INSTANCE_ADMIN_ACTIONS` on instance-level resources
  (`InstanceResource`, and `RuleScopeResource` with scope `global`). It adds nothing inside a
  tenant: there the membership role and domain access decide, like for anyone else (maintainer
  decision 2026-11-04). This rule lives only in `_instance_flag_allows`.
- Client viewers read only domains assigned through DomainAccess.
- Role matrix (tenant-level / domain-level actions beyond the domain CRUD set):
    owner, admin, analyst: dns.tools, check.run, message.analyze, content.analyze, rules.read
    owner, admin:          rules.manage (scope `tenant`, own active tenant only)
    client_viewer:         check.run (assigned domains only); never dns.tools, message.analyze,
                           content.analyze, rules.read or rules.manage
    instance admin flag:   instance.manage, rules.manage (scope `global` only), whatever the
                           tenant role (or none)
- Per-user feature toggles can only deny: a toggle keyed by the action value that is not exactly
  `True` denies that action; toggles never grant anything.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from app.models.membership import MembershipRole


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
    # Raw DNS tools (lookup, reverse, trace, propagation). Tenant-level: needs an active
    # membership; never granted to client viewers (SPEC section 3; GM decision 2026-11-05).
    DNS_TOOLS = "dns.tools"
    # Run the deliverability checks against one tenant domain (M3-14). Domain-level: client
    # viewers only on assigned domains (`_domain_allowed`); deniable per user with the toggle
    # `{"check.run": false}`. Free (tenant-less) checks use DNS_TOOLS instead.
    CHECK_RUN = "check.run"
    # Offline analysis of a pasted message (headers/body) (M4-06). A dedicated action because
    # none fits: `dns.tools` means raw DNS queries and toggles are keyed by action value, so
    # `{"dns.tools": false}` would also silently switch off this offline parser; `check.run` is
    # domain-level (needs a DomainResource and a registered domain) while a pasted message has
    # no domain, so reusing it would force a fake domain id. The analyzer touches no tenant data
    # but processes user-supplied content and costs CPU: it needs an active membership (no
    # anonymous use), is tenant-level, deniable per user with `{"message.analyze": false}`, and
    # like dns.tools is never granted to client viewers.
    MESSAGE_ANALYZE = "message.analyze"
    # Offline content analysis of a pasted body (M5-04). Separate from message.analyze so each
    # feature has its own deny toggle (`{"content.analyze": false}` must not switch off the
    # header analyzer, and vice versa). Same shape as message.analyze: tenant-level, needs an
    # active membership, owner/admin/analyst only, never client viewers, deniable per user.
    CONTENT_ANALYZE = "content.analyze"
    # Read the rules usable in the active tenant (global rules + that tenant's own rules: content
    # rules, DKIM selectors, custom checks). Tenant-level: owner/admin/analyst of the active
    # tenant; client viewers never see rule configuration. The caller filters to global + own
    # tenant rows; the instance admin flag adds nothing here (it reads global rules through
    # rules.manage on the global scope, see below).
    RULES_READ = "rules.read"
    # Create/update/delete rules (content rules, DKIM selectors, custom checks): one managing
    # permission, the scope on `RuleScopeResource` decides who. Scope `global` affects every
    # tenant, so only the instance admin flag grants it, regardless of any tenant role (a tenant
    # owner must not edit what other tenants run). Scope `tenant` is tenant data: owner/admin of
    # that same, active tenant, deniable per user with `{"rules.manage": false}`; the instance
    # admin flag adds nothing there (maintainer decision 2026-11-04 applies unchanged).
    RULES_MANAGE = "rules.manage"


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


class RuleScope(enum.StrEnum):
    GLOBAL = "global"
    TENANT = "tenant"


@dataclass(frozen=True, slots=True)
class RuleScopeResource:
    """The rule set of one scope. `global`: `tenant_id` must be None (instance-level). `tenant`:
    `tenant_id` must be a tenant id (tenant-level). Any other combination is malformed and
    denied."""

    scope: RuleScope
    tenant_id: int | None = None


Resource = InstanceResource | TenantResource | DomainResource | RuleScopeResource

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
        Action.DNS_TOOLS: TenantResource,
        Action.CHECK_RUN: DomainResource,
        Action.MESSAGE_ANALYZE: TenantResource,
        Action.CONTENT_ANALYZE: TenantResource,
        Action.RULES_READ: TenantResource,
        Action.RULES_MANAGE: RuleScopeResource,
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
            {
                Action.TENANT_READ,
                Action.TENANT_MANAGE,
                Action.USER_MANAGE,
                Action.DNS_TOOLS,
                Action.CHECK_RUN,
                Action.MESSAGE_ANALYZE,
                Action.CONTENT_ANALYZE,
                Action.RULES_READ,
                Action.RULES_MANAGE,  # tenant scope only; global goes through the instance flag
            }
        )
        | _DOMAIN_ALL,
        # Domains and inviting users; not owner settings.
        MembershipRole.ADMIN: frozenset(
            {
                Action.TENANT_READ,
                Action.USER_MANAGE,
                Action.DNS_TOOLS,
                Action.CHECK_RUN,
                Action.MESSAGE_ANALYZE,
                Action.CONTENT_ANALYZE,
                Action.RULES_READ,
                Action.RULES_MANAGE,  # tenant scope only; global goes through the instance flag
            }
        )
        | _DOMAIN_ALL,
        # Sees all domains, runs checks, uses the raw DNS tools and the message/content
        # analyzers, reads rules; no user/integration/rule management, no domain changes.
        MembershipRole.ANALYST: frozenset(
            {
                Action.TENANT_READ,
                Action.DOMAIN_LIST,
                Action.DOMAIN_READ,
                Action.DNS_TOOLS,
                Action.CHECK_RUN,
                Action.MESSAGE_ANALYZE,
                Action.CONTENT_ANALYZE,
                Action.RULES_READ,
            }
        ),
        # Read-only, assigned domains only (enforced in `_domain_allowed`). Runs checks on those
        # domains (M3 has no persistence: viewing the Authentication tab IS running the check).
        # No raw DNS tools, no message/content analyzer, no rules: not in this set, so no toggle
        # or DomainAccess grant can give them.
        MembershipRole.CLIENT_VIEWER: frozenset(
            {Action.TENANT_READ, Action.DOMAIN_LIST, Action.DOMAIN_READ, Action.CHECK_RUN}
        ),
    }
)

# Roles whose domain access is restricted to DomainAccess rows.
_DOMAIN_RESTRICTED_ROLES = frozenset({MembershipRole.CLIENT_VIEWER})


def is_domain_restricted(role: object) -> bool:
    """True if `role` sees only the domains assigned to it through DomainAccess. The single
    source is `_DOMAIN_RESTRICTED_ROLES`; callers (e.g. request dependencies loading grants) ask
    here instead of naming a role. An unknown or malformed role counts as restricted (fail
    closed: loading grants never widens access, `can` still denies the unknown role)."""
    known = _coerce_role(role)
    return known is None or known in _DOMAIN_RESTRICTED_ROLES


# The only actions the instance admin flag grants (instance-level resources only: InstanceResource
# and the global rule scope).
INSTANCE_ADMIN_ACTIONS = frozenset({Action.INSTANCE_MANAGE, Action.RULES_MANAGE})


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
    if isinstance(resource, RuleScopeResource):
        scope = _coerce_scope(resource.scope)
        if scope is RuleScope.GLOBAL:
            return resource.tenant_id is None
        if scope is RuleScope.TENANT:
            return _is_id(resource.tenant_id)
    return False


def _coerce_scope(scope: object) -> RuleScope | None:
    # Exact values only: "Global", " global" or "" are malformed, not a guess.
    if isinstance(scope, RuleScope):
        return scope
    if isinstance(scope, str):
        try:
            return RuleScope(scope)
        except ValueError:
            return None
    return None


def _is_instance_level(resource: object) -> bool:
    return isinstance(resource, InstanceResource) or (
        isinstance(resource, RuleScopeResource)
        and _coerce_scope(resource.scope) is RuleScope.GLOBAL
    )


def _instance_flag_allows(principal: Principal, action: Action) -> bool:
    """The single place deciding what the instance admin flag grants. Today: only instance-level
    actions, never tenant data (GM Q4b / maintainer decision 2026-11-04). Instance-level
    resources belong to no tenant, so no membership is needed and per-membership feature toggles
    do not apply here (a toggle in whichever tenant happens to be active must not decide a global
    permission)."""
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
    if not isinstance(ids, frozenset | set):
        return False
    # Compare only well-formed ids: True == 1 must not match domain 1.
    return any(_is_id(d) and d == domain_id for d in ids)


def can(principal: object, action: object, resource: object) -> bool:
    """True only if `principal` may perform `action` on `resource`; False otherwise."""
    if not isinstance(principal, Principal) or principal.is_active is not True:
        return False
    act = _coerce_action(action)
    if act is None or not _resource_well_formed(resource):
        return False
    if not isinstance(resource, _RESOURCE_KIND[act]):
        return False

    if _is_instance_level(resource):
        return _instance_flag_allows(principal, act)

    assert isinstance(resource, TenantResource | DomainResource | RuleScopeResource)
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
