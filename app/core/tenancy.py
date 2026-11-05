"""TenantContext: the immutable "who acts, in which tenant" value every tenant repository needs.

It is built once per request/job after authentication and membership resolution (M1-11/M1-13)
and passed to `app.repositories.repo_for`. There is deliberately no default and no way to build
one without a valid `tenant_id` (ARCHITECTURE section 4, item 2).
"""

from __future__ import annotations

from dataclasses import dataclass


def _is_valid_id(value: object) -> bool:
    # bool is a subclass of int; True must not silently become tenant 1.
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


@dataclass(frozen=True, slots=True)
class TenantContext:
    """Immutable scope for tenant data access.

    `tenant_id`: the tenant every repository query is filtered on (required, positive int).
    `principal`: id of the acting user, or None for system work (e.g. a scheduled job acting for
    the tenant). It is carried for auditing/permission checks; it never widens the scope.
    """

    tenant_id: int
    principal: int | None

    def __post_init__(self) -> None:
        if not _is_valid_id(self.tenant_id):
            raise ValueError("TenantContext requires a positive integer tenant_id")
        if self.principal is not None and not _is_valid_id(self.principal):
            raise ValueError("TenantContext principal must be a positive integer user id or None")
