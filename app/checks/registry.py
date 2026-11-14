"""Check registry (M3-02).

Registration is explicit: ``load_builtin_checks()`` lists the built-in checks by import, so
importing this module has no side effects and tests can use an empty ``CheckRegistry``.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.checks.models import Check


class DuplicateCheckError(ValueError):
    """A check with this id is already registered."""


class CheckRegistry:
    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def register(self, check: Check) -> None:
        if check.id in self._checks:
            raise DuplicateCheckError(f"duplicate check id: {check.id!r}")
        self._checks[check.id] = check

    def get(self, check_id: str) -> Check:
        """Return the check or raise ``KeyError``."""
        return self._checks[check_id]

    def all_ids(self) -> list[str]:
        return sorted(self._checks)

    def with_checks(self, extra: Iterable[Check]) -> CheckRegistry:
        """A new registry: these checks plus `extra` (one domain run's custom checks, M5-23).
        This registry is unchanged; a duplicate id raises ``DuplicateCheckError``."""
        registry = CheckRegistry()
        for check_id in self.all_ids():
            registry.register(self._checks[check_id])
        for check in extra:
            registry.register(check)
        return registry

    def replacing(self, check: Check) -> CheckRegistry:
        """A new registry with `check` in place of the registered check of the same id (one run's
        configured copy, e.g. the DNSBL check with the instance's enabled lists, M7-05c). This
        registry is unchanged; an id that is not registered raises ``KeyError``."""
        self.get(check.id)
        registry = CheckRegistry()
        for check_id in self.all_ids():
            registry.register(check if check_id == check.id else self._checks[check_id])
        return registry


def load_builtin_checks(registry: CheckRegistry | None = None) -> CheckRegistry:
    """Register every built-in check (explicit list; empty until concrete checks land)."""
    reg = registry if registry is not None else CheckRegistry()
    from app.checks.dkim import DkimCheck
    from app.checks.dmarc import DmarcCheck
    from app.checks.dnsbl import DnsblCheck
    from app.checks.spf import SpfCheck

    builtin: tuple[Check, ...] = (DkimCheck(), DmarcCheck(), DnsblCheck(), SpfCheck())
    for check in builtin:
        reg.register(check)
    return reg
