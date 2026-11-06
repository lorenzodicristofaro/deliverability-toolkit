"""Check registry (M3-02).

Registration is explicit: ``load_builtin_checks()`` lists the built-in checks by import, so
importing this module has no side effects and tests can use an empty ``CheckRegistry``.
"""

from __future__ import annotations

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


def load_builtin_checks(registry: CheckRegistry | None = None) -> CheckRegistry:
    """Register every built-in check (explicit list; empty until concrete checks land)."""
    reg = registry if registry is not None else CheckRegistry()
    from app.checks.dkim import DkimCheck
    from app.checks.dmarc import DmarcCheck
    from app.checks.spf import SpfCheck

    builtin: tuple[Check, ...] = (DkimCheck(), DmarcCheck(), SpfCheck())
    for check in builtin:
        reg.register(check)
    return reg
