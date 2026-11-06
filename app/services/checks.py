"""THE entry point for running checks (UI, API and CLI) (M3-02).

The runner is the only producer of ``CheckResult`` that callers see: whatever a check returns is
re-stamped here (``started_at``/``duration_ms`` from the context clock, ``check_id``/``target``
from the request), and any exception, timeout or invalid return value becomes status ``error``
(never ``ok``) with a generic finding. Exceptions never escape and are logged by type only,
without echoing raw input.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from datetime import datetime

from app.checks.models import CheckContext, CheckResult, Target, finding
from app.checks.registry import CheckRegistry, load_builtin_checks
from app.core.domain_names import InvalidDomainName, to_dns_name

log = logging.getLogger(__name__)

CODES: tuple[str, ...] = ("CHECK_INTERNAL_ERROR", "CHECK_TIMEOUT")

DEFAULT_DEADLINE_S = 15.0
DEFAULT_CONCURRENCY = 8

_default_registry: CheckRegistry | None = None


class UnknownCheck(LookupError):
    """No check with this id (callers map to 404/422)."""

    def __init__(self, check_id: str) -> None:
        super().__init__("unknown check")
        self.check_id = check_id


class InvalidTarget(ValueError):
    """The domain name is not valid. ``reason`` is a stable code, never the input."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"invalid target: {reason}")
        self.reason = reason


def default_registry() -> CheckRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = load_builtin_checks()
    return _default_registry


def _target(name: str) -> Target:
    try:
        return Target(domain=to_dns_name(name, allow_underscore=False))
    except InvalidDomainName as e:
        raise InvalidTarget(e.reason) from None


def _require(reg: CheckRegistry, check_id: str) -> None:
    try:
        reg.get(check_id)
    except KeyError:
        raise UnknownCheck(check_id) from None


def _error(
    check_id: str, target: str, code: str, started: datetime, duration_ms: int
) -> CheckResult:
    return CheckResult.build(
        check_id=check_id,
        target=target,
        findings=[finding(code, "medium", remediation=False)],
        evaluated=False,
        started_at=started,
        duration_ms=duration_ms,
    )


async def _run(
    check_id: str,
    target: Target,
    ctx: CheckContext,
    reg: CheckRegistry,
    deadline_s: float,
) -> CheckResult:
    check = reg.get(check_id)
    started = ctx.clock()

    def elapsed_ms() -> int:
        return max(0, int((ctx.clock() - started).total_seconds() * 1000))

    def failed(code: str) -> CheckResult:
        return _error(check_id, target.domain, code, started, elapsed_ms())

    try:
        async with asyncio.timeout(deadline_s):
            raw = await check.run(ctx, target)
    except TimeoutError:
        # Our deadline, or a timeout raised inside the check: either way not evaluated.
        log.warning("check timed out", extra={"check_id": check_id})
        return failed("CHECK_TIMEOUT")
    except Exception as e:  # noqa: BLE001 - every failure becomes `error`
        log.warning("check failed", extra={"check_id": check_id, "error_type": type(e).__name__})
        return failed("CHECK_INTERNAL_ERROR")
    if not isinstance(raw, CheckResult):
        log.warning("check returned invalid result", extra={"check_id": check_id})
        return failed("CHECK_INTERNAL_ERROR")
    try:
        return CheckResult(
            check_id=check_id,
            target=target.domain,
            status=raw.status,
            findings=raw.findings,
            data=raw.data,
            started_at=started,
            duration_ms=elapsed_ms(),
        )
    except Exception as e:  # noqa: BLE001
        log.warning(
            "check result rejected", extra={"check_id": check_id, "error_type": type(e).__name__}
        )
        return failed("CHECK_INTERNAL_ERROR")


async def run_check(
    check_id: str,
    name: str,
    ctx: CheckContext,
    *,
    registry: CheckRegistry | None = None,
    deadline_s: float = DEFAULT_DEADLINE_S,
) -> CheckResult:
    """Run one check. Raises ``UnknownCheck`` / ``InvalidTarget``; nothing else escapes."""
    reg = registry if registry is not None else default_registry()
    _require(reg, check_id)
    return await _run(check_id, _target(name), ctx, reg, deadline_s)


async def run_checks(
    ids: Sequence[str],
    name: str,
    ctx: CheckContext,
    *,
    registry: CheckRegistry | None = None,
    deadline_s: float = DEFAULT_DEADLINE_S,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[CheckResult]:
    """Run checks concurrently (bounded); results are in the order of ``ids``."""
    reg = registry if registry is not None else default_registry()
    for check_id in ids:
        _require(reg, check_id)
    target = _target(name)
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(check_id: str) -> CheckResult:
        async with sem:
            return await _run(check_id, target, ctx, reg, deadline_s)

    return list(await asyncio.gather(*(one(i) for i in ids)))
