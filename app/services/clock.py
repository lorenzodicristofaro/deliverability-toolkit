"""Clock protocol (M7-09): code that needs "now" takes a `Clock`, so tests use a fake one."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """The current time, timezone-aware (UTC)."""
        ...


class SystemClock:
    """The real wall clock, in UTC."""

    __slots__ = ()

    def now(self) -> datetime:
        return datetime.now(UTC)
