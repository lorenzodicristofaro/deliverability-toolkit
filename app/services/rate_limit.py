"""In-memory rate limiting for scheduled runs (M7-09, ARCHITECTURE section 6).

Keys: one per DNSBL list id, one per remote host of an `http_fetch`, one per tenant. A run needs
a free slot on EVERY key it touches and takes them all at once or none (`try_acquire`).

Algorithm: a sliding-window log. Each key keeps the times of its grants inside the last `window`;
a grant is allowed while fewer than `capacity` remain. So, within one process, no interval of
length `window` ever holds more than `capacity` grants for a key (a token bucket refilled
continuously would allow up to twice that around a refill). State is in memory only: a restart
starts every key with a full allowance, which still cannot exceed `capacity` per window in the new
process. Grants made by the previous process are not known; that bound is per process.

The clock is injected. A clock that moves backwards is tolerated: earlier grants still count
until they leave the window measured from the newest time seen. No sleeping, no I/O.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from urllib.parse import urlsplit

from app.services.clock import Clock


class RateKind(StrEnum):
    DNSBL_LIST = "dnsbl"
    HTTP_HOST = "http_host"
    TENANT = "tenant"


@dataclass(frozen=True, slots=True)
class RateKey:
    kind: RateKind
    value: str


@dataclass(frozen=True, slots=True)
class RateLimit:
    """At most `capacity` grants per `window` for one key."""

    capacity: int
    window: timedelta

    def __post_init__(self) -> None:
        if type(self.capacity) is not int or self.capacity < 1:
            raise ValueError("capacity must be a positive int")
        if not isinstance(self.window, timedelta) or self.window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")


def tenant_key(tenant_id: int) -> RateKey:
    if type(tenant_id) is not int or tenant_id < 1:
        raise ValueError("tenant_id must be a positive int")
    return RateKey(RateKind.TENANT, str(tenant_id))


def dnsbl_key(list_id: str) -> RateKey:
    if not isinstance(list_id, str) or not list_id.strip():
        raise ValueError("list_id must be a non-empty string")
    return RateKey(RateKind.DNSBL_LIST, list_id)


def http_host_key(url: str) -> RateKey:
    """The key of the remote host of an absolute http(s) URL: lowercased, without port or trailing
    dot. Raises ValueError for anything else (no scheme, no host, other schemes, bad port)."""
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    try:
        parts = urlsplit(url.strip())
        parts.port  # noqa: B018 - raises ValueError for a malformed port
    except ValueError:
        raise ValueError("malformed url") from None
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("url must be http or https")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise ValueError("url has no host")
    return RateKey(RateKind.HTTP_HOST, host)


class SlidingWindowLimiter:
    """Per-key sliding-window limiter; see the module docstring. Not thread-safe: one owner."""

    __slots__ = ("_clock", "_grants", "_latest", "_limits")

    def __init__(self, limits: Mapping[RateKind, RateLimit], clock: Clock) -> None:
        for kind in RateKind:
            if not isinstance(limits.get(kind), RateLimit):
                raise ValueError(f"missing rate limit for {kind.value}")
        self._limits = dict(limits)
        self._clock = clock
        self._grants: dict[RateKey, deque[datetime]] = {}
        self._latest: datetime | None = None

    def _now(self) -> datetime:
        now = self._clock.now()
        if now.tzinfo is None:
            raise ValueError("the clock must return timezone-aware datetimes")
        if self._latest is None or now > self._latest:
            self._latest = now
        return self._latest

    def _live(self, key: RateKey, now: datetime) -> deque[datetime] | None:
        grants = self._grants.get(key)
        if grants is None:
            return None
        start = now - self._limits[key.kind].window
        while grants and grants[0] <= start:
            grants.popleft()
        if not grants:
            del self._grants[key]  # idle keys do not accumulate
            return None
        return grants

    def retry_after(self, keys: Iterable[RateKey]) -> timedelta:
        """Zero if every key has a free slot now, else how long until all of them do."""
        now = self._now()
        wait = timedelta(0)
        for key in keys:
            limit = self._limits[key.kind]
            grants = self._live(key, now)
            if grants is not None and len(grants) >= limit.capacity:
                # The slot frees when the oldest grant that must leave falls out of the window.
                oldest = grants[len(grants) - limit.capacity]
                wait = max(wait, oldest + limit.window - now)
        return wait

    def try_acquire(self, keys: Iterable[RateKey]) -> bool:
        """Take a slot on every key, or on none if any key is full."""
        wanted = list(dict.fromkeys(keys))
        if self.retry_after(wanted) > timedelta(0):
            return False
        now = self._now()
        for key in wanted:
            self._grants.setdefault(key, deque()).append(now)
        return True

    def in_window(self, key: RateKey) -> int:
        """Grants of `key` still inside its window (for tests and diagnostics)."""
        grants = self._live(key, self._now())
        return 0 if grants is None else len(grants)
