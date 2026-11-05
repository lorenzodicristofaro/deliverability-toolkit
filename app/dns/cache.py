"""TTL-respecting DNS cache wrapping any Resolver.

Rules:
- Only `ok` (positive) and definitive-absence (`nxdomain`, `nodata`) results are cached.
  Every failure state (see ResultState.is_failure) is never stored, so a cached entry can
  never turn a failure into "missing" or "ok". No failure cache is implemented.
- Key = (inner.identity, question): results never mix across resolvers.
- Positive TTL = min(record TTLs) clamped to [min_ttl, max_ttl]; a record TTL of 0 means
  "do not cache" (checked before clamping). Hits report records with decremented TTL.
- Negative TTL: RFC 2308 derives it from the SOA minimum/TTL in the authority section, but
  DnsResult does not carry the SOA, so the constant `negative_ttl` is used (capped by max_ttl).
- Concurrent identical queries are coalesced (single flight). The shared query runs in its own
  task, so a cancelled waiter neither cancels it nor affects the other waiters.
- `bypass_cache=True` skips read, write and coalescing (live answer for propagation/"no cache").
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace

from app.dns.types import DnsQuestion, DnsRecord, DnsResult, Resolver

_Key = tuple[str, DnsQuestion]


@dataclass(frozen=True, slots=True)
class _Entry:
    result: DnsResult
    stored_at: float
    expires_at: float


class CachingResolver:
    def __init__(
        self,
        inner: Resolver,
        *,
        clock: Callable[[], float] = time.monotonic,
        min_ttl: int = 0,
        max_ttl: int = 3600,
        negative_ttl: int = 60,
        max_entries: int = 1024,
    ) -> None:
        if min_ttl < 0 or max_ttl < min_ttl or negative_ttl < 0 or max_entries < 1:
            raise ValueError("invalid cache bounds")
        self._inner = inner
        self._clock = clock
        self._min_ttl = min_ttl
        self._max_ttl = max_ttl
        self._negative_ttl = negative_ttl
        self._max_entries = max_entries
        self._entries: OrderedDict[_Key, _Entry] = OrderedDict()
        self._inflight: dict[_Key, asyncio.Task[DnsResult]] = {}

    @property
    def identity(self) -> str:
        return self._inner.identity

    def __len__(self) -> int:
        return len(self._entries)

    async def resolve(self, question: DnsQuestion, *, bypass_cache: bool = False) -> DnsResult:
        if bypass_cache:
            return await self._inner.resolve(question)
        key: _Key = (self._inner.identity, question)
        now = self._clock()
        entry = self._entries.get(key)
        if entry is not None:
            if now < entry.expires_at:
                self._entries.move_to_end(key)
                return self._aged(entry, now)
            del self._entries[key]
        task = self._inflight.get(key)
        if task is None:
            task = asyncio.ensure_future(self._fetch(key, question))
            self._inflight[key] = task
            task.add_done_callback(lambda t: self._finish(key, t))
        return await asyncio.shield(task)

    def _finish(self, key: _Key, task: asyncio.Task[DnsResult]) -> None:
        if self._inflight.get(key) is task:
            del self._inflight[key]
        if not task.cancelled():
            task.exception()  # mark retrieved; waiters see it via the shield

    async def _fetch(self, key: _Key, question: DnsQuestion) -> DnsResult:
        result = await self._inner.resolve(question)
        ttl = self._cache_ttl(result)
        if ttl > 0:
            now = self._clock()
            self._entries[key] = _Entry(result, now, now + ttl)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
        return result

    def _cache_ttl(self, result: DnsResult) -> int:
        if result.state.is_ok:
            raw = min(r.ttl for r in result.records)
            if raw <= 0:
                return 0
            return max(self._min_ttl, min(raw, self._max_ttl))
        if result.state.is_definitive_absence:
            return min(self._negative_ttl, self._max_ttl)
        return 0  # every failure state: never cached

    @staticmethod
    def _aged(entry: _Entry, now: float) -> DnsResult:
        elapsed = int(now - entry.stored_at)
        res = entry.result
        if not res.records:
            return replace(res, elapsed_ms=0.0)
        records: tuple[DnsRecord, ...] = tuple(
            replace(r, ttl=max(0, r.ttl - elapsed)) for r in res.records
        )
        return replace(
            res,
            records=records,
            ttl_min=min(r.ttl for r in records),
            elapsed_ms=0.0,
        )
