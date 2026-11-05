"""Login throttling per (client IP, account) with exponential backoff and a lockout (M1-15).

STORAGE DECISION (M1): in-process memory. The state lives in this Python process only, so it is
correct ONLY for a single web process (`ROLE=all`, or one `ROLE=web` process with one uvicorn
worker). With several web processes or workers each keeps its own counters and the effective
limit is multiplied by their number, and a restart forgets every counter. A DB-backed throttle
is required before running more than one web process (follow-up, not part of M1-15).

Policy (all failures of one key; a key is the pair (IP, normalized account)):
- The first `free_attempts` failures (5) are not delayed.
- From then on every next attempt must wait `base_delay * 2**(failures - free_attempts)` seconds
  (1, 2, 4, ... capped at `max_delay`, 300 s) after the last failure.
- At `lockout_after` failures (10) the key is locked for `lockout` (15 min) after the last
  failure.
- Failures are forgotten `window` (15 min) after the last failure, and a successful login resets
  the key.

Atomicity: `acquire` checks the key and, if the attempt is allowed, counts it as a failure up
front, under one lock. Parallel requests therefore cannot all pass the check while the password
is still being verified; `record_success` clears the key afterwards. A refused attempt is not
counted.

Memory is bounded (`max_keys`) without scanning: keys sit in three ordered tiers by failure count
(free < `free_attempts` <= backoff < `lockout_after` <= locked), each oldest-first. To make room
for a new key the oldest free key is evicted, then the oldest backoff key; a locked key is
dropped only once it has expired. If every slot holds a live locked key, a new key is refused
(fail closed) until the oldest lock expires. All of this is O(1) per request.

Unknown accounts are throttled exactly like real ones, so the throttle does not reveal whether an
account exists. Keys are SHA-256 digests: no email address or IP is kept in memory as text.
The clock is injectable (monotonic seconds) so tests need no sleeping. Thread-safe. Nothing here
logs.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

# Longest account string considered; longer input is truncated before hashing (cheap, bounded).
_MAX_ACCOUNT_CHARS = 512
_FREE, _BACKOFF, _LOCKED = 0, 1, 2


@dataclass(frozen=True, slots=True)
class ThrottlePolicy:
    free_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 300.0
    lockout_after: int = 10
    lockout: float = 15 * 60.0
    window: float = 15 * 60.0
    max_keys: int = 10_000

    def __post_init__(self) -> None:
        if not 0 < self.free_attempts < self.lockout_after:
            raise ValueError("need 0 < free_attempts < lockout_after")
        if not 0 < self.base_delay <= self.max_delay:
            raise ValueError("need 0 < base_delay <= max_delay")
        if self.lockout <= 0 or self.window <= 0 or self.max_keys <= 0:
            raise ValueError("lockout, window and max_keys must be positive")


@dataclass(slots=True)
class _Entry:
    failures: int
    last_failure: float


def throttle_key(ip: object, account: object) -> str:
    """Digest of (IP, account). The account is stripped and lowercased like an email; anything
    that is not a str (missing field, malformed input) maps to the empty string."""
    ip_text = ip if isinstance(ip, str) else ""
    account_text = account.strip().lower()[:_MAX_ACCOUNT_CHARS] if isinstance(account, str) else ""
    material = f"{ip_text}\x00{account_text}".encode("utf-8", "surrogatepass")
    return hashlib.sha256(material).hexdigest()


class LoginThrottle:
    """In-process throttle (single process only, see the module docstring)."""

    def __init__(
        self, policy: ThrottlePolicy | None = None, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.policy = policy or ThrottlePolicy()
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}
        self._tiers: tuple[OrderedDict[str, None], ...] = (
            OrderedDict(),
            OrderedDict(),
            OrderedDict(),
        )

    # --- public API ---------------------------------------------------------------------------

    def acquire(self, ip: object, account: object) -> float:
        """Reserve one attempt: 0.0 if allowed (already counted as a failure), else the seconds
        to wait (nothing is counted)."""
        key = throttle_key(ip, account)
        with self._lock:
            now = self._clock()
            entry = self._live(key, now)
            if entry is not None:
                wait = self._wait(entry, now)
                if wait > 0:
                    return wait
            if not self._count(key, entry, now):
                return self._full_wait(now)
            return 0.0

    def retry_after(self, ip: object, account: object) -> float:
        """Seconds the next attempt would have to wait (read-only); 0.0 means allowed."""
        key = throttle_key(ip, account)
        with self._lock:
            now = self._clock()
            entry = self._live(key, now)
            return 0.0 if entry is None else self._wait(entry, now)

    def record_failure(self, ip: object, account: object) -> None:
        """Count a failure without checking the delay (not used by the login flow, which counts
        through `acquire`). Dropped when the table is full of live locked keys."""
        key = throttle_key(ip, account)
        with self._lock:
            now = self._clock()
            self._count(key, self._live(key, now), now)

    def record_success(self, ip: object, account: object) -> None:
        key = throttle_key(ip, account)
        with self._lock:
            if key in self._entries:
                self._remove(key)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # --- internals (caller holds the lock) ----------------------------------------------------

    def _tier_of(self, failures: int) -> int:
        if failures >= self.policy.lockout_after:
            return _LOCKED
        return _BACKOFF if failures >= self.policy.free_attempts else _FREE

    def _expired(self, entry: _Entry, now: float) -> bool:
        since = now - entry.last_failure
        return since >= self.policy.window and since >= self.policy.lockout

    def _wait(self, entry: _Entry, now: float) -> float:
        policy = self.policy
        since = now - entry.last_failure
        if entry.failures >= policy.lockout_after:
            required = policy.lockout
        elif entry.failures >= policy.free_attempts:
            exponent = entry.failures - policy.free_attempts
            required = min(policy.base_delay * 2.0**exponent, policy.max_delay)
        else:
            return 0.0
        return max(0.0, required - since)

    def _full_wait(self, now: float) -> float:
        """Wait reported when the table is full of live locked keys: until the oldest expires."""
        locked = self._tiers[_LOCKED]
        if not locked:
            return self.policy.base_delay
        oldest = self._entries[next(iter(locked))]
        horizon = max(self.policy.window, self.policy.lockout)
        return max(self.policy.base_delay, horizon - (now - oldest.last_failure))

    def _remove(self, key: str) -> None:
        entry = self._entries.pop(key)
        self._tiers[self._tier_of(entry.failures)].pop(key, None)

    def _live(self, key: str, now: float) -> _Entry | None:
        entry = self._entries.get(key)
        if entry is not None and self._expired(entry, now):
            self._remove(key)
            return None
        return entry

    def _make_room(self, now: float) -> bool:
        """Free a slot for a new key; False (fail closed) if only live locked keys remain."""
        while len(self._entries) >= self.policy.max_keys:
            free, backoff, locked = self._tiers
            if free:
                self._remove(next(iter(free)))
            elif backoff:
                self._remove(next(iter(backoff)))
            else:
                oldest = next(iter(locked))
                if not self._expired(self._entries[oldest], now):
                    return False
                self._remove(oldest)
        return True

    def _count(self, key: str, entry: _Entry | None, now: float) -> bool:
        if entry is None:
            if not self._make_room(now):
                return False
            entry = _Entry(failures=0, last_failure=now)
            self._entries[key] = entry
        else:
            self._tiers[self._tier_of(entry.failures)].pop(key, None)
        entry.failures += 1
        entry.last_failure = now
        tier = self._tiers[self._tier_of(entry.failures)]
        tier[key] = None
        tier.move_to_end(key)
        return True
