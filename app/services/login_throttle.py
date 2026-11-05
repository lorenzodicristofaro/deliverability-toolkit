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
Unknown accounts are throttled exactly like real ones, so the throttle does not reveal whether an
account exists. Keys are SHA-256 digests: no email address or IP is kept in memory as text.
Memory is bounded (`max_keys`): expired keys are pruned first, then the oldest keys are evicted.

The clock is injectable (monotonic seconds) so tests need no sleeping. Thread-safe (sync FastAPI
endpoints run in a thread pool). Nothing here logs.
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
        self._entries: OrderedDict[str, _Entry] = OrderedDict()

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

    def _expired(self, entry: _Entry, now: float) -> bool:
        since = now - entry.last_failure
        return since >= self.policy.window and since >= self.policy.lockout

    def retry_after(self, ip: object, account: object) -> float:
        """Seconds the caller must wait before this attempt is allowed; 0.0 means allowed."""
        key = throttle_key(ip, account)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return 0.0
            now = self._clock()
            if self._expired(entry, now):
                del self._entries[key]
                return 0.0
            return self._wait(entry, now)

    def record_failure(self, ip: object, account: object) -> None:
        key = throttle_key(ip, account)
        with self._lock:
            now = self._clock()
            entry = self._entries.get(key)
            if entry is None or self._expired(entry, now):
                entry = _Entry(failures=0, last_failure=now)
            entry.failures += 1
            entry.last_failure = now
            self._entries[key] = entry
            self._entries.move_to_end(key)
            self._bound(now)

    def record_success(self, ip: object, account: object) -> None:
        with self._lock:
            self._entries.pop(throttle_key(ip, account), None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def _bound(self, now: float) -> None:
        if len(self._entries) <= self.policy.max_keys:
            return
        for key in [k for k, e in self._entries.items() if self._expired(e, now)]:
            del self._entries[key]
        while len(self._entries) > self.policy.max_keys:
            self._entries.popitem(last=False)  # least recently failed first
