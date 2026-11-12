"""Login throttling per (client IP, account) with exponential backoff and a lockout (M1-15), plus
an account-independent limit per client IP and a bound on concurrent password verifications
(R1-03, review finding AUTH-02).

STORAGE DECISION (M1): in-process memory. The state lives in this Python process only, so it is
correct ONLY for a single web process (`ROLE=all`, or one `ROLE=web` process with one uvicorn
worker). With several web processes or workers each keeps its own counters and the effective
limit is multiplied by their number, and a restart forgets every counter. A DB-backed throttle
is required before running more than one web process (follow-up, not part of M1-15).

Policy per key (all failures of one key; a key is the pair (IP, normalized account)):
- The first `free_attempts` failures (5) are not delayed.
- From then on every next attempt must wait `base_delay * 2**(failures - free_attempts)` seconds
  (1, 2, 4, ... capped at `max_delay`, 300 s) after the last failure.
- At `lockout_after` failures (10) the key is locked for `lockout` (15 min) after the last
  failure.
- Failures are forgotten `window` (15 min) after the last failure, and a successful login resets
  the key.

Policy per client IP (R1-03), checked first, before the key and before any password work:
- Every attempt the throttle lets through counts against its IP, whatever the account string
  and whatever the outcome (a success does not refund it, so a known password cannot buy extra
  guesses). At `ip_max_attempts` (`IP_MAX_ATTEMPTS`, 100) attempts the IP is refused until
  `ip_window` (`IP_WINDOW`, 15 min) after its last counted attempt. Without this limit a client
  sending a new account string on every request would never meet a delay, and every request
  would still pay one full argon2 verification (the dummy one for unknown accounts).
- "IP" is the direct peer address the web layer passes in. Behind a reverse proxy every client
  shares the proxy's address, so they share this limit until a trusted-proxy setting exists
  (tracked separately, AUTH-04).

Atomicity: `acquire` checks the IP and the key and, if the attempt is allowed, counts it up front
(a failure for the key, an attempt for the IP), under one lock. Parallel requests therefore
cannot all pass the check while the password is still being verified; `record_success` clears
the key afterwards. A refused attempt is not counted.

Memory is bounded (`max_keys`) without scanning: keys sit in three ordered tiers by failure count
(free < `free_attempts` <= backoff < `lockout_after` <= locked), each oldest-first. To make room
for a new key the oldest free key is evicted, then the oldest backoff key; a locked key is
dropped only once it has expired. If every slot holds a live locked key, a new key is refused
(fail closed) until the oldest lock expires. All of this is O(1) per request.
Evictions are counted against the evicted key's IP (R1-03): the IP remembers the worst live
evicted key (failure count and time of its last failure), and every new key of that IP starts
from that state instead of from zero. A flood of new keys therefore cannot reset an attacker's
own counter on a target account (or any key of the same IP) below what it had.
Side effect: once a key from an IP has been evicted (table full), every new key from that IP,
including the setup-token key, starts from the worst evicted state, so users behind the same NAT
or proxy address inherit that backoff until it expires (`window`/`lockout` after its failure).
The IP table is bounded too (`max_ips`, oldest touched evicted first). That eviction fails
open: an attacker who controls more than `max_ips` addresses can make an IP forget its counts,
but such an attacker is not limited by a per-IP rule anyway, and the per-key throttle and the
verification bound below still apply. Failing closed there would let address rotation lock
every user out.
When either table is full a WARNING is logged (at most once per `_FULL_LOG_INTERVAL` per table)
with only the table name: no IP, account or digest.

Concurrent verifications: `MAX_CONCURRENT_VERIFICATIONS` (4) bounds the argon2 verifications
(real or dummy) the web layer runs at once in this process; each needs 64 MiB with the library
defaults (app.core.security). The web layer holds one slot of a process-wide semaphore around
the password work and answers 429 when none is free, instead of queueing.

Unknown accounts are throttled exactly like real ones, so the throttle does not reveal whether an
account exists. Keys are SHA-256 digests: no email address or IP is kept in memory as text.
The clock is injectable (monotonic seconds) so tests need no sleeping. Thread-safe.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger("app.auth.throttle")

# Longest account string considered; longer input is truncated before hashing (cheap, bounded).
_MAX_ACCOUNT_CHARS = 512
_FREE, _BACKOFF, _LOCKED = 0, 1, 2

# Per-IP limit (R1-03): attempts counted per client IP, and the quiet time that resets them.
IP_MAX_ATTEMPTS = 100
IP_WINDOW = 15 * 60.0
# Process-wide bound on concurrent argon2 verifications (R1-03): 4 x 64 MiB with the defaults.
MAX_CONCURRENT_VERIFICATIONS = 4
# A full table is logged at most this often (monotonic seconds, per table).
_FULL_LOG_INTERVAL = 60.0


@dataclass(frozen=True, slots=True)
class ThrottlePolicy:
    free_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 300.0
    lockout_after: int = 10
    lockout: float = 15 * 60.0
    window: float = 15 * 60.0
    max_keys: int = 10_000
    ip_max_attempts: int = IP_MAX_ATTEMPTS
    ip_window: float = IP_WINDOW
    max_ips: int = 10_000

    def __post_init__(self) -> None:
        if not 0 < self.free_attempts < self.lockout_after:
            raise ValueError("need 0 < free_attempts < lockout_after")
        if not 0 < self.base_delay <= self.max_delay:
            raise ValueError("need 0 < base_delay <= max_delay")
        if self.lockout <= 0 or self.window <= 0 or self.max_keys <= 0:
            raise ValueError("lockout, window and max_keys must be positive")
        if self.ip_max_attempts <= 0 or self.ip_window <= 0 or self.max_ips <= 0:
            raise ValueError("ip_max_attempts, ip_window and max_ips must be positive")


@dataclass(slots=True)
class _Entry:
    failures: int
    last_failure: float
    ip: str = ""  # digest of the key's IP (see `ip_key`), to charge evictions against it


@dataclass(slots=True)
class _IpEntry:
    attempts: int = 0
    last_attempt: float = 0.0
    # Worst live evicted key of this IP: new keys of the IP start from it (0 = none).
    floor: int = 0
    floor_last_failure: float = 0.0


def _ip_text(ip: object) -> str:
    return ip if isinstance(ip, str) else ""


def throttle_key(ip: object, account: object) -> str:
    """Digest of (IP, account). The account is stripped and lowercased like an email; anything
    that is not a str (missing field, malformed input) maps to the empty string."""
    account_text = account.strip().lower()[:_MAX_ACCOUNT_CHARS] if isinstance(account, str) else ""
    material = f"{_ip_text(ip)}\x00{account_text}".encode("utf-8", "surrogatepass")
    return hashlib.sha256(material).hexdigest()


def ip_key(ip: object) -> str:
    """Digest of the client IP alone (domain-separated from `throttle_key`); non-str maps to ''."""
    material = f"ip\x00{_ip_text(ip)}".encode("utf-8", "surrogatepass")
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
        self._ips: OrderedDict[str, _IpEntry] = OrderedDict()
        self._full_logged: dict[str, float] = {}

    # --- public API ---------------------------------------------------------------------------

    def acquire(self, ip: object, account: object) -> float:
        """Reserve one attempt: 0.0 if allowed (already counted against the key and the IP),
        else the seconds to wait (nothing is counted). The IP limit is checked first. A new key
        of an IP that has had a key evicted (table full) starts from the worst evicted state, the
        setup-token key included, so users sharing that address inherit its backoff."""
        key, ipk = throttle_key(ip, account), ip_key(ip)
        with self._lock:
            now = self._clock()
            ip_entry = self._live_ip(ipk, now)
            ip_wait = self._ip_wait(ip_entry, now)
            if ip_wait > 0:
                return ip_wait
            entry = self._live(key, now)
            wait = self._wait(entry or self._inherited(ip_entry, now), now)
            if wait > 0:
                return wait
            if not self._count(key, entry, now, ipk):
                return self._full_wait(now)
            self._charge_ip(ipk, now)
            return 0.0

    def retry_after(self, ip: object, account: object) -> float:
        """Seconds the next attempt would have to wait (read-only); 0.0 means allowed."""
        key, ipk = throttle_key(ip, account), ip_key(ip)
        with self._lock:
            now = self._clock()
            ip_entry = self._live_ip(ipk, now)
            entry = self._live(key, now) or self._inherited(ip_entry, now)
            return max(self._ip_wait(ip_entry, now), self._wait(entry, now))

    def record_failure(self, ip: object, account: object) -> None:
        """Count a failure without checking the delays (not used by the login flow, which counts
        through `acquire`). Dropped when the table is full of live locked keys."""
        key, ipk = throttle_key(ip, account), ip_key(ip)
        with self._lock:
            now = self._clock()
            self._live_ip(ipk, now)
            if self._count(key, self._live(key, now), now, ipk):
                self._charge_ip(ipk, now)

    def record_success(self, ip: object, account: object) -> None:
        """Clear the key. The IP's attempt count is not refunded (see the module docstring)."""
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

    def _wait(self, entry: _Entry | None, now: float) -> float:
        if entry is None:
            return 0.0
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

    def _warn_full(self, table: str, now: float) -> None:
        last = self._full_logged.get(table)
        if last is not None and now - last < _FULL_LOG_INTERVAL:
            return
        self._full_logged[table] = now
        logger.warning(
            "login throttle table full", extra={"event": "auth.throttle_full", "table": table}
        )

    def _remove(self, key: str) -> _Entry:
        entry = self._entries.pop(key)
        self._tiers[self._tier_of(entry.failures)].pop(key, None)
        return entry

    def _live(self, key: str, now: float) -> _Entry | None:
        entry = self._entries.get(key)
        if entry is not None and self._expired(entry, now):
            self._remove(key)
            return None
        return entry

    # --- per-IP state -------------------------------------------------------------------------

    def _live_ip(self, ipk: str, now: float) -> _IpEntry | None:
        """The IP's entry with expired parts reset; None (and dropped) when nothing is left."""
        entry = self._ips.get(ipk)
        if entry is None:
            return None
        if entry.attempts and now - entry.last_attempt >= self.policy.ip_window:
            entry.attempts = 0
        if entry.floor and self._expired(_Entry(entry.floor, entry.floor_last_failure), now):
            entry.floor = 0
        if not entry.attempts and not entry.floor:
            del self._ips[ipk]
            return None
        return entry

    def _ip_wait(self, entry: _IpEntry | None, now: float) -> float:
        if entry is None or entry.attempts < self.policy.ip_max_attempts:
            return 0.0
        return max(0.0, self.policy.ip_window - (now - entry.last_attempt))

    def _inherited(self, entry: _IpEntry | None, now: float) -> _Entry | None:
        """The state a new key of this IP starts from (its worst live evicted key), if any."""
        if entry is None or not entry.floor:
            return None
        inherited = _Entry(entry.floor, entry.floor_last_failure)
        return None if self._expired(inherited, now) else inherited

    def _ip_entry(self, ipk: str) -> _IpEntry:
        """The IP's entry, created (making room) if missing, and marked most recently used."""
        entry = self._ips.get(ipk)
        if entry is None:
            if len(self._ips) >= self.policy.max_ips:
                self._warn_full("ips", self._clock())
                while len(self._ips) >= self.policy.max_ips:
                    self._ips.popitem(last=False)  # fail open, see the module docstring
            entry = self._ips[ipk] = _IpEntry()
        else:
            self._ips.move_to_end(ipk)
        return entry

    def _charge_ip(self, ipk: str, now: float) -> None:
        entry = self._ip_entry(ipk)
        entry.attempts += 1
        entry.last_attempt = now

    def _charge_eviction(self, evicted: _Entry, now: float) -> None:
        """Count an evicted live key against its IP, so its failures are not forgotten."""
        if evicted.failures <= 0 or self._expired(evicted, now):
            return
        entry = self._ip_entry(evicted.ip)
        current = self._inherited(entry, now)
        if current is None or (evicted.failures, evicted.last_failure) > (
            current.failures,
            current.last_failure,
        ):
            entry.floor = evicted.failures
            entry.floor_last_failure = evicted.last_failure

    # --- key table ----------------------------------------------------------------------------

    def _make_room(self, now: float) -> bool:
        """Free a slot for a new key; False (fail closed) if only live locked keys remain."""
        if len(self._entries) >= self.policy.max_keys:
            self._warn_full("keys", now)
        while len(self._entries) >= self.policy.max_keys:
            free, backoff, locked = self._tiers
            if free:
                self._charge_eviction(self._remove(next(iter(free))), now)
            elif backoff:
                self._charge_eviction(self._remove(next(iter(backoff))), now)
            else:
                oldest = next(iter(locked))
                if not self._expired(self._entries[oldest], now):
                    return False
                self._remove(oldest)
        return True

    def _count(self, key: str, entry: _Entry | None, now: float, ipk: str) -> bool:
        if entry is None:
            if not self._make_room(now):
                return False
            # A new key starts from the worst evicted state of its IP (see the module docstring:
            # every new key of that IP, setup-token key included, shares it until it expires).
            inherited = self._inherited(self._ips.get(ipk), now)
            entry = _Entry(
                failures=inherited.failures if inherited else 0, last_failure=now, ip=ipk
            )
            self._entries[key] = entry
        else:
            self._tiers[self._tier_of(entry.failures)].pop(key, None)
        entry.failures += 1
        entry.last_failure = now
        tier = self._tiers[self._tier_of(entry.failures)]
        tier[key] = None
        tier.move_to_end(key)
        return True
