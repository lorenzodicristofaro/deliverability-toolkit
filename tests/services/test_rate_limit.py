"""M7-09 rate limiter: sliding window per key, fake clock, no sleeping, no network."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.services.rate_limit import (
    RateKey,
    RateKind,
    RateLimit,
    SlidingWindowLimiter,
    dnsbl_key,
    http_host_key,
    tenant_key,
)

T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
MIN = timedelta(minutes=1)


class FakeClock:
    def __init__(self, at: datetime = T0) -> None:
        self.at = at

    def now(self) -> datetime:
        return self.at

    def advance(self, **kw: float) -> None:
        self.at += timedelta(**kw)


def _limiter(clock: FakeClock, dnsbl: int = 3, http: int = 2, tenant: int = 100) -> Any:
    return SlidingWindowLimiter(
        {
            RateKind.DNSBL_LIST: RateLimit(dnsbl, MIN),
            RateKind.HTTP_HOST: RateLimit(http, MIN),
            RateKind.TENANT: RateLimit(tenant, MIN),
        },
        clock,
    )


def _max_in_any_window(times: list[datetime], window: timedelta) -> int:
    return max((sum(1 for u in times if t <= u < t + window) for t in times), default=0)


# --- keys --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://Example.COM/x", "example.com"),
        ("http://example.com:8080/a?b", "example.com"),
        ("https://mta-sts.example.com./.well-known/mta-sts.txt", "mta-sts.example.com"),
        ("  https://example.com  ", "example.com"),
        ("https://[2001:db8::1]/", "2001:db8::1"),
    ],
)
def test_http_host_key(url: str, host: str) -> None:
    assert http_host_key(url) == RateKey(RateKind.HTTP_HOST, host)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "example.com",
        "//example.com/x",
        "ftp://example.com/",
        "file:///etc/passwd",
        "https://",
        "https://:443/",
        "https://example.com:99999/",
        "https://example.com:port/",
        "https://[::1/",
        "https://./",
        None,
        b"https://example.com",
        42,
    ],
)
def test_http_host_key_rejects_malformed(url: Any) -> None:
    with pytest.raises(ValueError):
        http_host_key(url)


@pytest.mark.parametrize("bad", [0, -1, True, "1", 1.0, None])
def test_tenant_key_rejects_malformed(bad: Any) -> None:
    with pytest.raises(ValueError):
        tenant_key(bad)


@pytest.mark.parametrize("bad", ["", "  ", None, 1])
def test_dnsbl_key_rejects_malformed(bad: Any) -> None:
    with pytest.raises(ValueError):
        dnsbl_key(bad)


def test_keys_are_distinct_per_kind() -> None:
    assert tenant_key(1) != RateKey(RateKind.DNSBL_LIST, "1")
    assert dnsbl_key("spamhaus-zen") == RateKey(RateKind.DNSBL_LIST, "spamhaus-zen")


@pytest.mark.parametrize(
    ("capacity", "window"),
    [(0, MIN), (-1, MIN), (True, MIN), (1.5, MIN), (1, timedelta(0)), (1, -MIN), (1, 60)],
)
def test_rate_limit_rejects_bad_values(capacity: Any, window: Any) -> None:
    with pytest.raises(ValueError):
        RateLimit(capacity, window)


def test_limiter_needs_every_kind() -> None:
    with pytest.raises(ValueError):
        SlidingWindowLimiter({RateKind.TENANT: RateLimit(1, MIN)}, FakeClock())


def test_limiter_rejects_a_naive_clock() -> None:
    limiter = _limiter(FakeClock(datetime(2026, 11, 17)))
    with pytest.raises(ValueError):
        limiter.try_acquire([tenant_key(1)])


# --- behaviour ---------------------------------------------------------------------------------


def test_capacity_then_wait() -> None:
    clock = FakeClock()
    limiter = _limiter(clock)
    key = dnsbl_key("zen")
    assert [limiter.try_acquire([key]) for _ in range(4)] == [True, True, True, False]
    assert limiter.retry_after([key]) == MIN
    clock.advance(seconds=59)
    assert limiter.try_acquire([key]) is False
    assert limiter.retry_after([key]) == timedelta(seconds=1)
    clock.advance(seconds=1)
    assert limiter.retry_after([key]) == timedelta(0)
    assert limiter.try_acquire([key]) is True


def test_keys_are_independent() -> None:
    limiter = _limiter(FakeClock())
    for _ in range(3):
        assert limiter.try_acquire([dnsbl_key("zen")])
    assert limiter.try_acquire([dnsbl_key("other")])
    assert limiter.try_acquire([tenant_key(1)])


def test_all_or_nothing() -> None:
    limiter = _limiter(FakeClock(), dnsbl=1)
    full, free = dnsbl_key("full"), dnsbl_key("free")
    assert limiter.try_acquire([full])
    assert limiter.try_acquire([full, free]) is False
    assert limiter.in_window(free) == 0  # nothing taken on the free key
    assert limiter.try_acquire([free])


def test_duplicate_keys_count_once() -> None:
    limiter = _limiter(FakeClock(), dnsbl=1)
    assert limiter.try_acquire([dnsbl_key("zen"), dnsbl_key("zen")])
    assert limiter.in_window(dnsbl_key("zen")) == 1


def test_retry_after_is_the_longest_wait() -> None:
    clock = FakeClock()
    limiter = _limiter(clock, dnsbl=1, http=1)
    limiter.try_acquire([dnsbl_key("a")])
    clock.advance(seconds=20)
    limiter.try_acquire([http_host_key("https://h.example/")])
    keys = [dnsbl_key("a"), http_host_key("https://h.example/")]
    assert limiter.retry_after(keys) == timedelta(seconds=60)
    assert limiter.retry_after([]) == timedelta(0)


@pytest.mark.parametrize("step_seconds", [0, 0.5, 7, 13, 30, 61])
def test_never_more_than_capacity_in_any_window(step_seconds: float) -> None:
    clock = FakeClock()
    limiter = _limiter(clock, dnsbl=5)
    key = dnsbl_key("zen")
    granted: list[datetime] = []
    for _ in range(200):
        if limiter.try_acquire([key]):
            granted.append(clock.now())
        clock.advance(seconds=step_seconds)
    assert granted
    assert _max_in_any_window(granted, MIN) <= 5


def test_restart_starts_full_but_never_exceeds_capacity() -> None:
    clock = FakeClock()
    key = dnsbl_key("zen")
    before = _limiter(clock, dnsbl=4)
    assert sum(before.try_acquire([key]) for _ in range(10)) == 4
    clock.advance(seconds=1)
    after = _limiter(clock, dnsbl=4)  # a restart: state is in memory only
    granted = []
    for _ in range(100):
        if after.try_acquire([key]):
            granted.append(clock.now())
        clock.advance(seconds=3)
    # Full allowance right after the restart, but no window ever holds more than the capacity.
    assert granted[:4] == [T0 + timedelta(seconds=1 + 3 * i) for i in range(4)]
    assert _max_in_any_window(granted, MIN) == 4


def test_clock_going_backwards_does_not_free_slots() -> None:
    clock = FakeClock()
    limiter = _limiter(clock, dnsbl=2)
    key = dnsbl_key("zen")
    clock.advance(seconds=30)
    assert limiter.try_acquire([key]) and limiter.try_acquire([key])
    clock.advance(seconds=-3600)
    assert limiter.try_acquire([key]) is False
    assert limiter.retry_after([key]) == MIN


def test_idle_keys_are_forgotten() -> None:
    clock = FakeClock()
    limiter = _limiter(clock)
    for i in range(50):
        limiter.try_acquire([dnsbl_key(f"l{i}")])
    clock.advance(minutes=2)
    assert all(limiter.in_window(dnsbl_key(f"l{i}")) == 0 for i in range(50))
    assert limiter._grants == {}
