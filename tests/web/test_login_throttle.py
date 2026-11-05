"""M1-15 login throttle: backoff, lockout, window, reset, key isolation, bounds (fake clock)."""

from __future__ import annotations

import threading
from typing import Any

import pytest

from app.services.login_throttle import LoginThrottle, ThrottlePolicy, throttle_key

IP = "203.0.113.7"
ACCOUNT = "alice@example.com"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _throttle(**policy: Any) -> tuple[LoginThrottle, Clock]:
    clock = Clock()
    return LoginThrottle(ThrottlePolicy(**policy), clock=clock), clock


def _fail(throttle: LoginThrottle, n: int, ip: str = IP, account: str = ACCOUNT) -> None:
    for _ in range(n):
        throttle.record_failure(ip, account)


@pytest.mark.parametrize(
    ("failures", "expected_wait"),
    [
        (0, 0.0),
        (4, 0.0),
        (5, 1.0),  # first delayed attempt: base_delay * 2**0
        (6, 2.0),
        (7, 4.0),
        (8, 8.0),
        (9, 16.0),
        (10, 900.0),  # lockout
        (25, 900.0),
    ],
)
def test_backoff_and_lockout(failures: int, expected_wait: float) -> None:
    throttle, _ = _throttle()
    _fail(throttle, failures)
    assert throttle.retry_after(IP, ACCOUNT) == pytest.approx(expected_wait)


def test_backoff_is_capped_by_max_delay() -> None:
    throttle, _ = _throttle(free_attempts=1, base_delay=10.0, max_delay=30.0, lockout_after=50)
    _fail(throttle, 6)
    assert throttle.retry_after(IP, ACCOUNT) == pytest.approx(30.0)


def test_wait_decreases_with_time_and_then_allows() -> None:
    throttle, clock = _throttle()
    _fail(throttle, 7)  # 4 s backoff
    clock.now += 3
    assert throttle.retry_after(IP, ACCOUNT) == pytest.approx(1.0)
    clock.now += 1
    assert throttle.retry_after(IP, ACCOUNT) == 0.0
    throttle.record_failure(IP, ACCOUNT)  # failures keep accumulating inside the window
    assert throttle.retry_after(IP, ACCOUNT) == pytest.approx(8.0)


def test_lockout_lasts_the_full_window() -> None:
    throttle, clock = _throttle()
    _fail(throttle, 10)
    clock.now += 899
    assert throttle.retry_after(IP, ACCOUNT) == pytest.approx(1.0)
    clock.now += 1
    assert throttle.retry_after(IP, ACCOUNT) == 0.0
    assert len(throttle) == 0  # expired entry was dropped


def test_window_forgets_old_failures() -> None:
    throttle, clock = _throttle()
    _fail(throttle, 4)
    clock.now += 15 * 60
    throttle.record_failure(IP, ACCOUNT)  # counts from 1 again
    assert throttle.retry_after(IP, ACCOUNT) == 0.0


def test_success_resets() -> None:
    throttle, _ = _throttle()
    _fail(throttle, 9)
    throttle.record_success(IP, ACCOUNT)
    assert throttle.retry_after(IP, ACCOUNT) == 0.0
    throttle.record_success(IP, ACCOUNT)  # idempotent


@pytest.mark.parametrize(
    ("other_ip", "other_account", "shared"),
    [
        (IP, ACCOUNT, True),
        (IP, "  ALICE@Example.COM ", True),  # same normalized account
        ("198.51.100.1", ACCOUNT, False),  # same account, other IP
        (IP, "bob@example.com", False),  # same IP, other account
    ],
)
def test_keys_are_per_ip_and_account(other_ip: str, other_account: str, shared: bool) -> None:
    throttle, _ = _throttle()
    _fail(throttle, 10)
    assert (throttle.retry_after(other_ip, other_account) > 0) is shared


@pytest.mark.parametrize(
    ("ip", "account"),
    [
        (None, None),
        (123, ["x"]),
        ("", ""),
        (IP, "\udcff"),  # lone surrogate
        (IP, "a" * 100_000),
        ("\x00", "\x00@\x00"),
    ],
)
def test_malformed_input_is_throttled_not_crashing(ip: Any, account: Any) -> None:
    throttle, _ = _throttle()
    _fail(throttle, 10, ip, account)
    assert throttle.retry_after(ip, account) > 0
    assert len(throttle_key(ip, account)) == 64


def test_unknown_and_known_accounts_behave_the_same() -> None:
    throttle, _ = _throttle()
    _fail(throttle, 6, IP, "nobody@example.com")
    _fail(throttle, 6, IP, ACCOUNT)
    assert throttle.retry_after(IP, "nobody@example.com") == throttle.retry_after(IP, ACCOUNT)


def test_keys_do_not_store_plain_text() -> None:
    throttle, _ = _throttle()
    throttle.record_failure(IP, ACCOUNT)
    assert all(ACCOUNT not in k and IP not in k for k in throttle._entries)


def test_memory_is_bounded() -> None:
    throttle, clock = _throttle(max_keys=3)
    for i in range(5):
        throttle.record_failure(IP, f"user{i}@example.com")
        clock.now += 1
    assert len(throttle) == 3
    assert throttle.retry_after(IP, "user0@example.com") == 0.0  # oldest evicted
    _fail(throttle, 4, IP, "user4@example.com")
    assert throttle.retry_after(IP, "user4@example.com") > 0


def test_expired_entries_are_pruned_before_eviction() -> None:
    throttle, clock = _throttle(max_keys=2)
    _fail(throttle, 10, IP, "locked@example.com")
    throttle.record_failure(IP, "old@example.com")
    clock.now += 15 * 60  # both expire...
    throttle.record_failure(IP, "a@example.com")
    throttle.record_failure(IP, "b@example.com")
    assert len(throttle) == 2


@pytest.mark.parametrize(
    "policy",
    [
        {"free_attempts": 0},
        {"free_attempts": 10, "lockout_after": 10},
        {"base_delay": 0},
        {"base_delay": 10, "max_delay": 5},
        {"lockout": 0},
        {"window": -1},
        {"max_keys": 0},
    ],
)
def test_policy_rejects_unsafe_values(policy: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        ThrottlePolicy(**policy)


def test_thread_safety() -> None:
    throttle, _ = _throttle(lockout_after=10_000)
    threads = [threading.Thread(target=_fail, args=(throttle, 200)) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert throttle._entries[throttle_key(IP, ACCOUNT)].failures == 1600
