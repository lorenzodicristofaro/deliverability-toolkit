"""M1-15 login throttle: backoff, lockout, window, reset, key isolation, bounds (fake clock).

R1-03: per-IP limit, eviction counted against the IP, bounded concurrent argon2 verifications
(unit tests and through the real app; no network, no wall-clock assertions).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal

import anyio
import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.security import hash_password
from app.main import create_app
from app.models import User
from app.services.login_throttle import LoginThrottle, ThrottlePolicy, ip_key, throttle_key
from app.web import auth as web_auth

IP_MAX_ATTEMPTS = 100  # the per-IP limit of the default policy (R1-03)

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


def test_expired_locked_key_is_dropped_to_make_room() -> None:
    throttle, clock = _throttle(max_keys=1)
    _fail(throttle, 10, IP, "locked@example.com")
    assert throttle.acquire(IP, "new@example.com") > 0  # full of a live lock
    clock.now += 15 * 60
    assert throttle.acquire(IP, "new@example.com") == 0.0
    assert len(throttle) == 1


# --- atomic reservation (QA round 1, blocker) ------------------------------------------------


@pytest.mark.parametrize("workers", [6, 32])
def test_concurrent_attempts_only_free_attempts_pass(workers: int) -> None:
    throttle, _ = _throttle()  # the clock does not move: no backoff can elapse
    barrier = threading.Barrier(workers)
    results: list[float] = []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        wait = throttle.acquire(IP, ACCOUNT)
        with lock:
            results.append(wait)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(1 for w in results if w == 0.0) == throttle.policy.free_attempts
    assert throttle._entries[throttle_key(IP, ACCOUNT)].failures == 5  # refusals not counted


def test_acquire_counts_up_front_and_success_clears() -> None:
    throttle, clock = _throttle()
    for _ in range(5):
        assert throttle.acquire(IP, ACCOUNT) == 0.0
    assert throttle.acquire(IP, ACCOUNT) == pytest.approx(1.0)
    clock.now += 1
    assert throttle.acquire(IP, ACCOUNT) == 0.0  # 6th attempt reserved
    throttle.record_success(IP, ACCOUNT)
    assert throttle.retry_after(IP, ACCOUNT) == 0.0
    assert len(throttle) == 0


# --- eviction never frees a locked key (QA round 1) -----------------------------------------


def test_flood_of_new_accounts_does_not_evict_a_lockout() -> None:
    throttle, clock = _throttle(max_keys=50)
    _fail(throttle, 10, IP, ACCOUNT)
    for i in range(5000):
        throttle.acquire(IP, f"random{i}@example.com")
        clock.now += 0.01
    assert len(throttle) == 50
    assert throttle.retry_after(IP, ACCOUNT) > 800


def test_low_count_keys_are_evicted_before_backoff_keys() -> None:
    throttle, clock = _throttle(max_keys=2)
    _fail(throttle, 8, IP, "backoff@example.com")  # older, but in the backoff tier (8 s)
    clock.now += 1
    throttle.record_failure(IP, "free@example.com")
    clock.now += 1
    assert throttle.acquire(IP, "new@example.com") == 0.0
    assert throttle.retry_after(IP, "backoff@example.com") > 0
    keys = set(throttle._entries)
    assert throttle_key(IP, "free@example.com") not in keys
    assert throttle_key(IP, "backoff@example.com") in keys


def test_full_of_locked_keys_fails_closed() -> None:
    throttle, clock = _throttle(max_keys=3)
    for name in ("a", "b", "c"):
        _fail(throttle, 10, IP, f"{name}@example.com")
    wait = throttle.acquire(IP, "new@example.com")
    assert wait == pytest.approx(900.0)
    assert throttle_key(IP, "new@example.com") not in throttle._entries
    throttle.record_failure(IP, "other@example.com")  # dropped, does not evict a lock
    assert len(throttle) == 3
    assert all(throttle.retry_after(IP, f"{n}@example.com") > 0 for n in "abc")
    clock.now += 900
    assert throttle.acquire(IP, "new@example.com") == 0.0


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


# --- R1-03 (AUTH-02): per-IP limit, eviction counted against the IP --------------------------


def test_many_accounts_from_one_ip_are_throttled() -> None:
    throttle, _ = _throttle()
    waits = [throttle.acquire(IP, f"user{i}@example.com") for i in range(200)]
    allowed = sum(1 for w in waits if w == 0.0)
    assert allowed == IP_MAX_ATTEMPTS
    assert all(w == 0.0 for w in waits[:IP_MAX_ATTEMPTS])
    assert all(w > 0 for w in waits[IP_MAX_ATTEMPTS:])
    assert throttle.acquire("198.51.100.1", "user0@example.com") == 0.0  # other IPs unaffected


@pytest.mark.parametrize(
    ("policy", "flood"),
    [
        ({"max_keys": 50}, 90),  # stays under the per-IP limit: eviction alone is tested
        ({"max_keys": 10}, 90),
        ({"max_keys": 50, "ip_max_attempts": 1_000_000}, 10_000),
    ],
)
def test_flood_of_new_keys_does_not_reset_a_key_of_the_same_ip(
    policy: dict[str, Any], flood: int
) -> None:
    throttle, clock = _throttle(**policy)
    _fail(throttle, 4, IP, ACCOUNT)
    for i in range(flood):
        throttle.acquire(IP, f"random{i}@example.com")
        clock.now += 0.01
    assert len(throttle) <= policy["max_keys"]
    assert throttle_key(IP, ACCOUNT) not in throttle._entries  # it was evicted...
    # ...yet at most the fifth attempt is still free: the four failures were not forgotten.
    assert sum(1 for _ in range(5) if throttle.acquire(IP, ACCOUNT) == 0.0) <= 1


def test_setup_token_key_shares_the_ip_limit() -> None:
    throttle, _ = _throttle()
    for i in range(200):
        throttle.acquire(IP, f"user{i}@example.com")
    assert throttle.acquire(IP, "#setup-token") > 0


def test_ip_limit_waits_for_the_window_and_success_does_not_refund() -> None:
    throttle, clock = _throttle(ip_max_attempts=3, ip_window=60.0)
    for i in range(3):
        assert throttle.acquire(IP, f"user{i}@example.com") == 0.0
        throttle.record_success(IP, f"user{i}@example.com")  # successes still count
    assert throttle.acquire(IP, "other@example.com") == pytest.approx(60.0)
    assert throttle.retry_after(IP, "other@example.com") == pytest.approx(60.0)
    clock.now += 59
    assert throttle.acquire(IP, "other@example.com") == pytest.approx(1.0)  # refusals not counted
    clock.now += 1
    assert throttle.acquire(IP, "other@example.com") == 0.0


@pytest.mark.parametrize("ip", [None, 123, "", "\udcff", "\x00", "a" * 100_000])
def test_ip_limit_with_malformed_ip(ip: Any) -> None:
    throttle, _ = _throttle(ip_max_attempts=2)
    assert throttle.acquire(ip, "a@example.com") == 0.0
    assert throttle.acquire(ip, "b@example.com") == 0.0
    assert throttle.acquire(ip, "c@example.com") > 0


def test_ip_table_is_bounded_and_keeps_no_plain_text() -> None:
    throttle, clock = _throttle(max_ips=3)
    for i in range(10):
        throttle.acquire(f"192.0.2.{i}", ACCOUNT)
        clock.now += 1
    assert len(throttle._ips) == 3
    assert all("192.0.2" not in k for k in throttle._ips)


def test_full_tables_log_a_warning_without_ip_or_account(
    caplog: pytest.LogCaptureFixture,
) -> None:
    throttle, clock = _throttle(max_keys=2, max_ips=2)
    with caplog.at_level("WARNING", logger="app.auth.throttle"):
        for i in range(20):
            throttle.acquire(f"192.0.2.{i}", f"user{i}@example.com")
    tables = [getattr(r, "table", None) for r in caplog.records]
    assert sorted(tables) == ["ips", "keys"]  # rate limited: once per table
    text = " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)
    assert "192.0.2" not in text and "@example.com" not in text


@pytest.mark.parametrize("policy", [{"ip_max_attempts": 0}, {"ip_window": 0}, {"max_ips": -1}])
def test_policy_rejects_unsafe_ip_values(policy: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        ThrottlePolicy(**policy)


# --- R1-03 through the real app (SQLite, or PostgreSQL with TEST_DATABASE_URL; no network) -----

KEY = "k" * 40
PASSWORD = "correct horse battery staple"
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
CLIENT_IP = "testclient"  # the peer address Starlette's TestClient reports
BUSY_EN = "The server is busy"


def _slots(
    monkeypatch: pytest.MonkeyPatch, free: int, bound: int, *, wait: float
) -> anyio.Semaphore:
    """Install a fresh verification semaphore and wait bound (no real waiting when wait=0)."""
    slots = anyio.Semaphore(free, max_value=bound)
    monkeypatch.setattr(web_auth, "VERIFICATION_SLOTS", slots)
    monkeypatch.setattr(web_auth, "VERIFICATION_WAIT", wait)
    return slots


class SpyHasher(PasswordHasher):
    """Fast hasher whose `verify` parks until released and records the peak concurrency."""

    def __init__(self) -> None:
        super().__init__(time_cost=1, memory_cost=8, parallelism=1)
        self.cond = threading.Condition()
        self.active = 0
        self.peak = 0
        self.entered = 0
        self.released = False

    def verify(self, hash: str | bytes, password: str | bytes) -> Literal[True]:
        with self.cond:
            self.active += 1
            self.entered += 1
            self.peak = max(self.peak, self.active)
            self.cond.notify_all()
            # Safety net only (never asserted on): a broken test must not hang the suite.
            self.cond.wait_for(lambda: self.released, timeout=30)
            self.active -= 1
        return super().verify(hash, password)


@dataclass
class App:
    client: TestClient
    app: FastAPI


def _app(db_url: str, *, with_user: bool) -> FastAPI:
    if with_user:
        engine = create_db_engine(db_url)
        try:
            with create_session_factory(engine)() as db:
                db.add(User(email="alice@example.com", password_hash=hash_password(PASSWORD, FAST)))
                db.commit()
        finally:
            engine.dispose()
    application = create_app(
        Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    )
    application.state.login_throttle = LoginThrottle(clock=Clock())
    return application


@contextmanager
def _running(
    db_url: str, monkeypatch: pytest.MonkeyPatch, *, with_user: bool = True
) -> Iterator[App]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    monkeypatch.setattr(web_auth, "PASSWORD_HASHER", FAST)
    application = _app(db_url, with_user=with_user)
    try:
        with TestClient(application) as client:
            yield App(client, application)
    finally:
        engine = getattr(application.state, "db_engine", None)
        if engine is not None:
            engine.dispose()


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


@pytest.mark.parametrize(("lang", "text"), [("en", "Too many failed attempts"), ("it", "Troppi")])
def test_http_many_accounts_from_one_ip_get_the_localized_429(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, lang: str, text: str
) -> None:
    with _running(migrated_db_url, monkeypatch) as a:
        headers = {"Accept-Language": lang}
        token = _csrf(a.client.get("/login", headers=headers).text)
        responses = [
            a.client.post(
                "/login",
                data={"email": f"user{i}@example.com", "password": "pw-x", "csrf_token": token},
                headers=headers,
                follow_redirects=False,
            )
            for i in range(200)
        ]
        statuses = [r.status_code for r in responses]
        assert statuses[:IP_MAX_ATTEMPTS] == [401] * IP_MAX_ATTEMPTS
        assert statuses[IP_MAX_ATTEMPTS:] == [429] * (200 - IP_MAX_ATTEMPTS)
        last = responses[-1]
        assert text in last.text and int(last.headers["retry-after"]) >= 1
        assert 'value="user199@example.com"' in last.text  # same page as today
        assert "pw-x" not in last.text


@pytest.mark.parametrize(("bound", "requests"), [(1, 4), (3, 10)])
def test_concurrent_verifications_are_bounded(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, bound: int, requests: int
) -> None:
    spy = SpyHasher()
    with _running(migrated_db_url, monkeypatch) as a:
        monkeypatch.setattr(web_auth, "PASSWORD_HASHER", spy)
        _slots(monkeypatch, bound, bound, wait=0.0)  # no waiting: over the bound is "busy"
        token = _csrf(a.client.get("/login").text)
        statuses: list[int] = []
        texts: list[str] = []

        def post(i: int) -> None:
            # Known (real verify) and unknown accounts (dummy_verify) alike.
            email = "alice@example.com" if i % 2 else f"ghost{i}@example.com"
            response = a.client.post(
                "/login",
                data={"email": email, "password": "wrong", "csrf_token": token},
                follow_redirects=False,
            )
            with spy.cond:
                statuses.append(response.status_code)
                if response.status_code == 429:
                    texts.append(response.text)
                spy.cond.notify_all()

        threads = [threading.Thread(target=post, args=(i,)) for i in range(requests)]
        for thread in threads:
            thread.start()
        with spy.cond:
            # Proceed once every request is either parked in verify or answered, or as soon
            # as more than `bound` verifications run at once (the failure being tested).
            spy.cond.wait_for(
                lambda: spy.entered + len(statuses) >= requests or spy.peak > bound, timeout=30
            )
            spy.released = True
            spy.cond.notify_all()
        for thread in threads:
            thread.join()
        assert spy.peak <= bound
        assert statuses.count(429) == requests - bound
        assert statuses.count(401) == bound
        # The busy page has its own message, not "too many failed attempts".
        assert all(BUSY_EN in text and "Too many failed" not in text for text in texts)
        assert web_auth.VERIFICATION_SLOTS.value == bound  # every slot was given back
        # Requests refused for lack of a slot were not counted against the IP.
        assert a.app.state.login_throttle._ips[ip_key(CLIENT_IP)].attempts == bound


def test_request_waits_for_a_slot_instead_of_failing(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = SpyHasher()
    with _running(migrated_db_url, monkeypatch) as a:
        monkeypatch.setattr(web_auth, "PASSWORD_HASHER", spy)
        # The wait bound never elapses here: the second request must be served after the first.
        slots = _slots(monkeypatch, 1, 1, wait=30.0)
        token = _csrf(a.client.get("/login").text)
        statuses: list[int] = []

        def post(i: int) -> None:
            response = a.client.post(
                "/login",
                data={"email": f"ghost{i}@example.com", "password": "x", "csrf_token": token},
                follow_redirects=False,
            )
            with spy.cond:
                statuses.append(response.status_code)

        threads = [threading.Thread(target=post, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        with spy.cond:
            # Poll (no timing asserted) until one request is verifying and the other queues.
            for _ in range(600):
                if spy.entered == 1 and slots.statistics().tasks_waiting == 1:
                    break
                spy.cond.wait(timeout=0.05)
            assert spy.entered == 1 and slots.statistics().tasks_waiting == 1
            spy.released = True
            spy.cond.notify_all()
        for thread in threads:
            thread.join()
        assert statuses == [401, 401]
        assert spy.peak == 1
        assert slots.value == 1


@pytest.mark.parametrize("over", ["key", "ip"])
def test_throttled_request_is_refused_without_queueing(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, over: str
) -> None:
    with _running(migrated_db_url, monkeypatch) as a:
        # No free slot and a long wait: a throttled request that queued would answer "busy".
        _slots(monkeypatch, 0, 1, wait=30.0)
        throttle = a.app.state.login_throttle
        for i in range(10 if over == "key" else IP_MAX_ATTEMPTS):
            throttle.record_failure(CLIENT_IP, "ghost@example.com" if over == "key" else str(i))
        response = a.client.post(
            "/login",
            data={
                "email": "ghost@example.com",
                "password": "x",
                "csrf_token": _csrf(a.client.get("/login").text),
            },
            follow_redirects=False,
        )
        assert response.status_code == 429
        assert "Too many failed attempts" in response.text and BUSY_EN not in response.text


@pytest.mark.parametrize(("lang", "text"), [("en", BUSY_EN), ("it", "Il server è occupato")])
def test_busy_page_is_localized(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, lang: str, text: str
) -> None:
    with _running(migrated_db_url, monkeypatch) as a:
        _slots(monkeypatch, 0, 1, wait=0.0)
        headers = {"Accept-Language": lang}
        response = a.client.post(
            "/login",
            data={
                "email": "alice@example.com",
                "password": "pw-x",
                "csrf_token": _csrf(a.client.get("/login", headers=headers).text),
            },
            headers=headers,
            follow_redirects=False,
        )
        assert response.status_code == 429
        assert response.headers["retry-after"] == "1"
        assert text in response.text and "pw-x" not in response.text
        assert len(a.app.state.login_throttle) == 0  # not counted


def test_setup_token_path_shares_the_ip_limit(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _running(migrated_db_url, monkeypatch, with_user=False) as a:
        throttle = a.app.state.login_throttle
        for i in range(IP_MAX_ATTEMPTS):  # login attempts from the same peer address
            assert throttle.acquire(CLIENT_IP, f"user{i}@example.com") == 0.0
        response = a.client.post(
            "/setup",
            data={"csrf_token": _csrf(a.client.get("/setup").text), "setup_token": "x" * 43},
            headers={"Accept-Language": "it"},
            follow_redirects=False,
        )
        assert response.status_code == 429
        assert "Troppi tentativi" in response.text
