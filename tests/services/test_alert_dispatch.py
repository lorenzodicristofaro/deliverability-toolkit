"""M7-15 alert dispatch: settings validation (table-driven, malformed input), secret sealing,
rendering in the tenant language, the channel registry, the test send limiter, and the delivery
loop on top of M7-14's `deliver_due` with a fake channel (outcomes, channel exceptions, missing,
disabled, unregistered or unreadable channels, timeouts, several tenants, stop and cancel).

Runs on SQLite and, with TEST_DATABASE_URL, on PostgreSQL. No network: the channel is a fake and
URL checks are pure (`app.net.policy.parse_url`, no DNS).
"""

from __future__ import annotations

import asyncio
import logging
import types
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core import i18n
from app.core.db import create_db_engine, create_session_factory
from app.core.secrets_crypto import SecretCipher, SecretsError
from app.core.tenancy import TenantContext
from app.models import AlertDelivery, Tenant
from app.repositories import repo_for
from app.services import alert_dispatch
from app.services.alert_dispatch import (
    AlertDispatcher,
    ChannelRegistry,
    FieldError,
    RenderedAlert,
    ResolvedChannel,
    SendOutcome,
    SendResult,
    TestSendLimiter,
    check_url,
    default_registry,
    field_key,
    open_secrets,
    render,
    seal_secrets,
    validate_config,
    validate_secrets,
)
from app.services.alerts import AlertMessage, AlertService
from app.services.change_detect import ChangeEvent

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
PORTS = (80, 443)
SECRET_URL = "https://hooks.example.com/services/T0SECRETPATH"
SIGNING = "s3cr3t-signing-value-0123"


class FakeClock:
    def __init__(self, now: datetime = T0) -> None:
        self.at = now

    def now(self) -> datetime:
        return self.at

    def advance(self, delta: timedelta) -> None:
        self.at += delta


@dataclass
class FakeChannel:
    kind: str = "webhook"
    result: Any = field(default_factory=SendResult.ok)
    exc: BaseException | None = None
    hang: bool = False
    config_errors: list[FieldError] = field(default_factory=list)
    secret_errors: list[FieldError] = field(default_factory=list)
    calls: list[tuple[AlertMessage, RenderedAlert, ResolvedChannel]] = field(default_factory=list)
    on_send: Any = None

    def validate_config(self, config: Mapping[str, Any]) -> list[FieldError]:
        return list(self.config_errors)

    def validate_secrets(self, secrets: Mapping[str, str]) -> list[FieldError]:
        return list(self.secret_errors)

    async def send(
        self, alert: AlertMessage, rendered: RenderedAlert, channel: ResolvedChannel
    ) -> SendResult:
        self.calls.append((alert, rendered, channel))
        if self.on_send is not None:
            self.on_send()
        if self.hang:
            await asyncio.sleep(30)
        if self.exc is not None:
            raise self.exc
        return self.result  # type: ignore[no-any-return]


@pytest.fixture(autouse=True)
def _strict() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


# --- pure parts --------------------------------------------------------------------------------

EMPTY = ChannelRegistry()
REC_BAD = [FieldError("recipients", "malformed")]
REC_COUNT = [FieldError("recipients", "count")]
SIG_BAD = [FieldError("signing_secret", "malformed")]
PORT_BAD = [FieldError("url", "port_not_allowed")]

CONFIG_CASES: list[tuple[str, Any, list[FieldError]]] = [
    ("email", {"recipients": ["ops@example.com"]}, []),
    ("email", {"recipients": [f"u{i}@example.com" for i in range(10)]}, []),
    ("email", {}, [FieldError("recipients", "required")]),
    ("email", {"recipients": []}, REC_COUNT),
    ("email", {"recipients": [f"u{i}@example.com" for i in range(11)]}, REC_COUNT),
    ("email", {"recipients": "ops@example.com"}, REC_COUNT),
    ("email", {"recipients": ["not-an-address"]}, REC_BAD),
    ("email", {"recipients": ["Ops@Example.com"]}, REC_BAD),
    ("email", {"recipients": ["a@example.com", "a@example.com"]}, REC_BAD),
    ("email", {"recipients": ["a@example.com\r\nbcc:x@evil.example"]}, REC_BAD),
    ("email", {"recipients": ["a@example.com,b@example.com"]}, REC_BAD),
    ("email", {"recipients": [5]}, REC_BAD),
    ("email", {"recipients": ["a@example.com"], "cc": []}, [FieldError("config", "unknown_field")]),
    ("email", ["recipients"], [FieldError("config", "malformed")]),
    ("email", None, [FieldError("config", "malformed")]),
    ("webhook", {}, []),
    ("webhook", {"url": SECRET_URL}, [FieldError("config", "unknown_field")]),
    ("slack", {}, []),
    ("teams", {"x": 1}, [FieldError("config", "unknown_field")]),
]  # fmt: skip


@pytest.mark.parametrize(
    ("kind", "config", "expected"), CONFIG_CASES, ids=[repr(c[:2]) for c in CONFIG_CASES]
)
def test_validate_config(kind: str, config: Any, expected: list[FieldError]) -> None:
    assert validate_config(kind, config, EMPTY)[1] == expected


SECRET_CASES: list[tuple[str, Any, list[FieldError]]] = [
    ("webhook", {"url": SECRET_URL}, []),
    ("webhook", {"url": SECRET_URL, "signing_secret": SIGNING}, []),
    ("webhook", {}, [FieldError("url", "required")]),
    ("webhook", {"url": SECRET_URL, "token": "x"}, [FieldError("secrets", "unknown_field")]),
    ("webhook", {"url": "http://hooks.example.com/x"}, [FieldError("url", "scheme_not_allowed")]),
    ("webhook", {"url": "ftp://hooks.example.com/x"}, [FieldError("url", "scheme_not_allowed")]),
    ("webhook", {"url": "https://hooks.example.com:8443/x"}, PORT_BAD),
    ("webhook", {"url": "https://user:pw@hooks.example.com/x"}, [FieldError("url", "blocked")]),
    ("webhook", {"url": "https://127.0.0.1/x"}, [FieldError("url", "blocked")]),
    ("webhook", {"url": "https://10.0.0.5/x"}, [FieldError("url", "blocked")]),
    ("webhook", {"url": "https://[::1]/x"}, [FieldError("url", "blocked")]),
    ("webhook", {"url": "https:///nohost"}, [FieldError("url", "blocked")]),
    ("webhook", {"url": "https://exa mple.com/"}, [FieldError("url", "blocked")]),
    ("webhook", {"url": "https://example.com/\r\nX: y"}, [FieldError("url", "blocked")]),
    ("webhook", {"url": ""}, [FieldError("url", "malformed")]),
    ("webhook", {"url": 5}, [FieldError("url", "malformed")]),
    ("webhook", {"url": "https://example.com/" + "a" * 2100}, [FieldError("url", "malformed")]),
    ("webhook", {"url": SECRET_URL, "signing_secret": "short"}, SIG_BAD),
    ("webhook", {"url": SECRET_URL, "signing_secret": "has space 12345678"}, SIG_BAD),
    ("webhook", {"url": SECRET_URL, "signing_secret": "x" * 257}, SIG_BAD),
    ("webhook", {"url": SECRET_URL, "signing_secret": "é" * 20}, SIG_BAD),
    ("slack", {"url": SECRET_URL}, []),
    ("slack", {"url": SECRET_URL, "signing_secret": SIGNING}, [FieldError("secrets", "unknown_field")]),  # noqa: E501
    ("teams", {}, [FieldError("url", "required")]),
    ("email", {}, []),
    ("email", {"password": "x"}, [FieldError("secrets", "unknown_field")]),
    ("webhook", "https://x.example", [FieldError("secrets", "malformed")]),
]  # fmt: skip


@pytest.mark.parametrize(
    ("kind", "secrets", "expected"), SECRET_CASES, ids=[repr(c[:2])[:80] for c in SECRET_CASES]
)
def test_validate_secrets(kind: str, secrets: Any, expected: list[FieldError]) -> None:
    assert validate_secrets(kind, secrets, EMPTY, PORTS)[1] == expected


def test_registered_channel_checks_run_after_the_base_checks() -> None:
    fake = FakeChannel(
        config_errors=[FieldError("config", "channel_says_no")],
        secret_errors=[FieldError("url", "host_not_documented")],
    )
    registry = ChannelRegistry({"webhook": fake})
    assert validate_config("webhook", {}, registry)[1] == [FieldError("config", "channel_says_no")]
    assert validate_secrets("webhook", {"url": SECRET_URL}, registry, PORTS)[1] == [
        FieldError("url", "host_not_documented")
    ]
    # A base failure is reported first; the channel is not asked.
    assert validate_secrets("webhook", {}, registry, PORTS)[1] == [FieldError("url", "required")]


def test_check_url_respects_the_operator_ports() -> None:
    assert check_url("https://hooks.example.com:8443/x", (443, 8443)) is None


@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("url", "alert.channel.error.invalid_url"),
        ("recipients", "alert.channel.error.invalid_recipients"),
        ("signing_secret", "alert.channel.error.invalid_signing_secret"),
        ("kind", "alert.channel.error.invalid_kind"),
        ("name", "alert.channel.error.invalid_name"),
        ("channel", "alert.channel.error.limit_reached"),
        ("config", "alert.channel.error.invalid_settings"),
        ("anything", "alert.channel.error.invalid_settings"),
    ],
)
def test_field_keys_exist(name: str, key: str) -> None:
    assert field_key(name) == key
    for lang in ("en", "it"):
        assert key in i18n.load_catalogue(lang)


@pytest.fixture
def cipher() -> SecretCipher:
    return SecretCipher(Fernet.generate_key().decode())


def test_seal_and_open_round_trip(cipher: SecretCipher) -> None:
    token, names = seal_secrets(cipher, {"url": SECRET_URL, "signing_secret": SIGNING})
    assert token is not None and SECRET_URL not in token and SIGNING not in token
    assert names == ["signing_secret", "url"]
    assert open_secrets(cipher, token) == {"url": SECRET_URL, "signing_secret": SIGNING}
    assert seal_secrets(cipher, {}) == (None, [])
    assert open_secrets(cipher, None) == {}


@pytest.mark.parametrize(
    "plaintext", ["not json", "[1, 2]", '{"url": 5}', "null", '"text"'], ids=repr
)
def test_open_rejects_malformed_plaintext(cipher: SecretCipher, plaintext: str) -> None:
    with pytest.raises(SecretsError) as info:
        open_secrets(cipher, cipher.encrypt(plaintext))
    assert plaintext not in str(info.value)


@pytest.mark.parametrize("token", ["", "garbage", "gAAAAA" + "x" * 80, "é"], ids=repr)
def test_open_rejects_bad_tokens(cipher: SecretCipher, token: str) -> None:
    with pytest.raises(SecretsError):
        open_secrets(cipher, token)


def test_open_with_another_key_fails(cipher: SecretCipher) -> None:
    token, _ = seal_secrets(cipher, {"url": SECRET_URL})
    with pytest.raises(SecretsError):
        open_secrets(SecretCipher(Fernet.generate_key().decode()), token)


@pytest.mark.parametrize("lang", ["en", "it"])
def test_render_uses_the_language_and_keeps_values_raw(lang: str) -> None:
    hostile = "<b>{x}</b>&@channel"
    message = AlertMessage(
        1, 2, "new_listing", "ALERT_NEW_LISTING", {"subject": hostile, "after": "listed"}, T0
    )
    rendered = render(message, lang, "example.com")
    assert rendered.language == lang and rendered.domain == "example.com"
    assert rendered.title == i18n.t("alert.ALERT_NEW_LISTING.title", lang, subject=hostile)
    assert hostile in rendered.title  # not escaped here: each channel escapes for its format


@pytest.mark.parametrize("lang", ["en", "it"])
def test_test_alert_renders(lang: str) -> None:
    message = AlertMessage(0, 0, "test", "ALERT_TEST", {}, T0)
    rendered = render(message, lang, "")
    assert rendered.title == i18n.t("alert.ALERT_TEST.title", lang)


def test_resolved_channel_repr_hides_secrets() -> None:
    resolved = ResolvedChannel(1, 1, "webhook", "ops", {}, {"url": SECRET_URL})
    assert SECRET_URL not in repr(resolved)


def test_registry_rejects_wrong_kinds_and_non_channels() -> None:
    with pytest.raises(ValueError):
        ChannelRegistry({"sms": FakeChannel(kind="sms")})
    with pytest.raises(ValueError):
        ChannelRegistry({"slack": FakeChannel(kind="webhook")})
    with pytest.raises(TypeError):
        ChannelRegistry({"webhook": types.SimpleNamespace(kind="webhook")})  # type: ignore[dict-item]
    registry = ChannelRegistry({"webhook": FakeChannel()})
    assert registry.kinds == {"webhook"} and registry.get("slack") is None


def test_default_registry_reads_the_channels_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(alert_dispatch.importlib.util, "find_spec", lambda _name: None)
    assert default_registry().kinds == frozenset()
    fake = FakeChannel(kind="slack")
    module = types.SimpleNamespace(CHANNELS={"slack": fake})
    monkeypatch.setattr(alert_dispatch.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(alert_dispatch.importlib, "import_module", lambda _name: module)
    assert default_registry().get("slack") is fake


def test_send_result_codes_are_sanitized() -> None:
    assert SendResult.retryable("http_5xx").code == "http_5xx"
    assert SendResult.permanent("Bad Request: token=abc").code == "invalid_error_code"
    assert SendResult.ok().outcome is SendOutcome.OK


def test_limiter_allows_capacity_per_window_per_channel() -> None:
    clock = FakeClock()
    limiter = TestSendLimiter(clock, capacity=2, window=timedelta(minutes=10))
    assert limiter.try_acquire(1, 1) is None
    assert limiter.try_acquire(1, 1) is None
    wait = limiter.try_acquire(1, 1)
    assert wait == timedelta(minutes=10)
    assert limiter.try_acquire(1, 2) is None  # another channel
    assert limiter.try_acquire(2, 1) is None  # same id, another tenant
    clock.advance(timedelta(minutes=10))
    assert limiter.try_acquire(1, 1) is None


@pytest.mark.parametrize(
    "kw", [{"capacity": 0}, {"capacity": True}, {"window": timedelta(0)}, {"window": 5}]
)
def test_limiter_rejects_bad_settings(kw: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        TestSendLimiter(FakeClock(), **kw)


# --- dispatcher on a database ------------------------------------------------------------------


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@dataclass
class World:
    factory: sessionmaker[Session]
    cipher: SecretCipher
    ctx: TenantContext
    ctx_b: TenantContext
    domain: int
    domain_b: int
    clock: FakeClock = field(default_factory=FakeClock)
    fake: FakeChannel = field(default_factory=FakeChannel)

    def alerts(self, **kw: Any) -> AlertService:
        kw.setdefault("min_realert", timedelta(0))
        return AlertService(self.factory, self.clock, **kw)

    def dispatcher(
        self, registry: ChannelRegistry | None = None, *, alerts: AlertService | None = None,
        **kw: Any,
    ) -> AlertDispatcher:  # fmt: skip
        return AlertDispatcher(
            self.factory,
            alerts or self.alerts(),
            ChannelRegistry({"webhook": self.fake}) if registry is None else registry,
            self.cipher,
            self.clock,
            **kw,
        )

    def channel(
        self, ctx: TenantContext | None = None, name: str = "ops", enabled: bool = True,
        token: str | None = None,
    ) -> int:  # fmt: skip
        sealed, names = seal_secrets(self.cipher, {"url": SECRET_URL, "signing_secret": SIGNING})
        with self.factory.begin() as db:
            return repo_for(ctx or self.ctx, db).alert_channels.create(
                kind="webhook", name=name, enabled=enabled, config={},
                secret_token=token or sealed, secret_fields=names, now=T0,
            ).id  # fmt: skip

    def emit(self, channel_id: int, ctx: TenantContext | None = None, after: str = "x") -> None:
        ctx = ctx or self.ctx
        domain = self.domain if ctx == self.ctx else self.domain_b
        with self.factory.begin() as db:
            repo_for(ctx, db).alert_rules.add("new_listing", channel_id)
        event = ChangeEvent("new_listing", domain, f"zen-{after}.example", None, after, "dnsbl")
        assert self.alerts().emit(ctx, [event]).deliveries >= 1

    def deliveries(self) -> list[tuple[int, str, int, str | None]]:
        with self.factory() as db:
            rows = db.execute(
                select(
                    AlertDelivery.tenant_id,
                    AlertDelivery.status,
                    AlertDelivery.attempts,
                    AlertDelivery.last_error,
                ).order_by(AlertDelivery.id)
            ).all()
            return [tuple(r) for r in rows]  # type: ignore[misc]


@pytest.fixture
def world(engine: Engine, cipher: SecretCipher) -> World:
    factory = create_session_factory(engine)
    with factory.begin() as db:
        ta = Tenant(name="A", slug="a", language="it")
        tb = Tenant(name="B", slug="b")
        db.add_all([ta, tb])
        db.flush()
        ctx, ctx_b = TenantContext(ta.id, None), TenantContext(tb.id, None)
        domain = repo_for(ctx, db).domains.create("a.example").id
        domain_b = repo_for(ctx_b, db).domains.create("b.example").id
    return World(factory, cipher, ctx, ctx_b, domain, domain_b)


def test_delivery_ok_renders_in_tenant_language_with_decrypted_secrets(world: World) -> None:
    cid = world.channel()
    world.emit(cid)
    report = asyncio.run(world.dispatcher().run_once())
    assert report.sent == 1
    assert world.deliveries() == [(world.ctx.tenant_id, "sent", 1, None)]
    alert, rendered, resolved = world.fake.calls[0]
    assert alert.code == "ALERT_NEW_LISTING"
    assert rendered.language == "it" and rendered.domain == "a.example"
    assert rendered.title == i18n.t("alert.ALERT_NEW_LISTING.title", "it", subject="zen-x.example")
    assert resolved.secrets == {"url": SECRET_URL, "signing_secret": SIGNING}
    assert (resolved.id, resolved.tenant_id, resolved.kind) == (cid, world.ctx.tenant_id, "webhook")


FAILURES = [
    ("retryable", {"result": SendResult.retryable("http_5xx")}, "http_5xx"),
    ("permanent", {"result": SendResult.permanent("http_4xx")}, "http_4xx"),
    ("exception", {"exc": RuntimeError(SECRET_URL)}, "internal_error"),
    ("not a result", {"result": "ok"}, "invalid_result"),
    ("config invalid", {"secret_errors": [FieldError("url", "x")]}, "config_invalid"),
]


@pytest.mark.parametrize(("label", "setup", "code"), FAILURES, ids=[f[0] for f in FAILURES])
def test_failures_become_failed_attempts_with_backoff(
    world: World, caplog: pytest.LogCaptureFixture, label: str, setup: dict[str, Any], code: str
) -> None:
    for name, value in setup.items():
        setattr(world.fake, name, value)
    world.emit(world.channel())
    with caplog.at_level(logging.DEBUG):
        report = asyncio.run(world.dispatcher().run_once())
    assert report.failed == 1
    assert world.deliveries() == [(world.ctx.tenant_id, "failed", 1, code)]
    assert SECRET_URL not in caplog.text and SIGNING not in caplog.text
    # Backoff from M7-14: not due again until base delay passed.
    assert asyncio.run(world.dispatcher().run_once()).failed == 0
    world.clock.advance(timedelta(minutes=1))
    assert asyncio.run(world.dispatcher().run_once()).failed == 1
    assert world.deliveries()[0][2] == 2


def test_attempts_end_abandoned(world: World) -> None:
    world.fake.result = SendResult.permanent("http_4xx")
    world.emit(world.channel())
    dispatcher = world.dispatcher(alerts=world.alerts(max_attempts=2))
    asyncio.run(dispatcher.run_once())
    world.clock.advance(timedelta(hours=1))
    assert asyncio.run(dispatcher.run_once()).abandoned == 1
    assert world.deliveries() == [(world.ctx.tenant_id, "abandoned", 2, "http_4xx")]


def test_channel_exception_does_not_stop_the_next_delivery(world: World) -> None:
    cid = world.channel()
    world.emit(cid, after="one")
    world.emit(cid, after="two")
    outcomes = iter([RuntimeError("boom"), None])

    def on_send() -> None:
        world.fake.exc = next(outcomes)

    world.fake.on_send = on_send
    report = asyncio.run(world.dispatcher().run_once())
    assert (report.failed, report.sent) == (1, 1)


def test_unusable_channels(world: World, caplog: pytest.LogCaptureFixture) -> None:
    disabled = world.channel(name="off", enabled=False)
    foreign_key = SecretCipher(Fernet.generate_key().decode())
    unreadable = world.channel(name="bad", token=seal_secrets(foreign_key, {"url": SECRET_URL})[0])
    for channel in (disabled, unreadable):
        with world.factory.begin() as db:
            repo_for(world.ctx, db).alert_rules.add("new_listing", channel)
    world.emit(999_999)  # plus a rule to a channel that does not exist: one alert, 3 deliveries
    with caplog.at_level(logging.DEBUG):
        asyncio.run(world.dispatcher().run_once())
    codes = sorted(d[3] or "" for d in world.deliveries())
    assert codes == ["channel_disabled", "channel_missing", "secret_unreadable"]
    assert world.fake.calls == []
    assert SECRET_URL not in caplog.text


def test_unregistered_kind(world: World) -> None:
    world.emit(world.channel())
    asyncio.run(world.dispatcher(ChannelRegistry()).run_once())
    assert world.deliveries()[0][3] == "channel_unavailable"


def test_send_timeout_is_m7_14s(world: World) -> None:
    world.fake.hang = True
    world.emit(world.channel())
    alerts = world.alerts(send_timeout=timedelta(milliseconds=50))
    asyncio.run(world.dispatcher(alerts=alerts).run_once())
    assert world.deliveries()[0][1:] == ("failed", 1, "timeout")


def test_run_once_covers_every_tenant_and_survives_one_failing(
    world: World, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.emit(world.channel())
    world.emit(world.channel(world.ctx_b), world.ctx_b)
    assert asyncio.run(world.dispatcher().run_once()).sent == 2
    world.emit(world.channel(name="second"), after="y")
    world.emit(world.channel(world.ctx_b, name="second"), world.ctx_b, after="y")
    alerts = world.alerts()
    original = alerts.deliver_due

    async def flaky(ctx: TenantContext, send: Any, *, limit: int = 50) -> Any:
        if ctx == world.ctx:
            raise RuntimeError("db down")
        return await original(ctx, send, limit=limit)

    monkeypatch.setattr(alerts, "deliver_due", flaky)
    with caplog.at_level(logging.ERROR):
        report = asyncio.run(world.dispatcher(alerts=alerts).run_once())
    assert report.sent == 2  # tenant B's new alert goes to both of its channels
    pending = [d for d in world.deliveries() if d[1] == "pending"]
    assert pending and {d[0] for d in pending} == {world.ctx.tenant_id}
    assert "RuntimeError" in caplog.text


def test_run_stops_on_event_and_survives_a_failed_pass(world: World) -> None:
    world.emit(world.channel())
    dispatcher = world.dispatcher(poll_interval=timedelta(milliseconds=10))
    stop = asyncio.Event()
    calls = 0
    original = dispatcher.run_once

    async def run_once() -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("transient")
        report = await original()
        stop.set()
        return report

    dispatcher.run_once = run_once  # type: ignore[method-assign]
    asyncio.run(asyncio.wait_for(dispatcher.run(stop), 5))
    assert calls == 2
    assert world.deliveries()[0][1] == "sent"


def test_run_is_cancelled_cleanly(world: World) -> None:
    started = asyncio.Event()

    async def sleep(_seconds: float) -> None:
        started.set()
        await asyncio.Event().wait()

    async def scenario() -> None:
        task = asyncio.create_task(world.dispatcher(sleep=sleep).run())
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "kw",
    [
        {"poll_interval": timedelta(0)},
        {"test_timeout": 5},
        {"tenant_batch": 0},
        {"delivery_batch": 1001},
        {"tenant_batch": True},
    ],
)
def test_dispatcher_rejects_bad_settings(world: World, kw: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        world.dispatcher(**kw)


# --- test send ---------------------------------------------------------------------------------


def test_send_test_outcomes(world: World, caplog: pytest.LogCaptureFixture) -> None:
    cid = world.channel(enabled=False)  # a disabled channel can still be tested
    dispatcher = world.dispatcher(test_timeout=timedelta(milliseconds=50))
    result = asyncio.run(dispatcher.send_test(world.ctx, cid))
    assert result == SendResult.ok()
    alert, rendered, resolved = world.fake.calls[0]
    assert alert.code == "ALERT_TEST" and rendered.language == "it"
    assert resolved.secrets["url"] == SECRET_URL
    world.fake.result = SendResult.permanent("http_4xx")
    assert asyncio.run(dispatcher.send_test(world.ctx, cid)) == SendResult.permanent("http_4xx")
    world.fake.exc = RuntimeError(SECRET_URL)
    with caplog.at_level(logging.DEBUG):
        assert asyncio.run(dispatcher.send_test(world.ctx, cid)) == SendResult.retryable(
            "internal_error"
        )
    assert SECRET_URL not in caplog.text
    world.fake.exc, world.fake.hang = None, True
    assert asyncio.run(dispatcher.send_test(world.ctx, cid)) == SendResult.retryable("timeout")
    world.fake.hang, world.fake.result = False, "bogus"
    assert asyncio.run(dispatcher.send_test(world.ctx, cid)) == SendResult.permanent(
        "invalid_result"
    )
    assert world.deliveries() == []  # a test send records nothing


def test_send_test_missing_foreign_or_unavailable(world: World) -> None:
    cid = world.channel()
    dispatcher = world.dispatcher()
    assert asyncio.run(dispatcher.send_test(world.ctx_b, cid)) is None
    assert asyncio.run(dispatcher.send_test(world.ctx, 999_999)) is None
    unavailable = world.dispatcher(ChannelRegistry())
    assert asyncio.run(unavailable.send_test(world.ctx, cid)) == SendResult.permanent(
        "channel_unavailable"
    )
    with pytest.raises(TypeError):
        asyncio.run(dispatcher.send_test(world.ctx.tenant_id, cid))  # type: ignore[arg-type]
