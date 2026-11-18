"""Email alert channel (M7-16): fake transport, no network."""

from __future__ import annotations

import contextlib
import smtplib
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any

import pytest

from app.core.config import ConfigError, Settings
from app.services.alert_channels import CHANNELS
from app.services.alert_channels.email import (
    MAX_SUBJECT,
    AuthUnavailable,
    EmailChannel,
    SmtpSettings,
    TlsRefused,
    build_message,
    map_exception,
    smtp_transport,
)
from app.services.alert_dispatch import (
    DEFAULT_TEST_TIMEOUT,
    TEST_CODE,
    TEST_KIND,
    FieldError,
    SendOutcome,
    SendResult,
    default_registry,
    render,
)
from app.services.alerts import AlertMessage

KEY = "k" * 40
NOW = datetime(2026, 11, 18, tzinfo=UTC)


def settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "secret_key": KEY,
        "encryption_key": KEY,
        "smtp_host": "relay.internal",
        "smtp_from": "alerts@example.com",
        "base_url": "https://dt.example.com/",
    }
    return Settings(**{**base, **kw})  # type: ignore[arg-type]


class Fake:
    def __init__(self, exc: BaseException | None = None) -> None:
        self.exc = exc
        self.calls: list[tuple[SmtpSettings, EmailMessage, list[str]]] = []

    def __call__(self, cfg: SmtpSettings, msg: EmailMessage, rcpt: list[str]) -> None:
        self.calls.append((cfg, msg, rcpt))
        if self.exc is not None:
            raise self.exc


def alert(params: dict[str, str] | None = None, domain_id: int = 7) -> AlertMessage:
    return AlertMessage(1, domain_id, "dnsbl", "ALERT_NEW_LISTING", params or {"subject": "x"}, NOW)


def channel_of(recipients: Any) -> Any:
    from app.services.alert_dispatch import ResolvedChannel

    return ResolvedChannel(1, 1, "email", "n", {"recipients": recipients}, {})


async def send(
    fake: Fake,
    *,
    cfg: Settings | None = None,
    message: AlertMessage | None = None,
    domain: str = "example.org",
    lang: str = "en",
    recipients: Any = None,
) -> SendResult:
    ch = EmailChannel(lambda: cfg or settings(), fake)
    msg = message or alert()
    rendered = render(msg, lang, domain)
    return await ch.send(
        msg, rendered, channel_of(recipients if recipients is not None else ["ops@example.com"])
    )


def _wrapped(exc: BaseException, inner: BaseException, *, cause: bool = False) -> BaseException:
    """`exc` as smtplib raises it inside `except inner` (context) or `from inner` (cause)."""
    if cause:
        exc.__cause__ = inner
    else:
        exc.__context__ = inner
    return exc


# --- results -------------------------------------------------------------------------------------


async def test_success_sends_one_message() -> None:
    fake = Fake()
    assert await send(fake, recipients=["a@example.com", "b@example.com"]) == SendResult.ok()
    cfg, msg, rcpt = fake.calls[0]
    assert rcpt == ["a@example.com", "b@example.com"]
    assert cfg.sender == "alerts@example.com" and cfg.security == "starttls" and cfg.port == 587
    assert msg["From"] == "alerts@example.com"
    assert msg.is_multipart() and msg.get_body(("plain",)) and msg.get_body(("html",))
    assert "https://dt.example.com/domains/7/monitoring" in msg.get_body(("plain",)).get_content()  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("exc", "outcome", "code"),
    [
        (smtplib.SMTPResponseException(451, b"try later"), SendOutcome.RETRYABLE, "smtp_4xx"),
        (smtplib.SMTPResponseException(421, b"closing"), SendOutcome.RETRYABLE, "smtp_4xx"),
        (smtplib.SMTPResponseException(550, b"no"), SendOutcome.PERMANENT, "smtp_5xx"),
        (smtplib.SMTPAuthenticationError(535, b"bad login"), SendOutcome.PERMANENT, "smtp_5xx"),
        (smtplib.SMTPRecipientsRefused({"a@b.c": (550, b"x")}), SendOutcome.PERMANENT, "smtp_5xx"),
        (smtplib.SMTPRecipientsRefused({"a@b.c": (450, b"x")}), SendOutcome.RETRYABLE, "smtp_4xx"),
        (smtplib.SMTPResponseException(399, b"odd"), SendOutcome.RETRYABLE, "smtp_error"),
        (TimeoutError(), SendOutcome.RETRYABLE, "timeout"),
        (ssl.SSLError("handshake"), SendOutcome.RETRYABLE, "tls_error"),
        (ssl.SSLCertVerificationError("cert"), SendOutcome.RETRYABLE, "tls_error"),
        (smtplib.SMTPNotSupportedError("no starttls"), SendOutcome.RETRYABLE, "tls_error"),
        (TlsRefused(), SendOutcome.RETRYABLE, "tls_error"),
        (AuthUnavailable(), SendOutcome.PERMANENT, "auth_unsupported"),
        (_wrapped(smtplib.SMTPServerDisconnected("closed"), TimeoutError()), SendOutcome.RETRYABLE,
         "timeout"),
        (_wrapped(smtplib.SMTPServerDisconnected("closed"), TimeoutError(), cause=True),
         SendOutcome.RETRYABLE, "timeout"),
        (_wrapped(smtplib.SMTPServerDisconnected("closed"), ConnectionResetError()),
         SendOutcome.RETRYABLE, "connect_error"),
        (ConnectionRefusedError(), SendOutcome.RETRYABLE, "connect_error"),
        (smtplib.SMTPServerDisconnected("gone"), SendOutcome.RETRYABLE, "connect_error"),
        (OSError("unreachable"), SendOutcome.RETRYABLE, "connect_error"),
        (smtplib.SMTPException("other"), SendOutcome.RETRYABLE, "connect_error"),
    ],
)  # fmt: skip
async def test_result_mapping(exc: BaseException, outcome: SendOutcome, code: str) -> None:
    result = await send(Fake(exc))
    assert (result.outcome, result.code) == (outcome, code)


async def test_unexpected_exception_propagates_to_the_dispatcher() -> None:
    with pytest.raises(ZeroDivisionError):
        await send(Fake(ZeroDivisionError()))
    with pytest.raises(ZeroDivisionError):
        map_exception(ZeroDivisionError())


@pytest.mark.parametrize("kw", [{"smtp_host": ""}])
async def test_missing_settings_are_permanent_not_configured(kw: dict[str, str]) -> None:
    fake = Fake()
    result = await send(fake, cfg=settings(**kw))
    assert result == SendResult.permanent("not_configured")
    assert not fake.calls


BAD_SEND = [
    [r]
    for r in (
        "x@[10.0.0.5]",
        "x@localhost",
        "@relay.example:v@x.example",
        "v%evil.example@relay.example",
        "a@b@c.example",
        '"q"@b.example',
    )
]


async def test_bad_recipients_never_reach_the_transport() -> None:
    fake = Fake()
    for bad in ([], "a@b.c", ["a@b.c\r\nBcc: x@y.z"], ["a@b.c,d@e.f"], ["é@b.c"], [1], *BAD_SEND):
        result = await send(fake, recipients=bad)  # type: ignore[arg-type]
        assert result == SendResult.permanent("config_invalid"), bad
    assert not fake.calls


async def test_timeout_budget_stays_inside_the_send_timeout() -> None:
    fake = Fake()
    await send(fake, cfg=settings(alert_send_timeout_seconds=10, alert_lease_seconds=60))
    assert 0 < fake.calls[0][0].budget < 10
    assert "password" not in repr(fake.calls[0][0]).lower()


@pytest.mark.parametrize(
    ("send_timeout", "budget"),
    [(10, 8.0), (DEFAULT_TEST_TIMEOUT.total_seconds(), DEFAULT_TEST_TIMEOUT.total_seconds() * 0.8),
     (600, DEFAULT_TEST_TIMEOUT.total_seconds() * 0.8)],
)  # fmt: skip
async def test_test_send_budget_stays_inside_the_test_wait(
    send_timeout: int, budget: float
) -> None:
    fake = Fake()
    test = AlertMessage(0, 0, TEST_KIND, TEST_CODE, {}, NOW)
    cfg = settings(alert_send_timeout_seconds=send_timeout, alert_lease_seconds=3600)
    await send(fake, cfg=cfg, message=test)
    assert fake.calls[0][0].budget == pytest.approx(budget)
    assert fake.calls[0][0].budget < DEFAULT_TEST_TIMEOUT.total_seconds()
    fake = Fake()
    await send(fake, cfg=cfg)  # a real alert keeps the full send budget
    assert fake.calls[0][0].budget == pytest.approx(send_timeout * 0.8)


async def test_slow_transport_is_left_to_the_dispatcher_timeout() -> None:
    # The channel itself does not swallow a hung transport: the dispatcher's wait_for cancels it.
    import asyncio

    def slow(cfg: SmtpSettings, msg: EmailMessage, rcpt: list[str]) -> None:
        time.sleep(0.3)

    ch = EmailChannel(lambda: settings(), slow)
    msg = alert()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            ch.send(msg, render(msg, "en", "d.example"), channel_of(["a@example.com"])), 0.05
        )


# --- message safety ------------------------------------------------------------------------------

INJECTIONS = [
    "evil.example\r\nBcc: victim@example.net",
    "evil.example\nSubject: pwned",
    "a b c\x00d",
    "<script>alert(1)</script>.example",
    '"><img src=x onerror=alert(1)>',
    "x" * 5000,
]


@pytest.mark.parametrize("evil", INJECTIONS)
@pytest.mark.parametrize("lang", ["en", "it"])
async def test_injection_in_domain_and_params(evil: str, lang: str) -> None:
    fake = Fake()
    message = alert({"subject": evil, "before": evil, "after": evil})
    result = await send(fake, message=message, domain=evil, lang=lang)
    assert result.outcome is SendOutcome.OK
    msg = fake.calls[0][1]
    assert set(msg.keys()) == {
        "Content-Type",
        "MIME-Version",
        "From",
        "To",
        "Subject",
        "Date",
        "Message-ID",
        "Auto-Submitted",
    }
    for name, value in msg.items():
        assert "\r" not in str(value) and "\n" not in str(value).replace("\r\n ", ""), name
    assert len(str(msg["Subject"]).replace("\r\n ", "")) < 400
    head = msg.as_bytes().decode("utf-8", "replace").split("\r\n\r\n", 1)[0]
    names = [x.split(":")[0] for x in head.split("\r\n") if x and x[0] not in " \t"]
    assert sorted(names) == sorted(set(names)) and "Bcc" not in names
    html_part = msg.get_body(("html",)).get_content()  # type: ignore[union-attr]
    assert "<script>" not in html_part and "<img" not in html_part
    assert '"><' not in html_part


def test_subject_is_capped_and_one_line() -> None:
    msg = alert({"subject": "s" * 1000})
    rendered = render(msg, "en", "d.example")
    built = build_message(msg, rendered, ["a@example.com"], "alerts@example.com", "https://x")
    subject = str(built["Subject"]).replace("\r\n ", "")
    assert len(subject) <= MAX_SUBJECT
    assert "\n" not in subject


def test_html_is_escaped_and_text_in_the_tenant_language() -> None:
    msg = alert({"subject": "<b>x</b>"})
    for lang, marker in (("en", "Domain: "), ("it", "Dominio: ")):
        built = build_message(
            msg,
            render(msg, lang, "a&b.example"),
            ["a@example.com"],
            "alerts@example.com",
            "https://x",
        )
        plain = built.get_body(("plain",)).get_content()  # type: ignore[union-attr]
        html_part = built.get_body(("html",)).get_content()  # type: ignore[union-attr]
        assert marker + "a&b.example" in plain
        assert marker + "a&amp;b.example" in html_part
        assert "&lt;b&gt;x&lt;/b&gt;" in html_part and "<b>x" not in html_part


def test_link_without_a_domain_is_the_base_url() -> None:
    msg = alert(domain_id=0)
    built = build_message(
        msg, render(msg, "en", ""), ["a@example.com"], "alerts@example.com", "https://x.example/"
    )
    plain = built.get_body(("plain",)).get_content()  # type: ignore[union-attr]
    assert "Details: https://x.example\n" in plain and "Domain:" not in plain


# --- validation, registry, settings --------------------------------------------------------------

VALID_RECIPIENTS = [
    "ops@example.com",
    "first.last+tag@mail.example.co.uk",
    "o_p-s@xn--bcher-kva.example",
    "a@b.c",
    "x=y&z#1@example.org",
]
INVALID_RECIPIENTS = ["x@[10.0.0.5]", "x@10.0.0.5", "x@localhost", "x@ipv6:::1", "x@[ipv6:::1]",
                      "@relay.example:v@x.example", "v%evil.example@relay.example", "a@b@c.example",
                      "a(c)@b.example", "a@b.example(c)", '"q"@b.example', "a..b@example.com",
                      ".a@example.com", "a.@example.com", "a!b@example.com", "a|b@example.com",
                      "a/b@example.com", "a@example.com.", "a@-x.example", "a@x_y.example",
                      "a@bücher.example", "a@b.123", "x" * 65 + "@example.com", "a@", "@b.example",
                      "a b@example.com", "a@example..com"]  # fmt: skip


@pytest.mark.parametrize(
    ("config", "ok"),
    [
        ({"recipients": ["a@example.com"]}, True),
        ({"recipients": []}, False),
        ({"recipients": ["A@example.com"]}, False),
        ({"recipients": ["a@example.com", "a@example.com"]}, False),
        ({"recipients": ["a@example.com\n"]}, False),
        ({"recipients": ["é@example.com"]}, False),
        ({"recipients": [None]}, False),
        ({"recipients": ["a@b.c"] * 11}, False),
        ({}, False),
        ({"recipients": "a@example.com"}, False),
        *[({"recipients": [r]}, True) for r in VALID_RECIPIENTS],
        *[({"recipients": [r]}, False) for r in INVALID_RECIPIENTS],
    ],
)
def test_validate_config(config: dict[str, Any], ok: bool) -> None:
    errors = EmailChannel(settings).validate_config(config)
    assert (errors == []) is ok
    assert all(isinstance(e, FieldError) and e.field == "recipients" for e in errors)


def test_registered_under_email() -> None:
    assert isinstance(CHANNELS["email"], EmailChannel)
    assert default_registry().get("email") is CHANNELS["email"]


@pytest.mark.parametrize(
    "kw",
    [
        {"smtp_from": "no-at-sign"},
        {"smtp_from": "a@b.c\r\nBcc: x@y.z"},
        {"smtp_host": "bad host"},
        {"smtp_host": "h\r\nx"},
        {"smtp_username": "u"},
        {"smtp_password": "p"},
        {"smtp_username": "u", "smtp_password": "p", "smtp_security": "none"},
        {"smtp_username": "u\n", "smtp_password": "p"},
        {"smtp_username": "usér", "smtp_password": "p"},
        {"smtp_username": "u", "smtp_password": "pässword"},
        {"smtp_username": "u", "smtp_password": "p\x7f"},
        {"smtp_username": "u", "smtp_password": "p\tq"},
        {"smtp_username": "u\u200b", "smtp_password": "p"},
        {"smtp_security": "ssl"},
        {"smtp_port": 0},
        {"smtp_port": 70000},
    ],
)
def test_bad_smtp_settings_stop_startup(kw: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        settings(**kw)


def test_good_smtp_settings_and_password_is_masked() -> None:
    cfg = settings(
        smtp_username="u", smtp_password="s3cret-pass", smtp_security="TLS", smtp_port=465
    )
    assert cfg.smtp_security == "tls"
    assert "s3cret-pass" not in repr(cfg) and "s3cret-pass" not in str(cfg)
    assert settings(smtp_host="", smtp_from="").smtp_host == ""
    assert settings(smtp_username="u@x", smtp_password=" !~pass word~! ").smtp_username == "u@x"


# --- real transport against a loopback fake server (no external network) ------------------------

Script = Callable[[socket.socket, list[str], threading.Event], None]


@contextlib.contextmanager
def loopback(script: Script) -> Iterator[tuple[int, list[str]]]:
    """A one-connection server on 127.0.0.1 running `script`; yields (port, received lines)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    done = threading.Event()
    lines: list[str] = []

    def run() -> None:
        with contextlib.suppress(OSError):
            conn, _ = server.accept()
            with conn:
                conn.settimeout(5)
                script(conn, lines, done)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1], lines
    finally:
        done.set()
        server.close()
        thread.join(5)


def silent(conn: socket.socket, lines: list[str], done: threading.Event) -> None:
    done.wait(5)  # accepts, never sends the banner


def no_starttls(advertise: bool) -> Script:
    def script(conn: socket.socket, lines: list[str], done: threading.Event) -> None:
        conn.sendall(b"220 fake ESMTP\r\n")
        reader = conn.makefile("rb")
        while not done.is_set():
            raw = reader.readline()
            if not raw:
                return
            line = raw.decode("ascii").strip()
            lines.append(line)
            verb = line.split(" ", 1)[0].upper()
            if verb == "EHLO":
                conn.sendall(b"250-fake\r\n250 STARTTLS\r\n" if advertise else b"250 fake\r\n")
            elif verb == "STARTTLS":
                conn.sendall(b"454 4.7.0 TLS not available\r\n")
            else:
                conn.sendall(b"221 bye\r\n")
                return

    return script


def relay(port: int, budget: float = 0.5) -> SmtpSettings:
    return SmtpSettings("127.0.0.1", port, "starttls", "", "", "alerts@example.com", budget)


def message() -> EmailMessage:
    msg = alert()
    return build_message(
        msg, render(msg, "en", "d.example"), ["a@example.com"], "alerts@example.com", "https://x"
    )


def test_real_transport_silent_server_is_timeout() -> None:
    with loopback(silent) as (port, _):
        started = time.monotonic()
        with pytest.raises(smtplib.SMTPServerDisconnected) as caught:
            smtp_transport(relay(port), message(), ["a@example.com"])
        elapsed = time.monotonic() - started
    assert map_exception(caught.value) == SendResult.retryable("timeout")
    assert elapsed < 3


@pytest.mark.parametrize("advertise", [False, True], ids=["not_offered", "refused_454"])
def test_real_transport_starttls_refused_is_tls_error(advertise: bool) -> None:
    with (
        loopback(no_starttls(advertise)) as (port, lines),
        pytest.raises(smtplib.SMTPException) as caught,
    ):
        smtp_transport(relay(port, 2.0), message(), ["a@example.com"])
    assert map_exception(caught.value) == SendResult.retryable("tls_error")
    assert lines[0].upper() == "EHLO EXAMPLE.COM"  # the domain of SMTP_FROM, no getfqdn()
    assert not any(line.upper().startswith(("MAIL", "RCPT", "DATA")) for line in lines)


def test_real_transport_login_without_auth_is_auth_unsupported() -> None:
    cfg = SmtpSettings("127.0.0.1", 0, "none", "u", "p", "alerts@example.com", 2.0)
    with loopback(no_starttls(False)) as (port, lines), pytest.raises(AuthUnavailable) as caught:
        smtp_transport(replace(cfg, port=port), message(), ["a@example.com"])
    assert map_exception(caught.value) == SendResult.permanent("auth_unsupported")
    assert not any(line.upper().startswith(("AUTH", "MAIL")) for line in lines)
