"""Alert channel `email` (M7-16). Design: ARCHITECTURE sections 6 and 9.

The channel config holds only the recipient addresses. The relay (SMTP_HOST, SMTP_PORT,
SMTP_SECURITY, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM) is operator configuration. Decision
record: that relay is trusted operator infrastructure, may be private, and does not go through
the guarded client (the guarded SMTP client is for SMTP checks, M9). A recipient address is only
ever put in the message envelope, never used as a connection target.

Result mapping (stable codes): no relay configured -> permanent `not_configured`; connection
failure, 4xx, disconnect -> retryable `connect_error` / `smtp_4xx`; timeout (also a read timeout
that smtplib reports as a disconnect) -> retryable `timeout`; TLS failure, STARTTLS not offered or
refused -> retryable `tls_error`; SMTP_USERNAME set but the relay offers no AUTH -> permanent
`auth_unsupported`; 5xx (including a refused login or recipient) -> permanent `smtp_5xx`.

Timeout. The whole exchange gets `SEND_BUDGET` (0.8) of ALERT_SEND_TIMEOUT_SECONDS, which
Settings keeps below the delivery lease; a test send gets 0.8 of min(that, the dispatcher's
DEFAULT_TEST_TIMEOUT), so a test never reports `timeout` while the thread still delivers. Every
socket read and write runs under the time left of that budget. EHLO uses the domain of SMTP_FROM
(no `getfqdn()` lookup). Name resolution of the relay host is the one step the standard library
cannot bound; the dispatcher stops waiting at the send timeout regardless.

Safety. No header value can carry CR/LF (control characters are replaced, the subject is capped
at 150 characters, recipients are re-checked, and `email.message.EmailMessage` with the SMTP
policy refuses a header with a line break). Values from domains and params are escaped in the
HTML part. Texts come from i18n keys `alert.email.*`.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import smtplib
import ssl
import time
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import formatdate, make_msgid
from functools import lru_cache
from typing import Any, Final

from app.core.config import Settings
from app.core.i18n import t
from app.services.alert_dispatch import (
    DEFAULT_TEST_TIMEOUT,
    TEST_KIND,
    FieldError,
    RenderedAlert,
    ResolvedChannel,
    SendResult,
    validate_recipients,
)
from app.services.alerts import AlertMessage

KIND: Final = "email"
SEND_BUDGET: Final = 0.8
MAX_SUBJECT: Final = 150
NOT_CONFIGURED: Final = "not_configured"
AUTH_UNSUPPORTED: Final = "auth_unsupported"
_REMOVED = frozenset({"Cc", "Cf", "Zl", "Zp"})


@dataclass(frozen=True, slots=True)
class SmtpSettings:
    """The relay settings of one send. repr hides the password."""

    host: str
    port: int
    security: str
    username: str
    password: str
    sender: str
    budget: float

    def __repr__(self) -> str:
        return f"SmtpSettings(host={self.host!r}, port={self.port}, security={self.security!r})"


class TlsRefused(smtplib.SMTPException):
    """The relay answered STARTTLS with an error reply (454, 501, ...)."""


class AuthUnavailable(smtplib.SMTPException):
    """SMTP_USERNAME is set but the relay offers no AUTH (after STARTTLS if configured)."""


# (relay, message, envelope recipients) -> None; raises what smtplib/ssl/socket raise.
Transport = Callable[[SmtpSettings, EmailMessage, list[str]], None]


class _Clock:
    def __init__(self, budget: float) -> None:
        self._end = time.monotonic() + budget

    def left(self) -> float:
        remaining = self._end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("smtp budget exhausted")
        return remaining


def _arm(client: Any, clock: _Clock) -> None:
    sock = getattr(client, "sock", None)
    if sock is not None:
        sock.settimeout(clock.left())


class _Smtp(smtplib.SMTP):
    def __init__(self, host: str, port: int, clock: _Clock, third: float, helo: str) -> None:
        self._clock = clock
        super().__init__(host, port, local_hostname=helo, timeout=third)

    def send(self, s: Any) -> None:
        _arm(self, self._clock)
        super().send(s)

    def getreply(self) -> tuple[int, bytes]:
        _arm(self, self._clock)
        return super().getreply()


class _SmtpSsl(smtplib.SMTP_SSL):
    def __init__(
        self,
        host: str,
        port: int,
        clock: _Clock,
        third: float,
        helo: str,
        context: ssl.SSLContext,
    ) -> None:
        self._clock = clock
        super().__init__(host, port, local_hostname=helo, timeout=third, context=context)

    def send(self, s: Any) -> None:
        _arm(self, self._clock)
        super().send(s)

    def getreply(self) -> tuple[int, bytes]:
        _arm(self, self._clock)
        return super().getreply()


def smtp_transport(cfg: SmtpSettings, message: EmailMessage, recipients: list[str]) -> None:
    """Deliver through the operator's relay (blocking; run it in a thread).

    EHLO names the domain of SMTP_FROM (`local_hostname`), so smtplib never calls
    `socket.getfqdn()` (an unbounded lookup) and the container host name is not sent."""
    clock = _Clock(cfg.budget)
    helo = cfg.sender.rpartition("@")[2]
    third = max(cfg.budget / 3, 0.1)  # connect, TLS handshake and banner each stay within it
    context = ssl.create_default_context()
    client: smtplib.SMTP
    if cfg.security == "tls":
        client = _SmtpSsl(cfg.host, cfg.port, clock, third, helo, context)
    else:
        client = _Smtp(cfg.host, cfg.port, clock, third, helo)
    try:
        client.ehlo()
        if cfg.security == "starttls":
            try:
                client.starttls(context=context)
            except smtplib.SMTPResponseException as exc:
                raise TlsRefused from exc
            client.ehlo()
        if cfg.username:
            try:
                client.login(cfg.username, cfg.password)
            except smtplib.SMTPNotSupportedError as exc:
                raise AuthUnavailable from exc  # the relay offers no AUTH: a settings problem
        client.send_message(message, from_addr=cfg.sender, to_addrs=recipients)
        with contextlib.suppress(smtplib.SMTPException, OSError):
            client.quit()  # the message was accepted already
    finally:
        client.close()


@lru_cache(maxsize=1)
def _env_settings() -> Settings:
    return Settings()  # the required keys come from the environment


# --- message -----------------------------------------------------------------------------------


def _line(value: str) -> str:
    """One line without control or format characters (CR, LF, bidi marks, ...)."""
    cleaned = "".join(" " if unicodedata.category(c) in _REMOVED else c for c in value)
    return " ".join(cleaned.split())


def _text(value: str) -> str:
    """Multi-line text: line breaks kept, other control characters dropped."""
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(c for c in value if c in "\n\t" or unicodedata.category(c) not in _REMOVED)


def _subject(rendered: RenderedAlert) -> str:
    subject = _line(t("alert.email.subject", rendered.language, title=_line(rendered.title)))
    return subject if len(subject) <= MAX_SUBJECT else subject[: MAX_SUBJECT - 3] + "..."


def _link(base_url: str, alert: AlertMessage) -> str:
    base = base_url.rstrip("/")
    return f"{base}/domains/{alert.domain_id}/monitoring" if alert.domain_id > 0 else base


def build_message(
    alert: AlertMessage,
    rendered: RenderedAlert,
    recipients: list[str],
    sender: str,
    base_url: str,
) -> EmailMessage:
    lang = rendered.language
    title, detail, domain = _text(rendered.title), _text(rendered.detail), _line(rendered.domain)
    link = _link(base_url, alert)
    intro = t("alert.email.intro", lang)
    footer = t("alert.email.footer", lang)
    domain_line = t("alert.email.domain", lang, domain=domain) if domain else ""
    link_line = t("alert.email.link", lang, url=link)

    plain = [title, "", intro, detail]
    plain += [domain_line] if domain_line else []
    plain += [link_line, "", "-- ", footer]
    esc = html.escape
    body = [f"<h2>{esc(title)}</h2>", f"<p>{esc(intro)}</p>", f"<p>{esc(detail)}</p>"]
    body += [f"<p>{esc(domain_line)}</p>"] if domain_line else []
    body += [
        f'<p><a href="{esc(link)}">{esc(link_line)}</a></p>',
        f"<hr><p><small>{esc(footer)}</small></p>",
    ]

    message = EmailMessage(policy=SMTP_POLICY)
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = _subject(rendered)
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=sender.rpartition("@")[2])
    message["Auto-Submitted"] = "auto-generated"
    message.set_content("\n".join(plain))
    message.add_alternative("<html><body>" + "".join(body) + "</body></html>", subtype="html")
    return message


# --- result mapping ----------------------------------------------------------------------------


def _timed_out(exc: BaseException) -> bool:
    """A timeout, also when smtplib re-raised it as SMTPServerDisconnected (a read that timed out
    closes the connection; the TimeoutError is kept as `__cause__` or `__context__`)."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, TimeoutError):  # socket.timeout is TimeoutError since 3.10
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def map_exception(exc: BaseException) -> SendResult:
    """The send result for an exception of the transport (never its message)."""
    if isinstance(exc, AuthUnavailable):
        return SendResult.permanent(AUTH_UNSUPPORTED)
    if _timed_out(exc):
        return SendResult.retryable("timeout")
    if isinstance(exc, ssl.SSLError | smtplib.SMTPNotSupportedError | TlsRefused):
        return SendResult.retryable("tls_error")
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        codes = [c for c, _ in exc.recipients.values()]
        return _by_code(max(codes, default=0))
    if isinstance(exc, smtplib.SMTPResponseException):
        return _by_code(exc.smtp_code)
    if isinstance(exc, smtplib.SMTPException | OSError):
        return SendResult.retryable("connect_error")
    raise exc


def _by_code(code: int) -> SendResult:
    if 500 <= code <= 599:
        return SendResult.permanent("smtp_5xx")
    return SendResult.retryable("smtp_4xx" if 400 <= code <= 499 else "smtp_error")


# --- channel -----------------------------------------------------------------------------------


class EmailChannel:
    kind = KIND

    def __init__(
        self,
        settings: Callable[[], Settings] = _env_settings,
        transport: Transport = smtp_transport,
    ) -> None:
        self._settings = settings
        self._transport = transport

    def validate_config(self, config: Mapping[str, Any]) -> list[FieldError]:
        return validate_recipients(config.get("recipients"))  # ASCII only: no SMTPUTF8

    def validate_secrets(self, secrets: Mapping[str, str]) -> list[FieldError]:
        return []

    async def send(
        self, alert: AlertMessage, rendered: RenderedAlert, channel: ResolvedChannel
    ) -> SendResult:
        settings = self._settings()
        if not settings.smtp_host or not settings.smtp_from:
            return SendResult.permanent(NOT_CONFIGURED)
        if self.validate_config(channel.config):
            return SendResult.permanent("config_invalid")
        recipients = list(channel.config["recipients"])
        timeout = float(settings.alert_send_timeout_seconds)
        if alert.kind == TEST_KIND:  # the dispatcher waits min(test timeout, send timeout)
            timeout = min(timeout, DEFAULT_TEST_TIMEOUT.total_seconds())
        cfg = SmtpSettings(
            host=settings.smtp_host,
            port=settings.smtp_port,
            security=settings.smtp_security,
            username=settings.smtp_username,
            password=settings.smtp_password.get_secret_value(),
            sender=settings.smtp_from,
            budget=timeout * SEND_BUDGET,
        )
        message = build_message(alert, rendered, recipients, cfg.sender, settings.base_url)
        try:
            await asyncio.to_thread(self._transport, cfg, message, recipients)
        except Exception as exc:  # noqa: BLE001 - mapped to a stable code, text never kept
            return map_exception(exc)
        return SendResult.ok()
