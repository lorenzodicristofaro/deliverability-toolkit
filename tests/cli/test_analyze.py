"""M4-13: CLI `analyze` command. Offline (sockets blocked); no input is ever echoed."""

from __future__ import annotations

import io
import os
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from app.cli import analyze as cli_analyze
from app.cli.main import app
from app.core import i18n
from app.parsers.message import MAX_RAW_BYTES
from app.services import message_analysis as ma
from app.services.message_analysis import analyze_message
from app.services.message_hops import HopTimeline
from tests.services import test_message_hops as hops_fx

runner = CliRunner()

SECRET_FOR = "victim-for-addr@example.net"
MESSAGE = (
    b"Received: from mail.example.com (mail.example.com [192.0.2.10])\r\n"
    b"\tby mx.example.net with ESMTP id abc123\r\n"
    b"\tfor <" + SECRET_FOR.encode() + b">; Mon, 01 Jan 2024 10:00:05 +0000\r\n"
    b"Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com;"
    b" dkim=pass header.d=example.com; dmarc=pass header.from=example.com\r\n"
    b"From: Alice <alice@example.com>\r\n"
    b"To: bob@example.net\r\n"
    b"Subject: hello\r\n"
    b"Date: Mon, 01 Jan 2024 10:00:00 +0000\r\n"
    b"Message-ID: <m1@example.com>\r\n"
    b"\r\n"
    b"BODY-TEXT-9191\r\n"
)
NO_AUTH = b"From: a@example.com\r\nSubject: x\r\n\r\nbody\r\n"
NOT_A_MESSAGE = b"this is not a message at all"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def blocked(*_a: Any, **_k: Any) -> None:
        raise AssertionError("network access in the analyze CLI")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket.socket, "sendto", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
    yield


def _file(tmp_path: Path, data: bytes, name: str = "m.eml") -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _expected_code(raw: bytes) -> int:
    status = analyze_message(raw).status
    return {"error": 2, "warn": 1, "fail": 1}.get(status, 0)


@pytest.mark.parametrize("raw", [MESSAGE, NO_AUTH, NOT_A_MESSAGE, b"\xff\xfe garbage\r\n\r\n"])
def test_json_is_byte_equal_to_model_dump_json(tmp_path: Path, raw: bytes) -> None:
    r = runner.invoke(app, ["analyze", _file(tmp_path, raw), "--format", "json"])
    assert r.stdout == analyze_message(raw).model_dump_json() + "\n"
    assert r.exit_code == _expected_code(raw)


def test_stdin_same_output_as_file(tmp_path: Path) -> None:
    from_file = runner.invoke(app, ["analyze", _file(tmp_path, MESSAGE), "--format", "json"])
    from_stdin = runner.invoke(app, ["analyze", "-", "--format", "json"], input=MESSAGE)
    assert from_stdin.stdout == from_file.stdout
    assert from_stdin.exit_code == from_file.exit_code


def test_exit_codes_cover_ok_warn_error(tmp_path: Path) -> None:
    codes = {
        runner.invoke(app, ["analyze", _file(tmp_path, raw), "--format", "json"]).exit_code
        for raw in (MESSAGE, NO_AUTH, NOT_A_MESSAGE)
    }
    assert 2 in codes  # error status
    assert 1 in codes or 0 in codes
    assert runner.invoke(app, ["analyze", _file(tmp_path, NOT_A_MESSAGE)]).exit_code == 2


@pytest.mark.parametrize("lang", ["en", "it"])
def test_text_is_translated_and_has_no_raw_keys(tmp_path: Path, lang: str) -> None:
    r = runner.invoke(app, ["analyze", _file(tmp_path, NO_AUTH), "--lang", lang])
    out = r.stdout
    analysis = analyze_message(NO_AUTH)
    assert i18n.t("message.section.findings", lang) in out
    assert i18n.t("message.section.received", lang) in out
    assert (
        i18n.t("cli.analyze.summary", lang, count=len(analysis.findings), code=r.exit_code) in out
    )
    for f in analysis.findings:
        assert i18n.t(f.title_key, lang, **dict(f.params)) in out
        assert f.title_key not in out
    assert "message.section" not in out
    assert "BODY" not in out


def test_languages_differ(tmp_path: Path) -> None:
    path = _file(tmp_path, NO_AUTH)
    assert (
        runner.invoke(app, ["analyze", path, "--lang", "en"]).stdout
        != runner.invoke(app, ["analyze", path, "--lang", "it"]).stdout
    )


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_received_for_address_is_never_printed(tmp_path: Path, fmt: str) -> None:
    r = runner.invoke(app, ["analyze", _file(tmp_path, MESSAGE), "--format", fmt])
    assert r.exit_code in (0, 1, 2)
    assert r.stdout.strip()
    assert SECRET_FOR not in r.stdout
    assert SECRET_FOR not in r.stderr
    assert "victim-for-addr" not in r.stdout
    if fmt == "json":
        assert "[redacted]" in r.stdout  # the hop was analysed, not dropped


# --- unreadable / hostile input -----------------------------------------------------------------


def _check_rejected(r: Any, key: str, secret: str = "") -> None:
    assert r.exit_code == 2
    assert r.stdout == ""
    assert i18n.t(key, "en") in r.stderr
    if secret:
        assert secret not in r.stderr


def test_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "SECRET-NAME-77.eml"
    r = runner.invoke(app, ["analyze", str(missing)])
    _check_rejected(r, "cli.analyze.error.not_found", "SECRET-NAME-77")


def test_directory(tmp_path: Path) -> None:
    r = runner.invoke(app, ["analyze", str(tmp_path)])
    _check_rejected(r, "cli.analyze.error.not_found")


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs non-root POSIX")
def test_unreadable_file(tmp_path: Path) -> None:
    path = _file(tmp_path, MESSAGE)
    os.chmod(path, 0)
    try:
        r = runner.invoke(app, ["analyze", path])
    finally:
        os.chmod(path, 0o600)
    _check_rejected(r, "cli.analyze.error.not_found")


def test_path_with_nul_is_unreadable() -> None:
    r = runner.invoke(app, ["analyze", "bad\x00path"])
    _check_rejected(r, "cli.analyze.error.not_found")


def test_binary_garbage_is_data_not_a_crash(tmp_path: Path) -> None:
    raw = bytes(range(1, 256)) * 20
    r = runner.invoke(app, ["analyze", _file(tmp_path, raw), "--format", "json"])
    assert r.exit_code == _expected_code(raw)
    assert r.stdout == analyze_message(raw).model_dump_json() + "\n"


@pytest.mark.parametrize(
    "raw", [b"From: a@example.com\r\nSubject: x\x00y\r\n\r\nbody", MESSAGE + b"\x00tail"]
)
def test_nul_byte(tmp_path: Path, raw: bytes) -> None:
    r = runner.invoke(app, ["analyze", _file(tmp_path, raw)])
    _check_rejected(r, "cli.analyze.error.nul_byte", "tail")


def test_empty_file_and_empty_stdin(tmp_path: Path) -> None:
    _check_rejected(
        runner.invoke(app, ["analyze", _file(tmp_path, b"")]), "cli.analyze.error.empty"
    )
    _check_rejected(runner.invoke(app, ["analyze", "-"], input=b""), "cli.analyze.error.empty")


def test_oversize_file_is_refused(tmp_path: Path) -> None:
    data = b"Subject: x\r\n\r\n" + b"a" * MAX_RAW_BYTES
    r = runner.invoke(app, ["analyze", _file(tmp_path, data)])
    _check_rejected(r, "cli.analyze.error.too_large")


def test_exactly_max_bytes_is_accepted(tmp_path: Path) -> None:
    head = b"Subject: x\r\n\r\n"
    data = head + b"a" * (MAX_RAW_BYTES - len(head))
    r = runner.invoke(app, ["analyze", _file(tmp_path, data), "--format", "json"])
    assert r.stdout == analyze_message(data).model_dump_json() + "\n"


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="needs /dev/zero")
def test_symlink_to_dev_zero_is_read_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = tmp_path / "zero.eml"
    link.symlink_to("/dev/zero")
    total = 0
    real_read = cli_analyze.read_bounded

    class Counting(io.RawIOBase):
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def read(self, size: int = -1) -> bytes:
            nonlocal total
            data: bytes = self.inner.read(size)
            total += len(data)
            return data

    def spy(stream: Any, limit: int = MAX_RAW_BYTES) -> bytes:
        return real_read(Counting(stream), limit)  # type: ignore[arg-type]

    monkeypatch.setattr(cli_analyze, "read_bounded", spy)
    r = runner.invoke(app, ["analyze", str(link)])
    _check_rejected(r, "cli.analyze.error.too_large")
    assert total == MAX_RAW_BYTES + 1  # stopped right past the cap


def test_stdin_oversize_is_capped() -> None:
    class Endless(io.RawIOBase):
        pulled = 0

        def read(self, size: int = -1) -> bytes:
            Endless.pulled += size
            return b"a" * size

    stream = Endless()
    with pytest.raises(cli_analyze.InputRejected):
        cli_analyze.read_bounded(stream)  # type: ignore[arg-type]
    assert Endless.pulled == MAX_RAW_BYTES + 1


def test_rejection_messages_are_translated(tmp_path: Path) -> None:
    r = runner.invoke(app, ["analyze", _file(tmp_path, b""), "--lang", "it"])
    assert i18n.t("cli.analyze.error.empty", "it") in r.stderr


# --- usage ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("extra", [["--format", "xml"], ["--lang", "fr"], ["--bogus"]])
def test_usage_errors_exit_64(tmp_path: Path, extra: list[str]) -> None:
    r = runner.invoke(app, ["analyze", _file(tmp_path, MESSAGE), *extra])
    assert r.exit_code == 64


def test_missing_argument_is_usage_error() -> None:
    assert runner.invoke(app, ["analyze"]).exit_code == 64


# --- F-01-02: per-hop authentication view -------------------------------------------------------


def hop_message(*lines: str) -> bytes:
    """Same message shape as the F-01-01 hop-view tests (tests/services/test_message_hops.py)."""
    return ("\r\n".join(("From: a@example.com", *lines)) + "\r\n\r\nbody").encode()


# A quoted authserv-id is accepted by the parser: markup, control characters and length all
# reach the view model, which bounds the text and drops control characters (``excerpt``).
HOSTILE_AUTHSERV = '"<script>alert(1)</script>\x1b[31m\x07' + "a" * 500 + '"'
_MAL_TOP = (
    hops_fx.ar("mx.top.example", "spf=fail; dkim=fail; arc=fail"),
    hops_fx.rcv("m.example", 5),
)

# The F-01-01 scenarios: (name, raw message). Malformed fields from its MALFORMED table.
HOP_SCENARIOS: list[tuple[str, bytes]] = [
    ("forwarding", hop_message(*hops_fx.BREAK_CASES[0][0])),
    ("mailing_list", hop_message(*hops_fx.BREAK_CASES[1][0])),
    (
        "forged_lower",
        hop_message(
            hops_fx.ar("mx.example.org", "spf=fail smtp.mailfrom=evil.example; dmarc=fail"),
            hops_fx.rcv("mx.example.org", 5),
            hops_fx.ar("mx.example.org", "dkim=pass header.d=example.com"),
        ),
    ),
    (
        "interleaved",
        hop_message(
            *hops_fx.arc_set(1, "none", "mx.final.example; arc=pass"),
            hops_fx.ar("mx.final.example", "dkim=fail header.d=example.com"),
            hops_fx.rcv("mx.final.example", 20),
            *hops_fx.arc_set(2, "pass", "list.example; dkim=pass header.d=example.com"),
            hops_fx.rcv("list.example", 10),
            hops_fx.ar("list.example", "dkim=pass header.d=example.com"),
            hops_fx.rcv("out.example.com", 1),
        ),
    ),
    *(
        (f"malformed_{i}", hop_message(*_MAL_TOP, line))
        for i, (line, _expected) in enumerate(hops_fx.MALFORMED)
    ),
    (
        "hostile_authserv",
        hop_message(
            hops_fx.ar("mx.top.example", "spf=fail"),
            hops_fx.rcv("mx.example", 5),
            hops_fx.ar(HOSTILE_AUTHSERV, "spf=pass"),
        ),
    ),
]
HOP_SCENARIO_IDS = [name for name, _ in HOP_SCENARIOS]


def _hop_section(stdout: str, lang: str) -> list[str]:
    after = stdout.split("\n" + i18n.t("message.section.hop_view", lang) + "\n", 1)[1]
    return after.split("\n\n", 1)[0].splitlines()


@pytest.mark.parametrize(("name", "raw"), HOP_SCENARIOS, ids=HOP_SCENARIO_IDS)
@pytest.mark.parametrize("lang", ["en", "it"])
def test_hop_view_text_follows_header_order(
    tmp_path: Path, name: str, raw: bytes, lang: str
) -> None:
    a = analyze_message(raw)
    assert a.hops is not None and a.hops.entries
    r = runner.invoke(app, ["analyze", _file(tmp_path, raw), "--lang", lang])
    assert r.exit_code == _expected_code(raw)
    lines = _hop_section(r.stdout, lang)
    assert len(lines) == len(a.hops.entries)
    for line, e in zip(lines, a.hops.entries, strict=True):
        kind = i18n.t(f"message.hop_view.kind.{e.kind}", lang)
        assert line.startswith(f"  {e.order + 1}. {kind}")
        if e.hop is not None:
            assert f"({i18n.t('message.hop_view.col.hop', lang)} {e.hop + 1})" in line
        if not e.parsed:
            assert i18n.t("message.hop_view.unparsed", lang) in line
            assert all(i in line for i in e.issues)
        elif e.stated_not_verifiable:
            stated = i18n.t("message.hop_view.stated", lang, authserv_id=e.authserv_id)
            assert line.endswith(stated)
        for res in e.results:
            assert f"{res.method}=" in line and res.result in line
    if name == "malformed_0":
        assert any(i18n.t("message.hop_view.unparsed", lang) in line for line in lines)
    assert "message.hop_view" not in r.stdout


def test_hop_view_lower_field_label_in_both_languages(tmp_path: Path) -> None:
    path = _file(tmp_path, dict(HOP_SCENARIOS)["forged_lower"])
    en = runner.invoke(app, ["analyze", path]).stdout
    it = runner.invoke(app, ["analyze", path, "--lang", "it"]).stdout
    assert "stated by mx.example.org, not verifiable" in en
    assert "dichiarato da mx.example.org, non verificabile" in it
    assert i18n.t("message.section.hop_view", "it") in it
    assert i18n.t("message.section.hop_view", "en") not in it


def test_hop_view_hostile_authserv_id_is_bounded_and_clean(tmp_path: Path) -> None:
    raw = dict(HOP_SCENARIOS)["hostile_authserv"]
    r = runner.invoke(app, ["analyze", _file(tmp_path, raw)])
    lower = [line for line in _hop_section(r.stdout, "en") if "not verifiable" in line]
    assert len(lower) == 1
    assert "\x1b" not in r.stdout and "\x07" not in r.stdout
    assert "a" * 201 not in r.stdout
    assert "<script>alert(1)</script>[31m" in lower[0]  # plain text: shown, never interpreted


@pytest.mark.parametrize(("name", "raw"), HOP_SCENARIOS, ids=HOP_SCENARIO_IDS)
def test_hop_view_does_not_change_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, raw: bytes
) -> None:
    path = _file(tmp_path, raw)
    with_hops = runner.invoke(app, ["analyze", path])
    monkeypatch.setattr(ma, "build_hop_view", lambda *_: HopTimeline((), False, False))
    without = runner.invoke(app, ["analyze", path])
    assert with_hops.exit_code == without.exit_code
    assert i18n.t("message.hop_view.empty", "en") in without.stdout


def test_hop_view_unavailable_and_truncated() -> None:
    a = analyze_message(dict(HOP_SCENARIOS)["forwarding"])
    assert a.hops is not None
    gone = cli_analyze.render_text(a.model_copy(update={"hops": None}), "it")
    assert _hop_section(gone, "it") == ["  " + i18n.t("message.section.unavailable", "it")]
    cut = a.hops.model_copy(update={"received_truncated": True, "arc_truncated": True})
    lines = _hop_section(cli_analyze.render_text(a.model_copy(update={"hops": cut}), "en"), "en")
    assert lines[-2:] == [
        "  " + i18n.t("message.hop_view.received_truncated", "en"),
        "  " + i18n.t("message.hop_view.arc_truncated", "en"),
    ]


@pytest.mark.parametrize(("name", "raw"), HOP_SCENARIOS, ids=HOP_SCENARIO_IDS)
def test_hop_view_json_is_byte_equal(tmp_path: Path, name: str, raw: bytes) -> None:
    r = runner.invoke(app, ["analyze", _file(tmp_path, raw), "--format", "json"])
    assert r.stdout == analyze_message(raw).model_dump_json() + "\n"
    assert '"hops":{"entries":[' in r.stdout
