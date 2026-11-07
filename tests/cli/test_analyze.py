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
from app.services.message_analysis import analyze_message

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
