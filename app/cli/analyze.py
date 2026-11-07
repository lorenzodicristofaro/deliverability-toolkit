"""``analyze`` command (M4-13): offline analysis of one raw message from a file or stdin.

Same trust boundary as ``check`` (shell access, no tenant, no database, no network). The bytes go
to :func:`app.services.message_analysis.analyze_message`; ``--format json`` prints exactly
``MessageAnalysis.model_dump_json()`` (the API body). Input is read in bounded chunks and stops at
``MAX_RAW_BYTES + 1`` so an endless source (``/dev/zero``) is never loaded. Text output renders
the service's redacted data through i18n keys and never echoes the raw input.

Exit codes: 0 no finding above info, 1 any warn/fail, 2 error status or unreadable, oversize,
empty or NUL input, 64 usage error (format or language).
"""

from __future__ import annotations

import sys
from typing import Annotated, BinaryIO

import typer

from app.cli.check import EXIT_ERROR, EXIT_OK, EXIT_USAGE, EXIT_WARN, FORMATS, _fail
from app.core import i18n
from app.core.i18n import t
from app.parsers.message import MAX_RAW_BYTES
from app.services.message_analysis import MessageAnalysis, analyze_message

CHUNK = 64 * 1024


class InputRejected(Exception):
    """The input cannot be analysed; ``key`` is the i18n message key (no input is carried)."""

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def read_bounded(stream: BinaryIO, limit: int = MAX_RAW_BYTES) -> bytes:
    """Read at most ``limit + 1`` bytes; more than ``limit`` means too large."""
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = stream.read(min(CHUNK, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
        raise InputRejected("cli.analyze.error.too_large")
    return data


def load_input(source: str) -> bytes:
    try:
        if source == "-":
            data = read_bounded(sys.stdin.buffer)
        else:
            with open(source, "rb") as fh:
                data = read_bounded(fh)
    except InputRejected:
        raise
    except (OSError, ValueError):  # missing, directory, permissions, closed stdin, bad path
        raise InputRejected("cli.analyze.error.not_found") from None
    if not data:
        raise InputRejected("cli.analyze.error.empty")
    if b"\x00" in data:
        raise InputRejected("cli.analyze.error.nul_byte")
    return data


def exit_code(analysis: MessageAnalysis) -> int:
    if analysis.status == "error":
        return EXIT_ERROR
    if analysis.status in ("warn", "fail"):
        return EXIT_WARN
    return EXIT_OK


def _val(v: object, lang: str) -> str:
    if v is None:
        return "-"
    if isinstance(v, bool):
        return t("message.bool.yes" if v else "message.bool.no", lang)
    return str(v)


def render_text(a: MessageAnalysis, lang: str) -> str:
    out: list[str] = []

    def section(key: str) -> None:
        out.append("")
        out.append(t(key, lang))

    def missing() -> None:
        out.append("  " + t("message.section.unavailable", lang))

    out.append(f"{t('message.arc.status', lang)}: {t(f'cli.check.status.{a.status}', lang)}")

    section("message.section.summary")
    if a.summary is None:
        missing()
    else:
        s = a.summary
        for label, v in (
            ("message.summary.subject", s.subject),
            ("message.summary.from", s.from_header),
            ("message.summary.to_count", s.to_count),
            ("message.summary.cc_count", s.cc_count),
            ("message.summary.date", s.date_header),
            ("message.summary.headers", s.header_count),
            ("message.summary.size", s.size_bytes),
        ):
            out.append(f"  {t(label, lang)}: {_val(v, lang)}")

    section("message.section.received")
    if a.received is None:
        missing()
    else:
        for h in a.received.hops:
            out.append(
                f"  {t('message.col.hop', lang)} {h.index}: "
                f"{t('message.col.from', lang)} {_val(h.from_host, lang)} ({_val(h.from_ip, lang)})"
                f", {t('message.col.by', lang)} {_val(h.by_host, lang)}"
                f", {t('message.col.delay', lang)} {_val(h.delay_seconds, lang)}"
            )
        if not a.received.hops:
            out.append("  " + t("message.section.empty", lang))

    section("message.section.authres")
    if a.authentication is None:
        missing()
    else:
        rows = [(r.method, r.result) for h in a.authentication for r in h.results]
        for method, result in rows:
            out.append(f"  {method}: {result}")
        if not rows:
            out.append("  " + t("message.section.empty", lang))

    section("message.section.alignment")
    if a.alignment is None:
        missing()
    else:
        al = a.alignment
        out.append(f"  {t('message.alignment.stated', lang)}: {_val(al.stated_dmarc, lang)}")
        out.append(f"  {t('message.alignment.computed', lang)}: {al.computed_dmarc}")
        for p in al.pairs:
            out.append(f"  {p.kind}: {p.state}")

    section("message.section.arc")
    if a.arc is None:
        missing()
    else:
        out.append(f"  {t('message.arc.status', lang)}: {a.arc.status}")
        out.append(f"  {t('message.arc.instances', lang)}: {a.arc.instance_count}")

    section("message.section.mime")
    if a.mime is None:
        missing()
    else:
        for part in a.mime.parts:
            out.append(
                f"  {part.index}: {part.content_type} ({part.category}), {part.encoded_size}"
            )

    section("message.section.findings")
    if not a.findings:
        out.append("  " + t("cli.check.no_findings", lang))
    for f in a.findings:
        params = dict(f.params)
        sev = t(f"cli.check.severity.{f.severity}", lang)
        out.append(f"  [{sev}] {t(f.title_key, lang, **params)}")
        out.append("    " + t(f.detail_key, lang, **params))
        if f.remediation_key:
            out.append("    " + t("cli.check.fix", lang, text=t(f.remediation_key, lang, **params)))

    out.append("")
    out.append(t("cli.analyze.summary", lang, count=len(a.findings), code=exit_code(a)))
    return "\n".join(out)


def analyze_command(
    file: Annotated[str, typer.Argument(help=t("cli.analyze.arg.file"), show_default=False)],
    fmt: Annotated[
        str, typer.Option("--format", help=t("cli.check.opt.format"), show_default=False)
    ] = "text",
    lang: Annotated[
        str, typer.Option("--lang", help=t("cli.check.opt.lang"), show_default=False)
    ] = i18n.DEFAULT_LANGUAGE,
) -> None:
    if lang not in i18n.SUPPORTED_LANGUAGES:
        raise _fail("cli.check.error.invalid_lang", EXIT_USAGE)
    if fmt not in FORMATS:
        raise _fail("cli.check.error.invalid_format", EXIT_USAGE, lang)
    try:
        raw = load_input(file)
    except InputRejected as e:
        raise _fail(e.key, EXIT_ERROR, lang) from None
    analysis = analyze_message(raw)
    typer.echo(analysis.model_dump_json() if fmt == "json" else render_text(analysis, lang))
    raise typer.Exit(exit_code(analysis))
