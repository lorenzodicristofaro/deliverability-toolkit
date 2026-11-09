"""``content`` command (M5-17): analyse one message's content against the tenant's rules.

Unlike ``check`` and ``analyze`` this reads tenant data (the effective content rules), so it runs
inside :func:`app.cli.tenant_scope.operator_scope`: ``--tenant-id`` and ``--user-id`` select who
acts, and the same ``can(CONTENT_ANALYZE)`` as the web decides. The permission check comes FIRST,
as in the API (the permission dependency runs before the body is read): a denied operator never
causes a file or stdin read and never reaches the analyzer. Only usage errors that need no I/O
(output language, two ``-`` inputs, malformed ids) come before it.

Inside the scope the checks follow the API's order and outcomes: read with a shared byte budget
of ``MAX_RAW_BYTES`` for all inputs (too large), NUL byte, language (same pattern as the API),
then empty. ``--json`` prints exactly ``ContentAnalysis.model_dump_json()`` (the API body) plus a
newline. Offline apart from the database.

Exit codes: 0 complete and nothing above info, 1 any warn/fail OR an incomplete evaluation (a
script must not read a run whose rules did not all run as clean), 2 error status, unreadable,
too large, empty, NUL or invalid-language input and operator errors, 64 usage, 77 denied.
"""

from __future__ import annotations

import re
import sys
import unicodedata
from typing import Annotated, BinaryIO, Final

import typer

from app.cli.check import EXIT_ERROR, EXIT_OK, EXIT_USAGE, EXIT_WARN
from app.cli.tenant_scope import TenantIdOption, UserIdOption, operator_scope
from app.core import i18n
from app.core.i18n import t
from app.core.permissions import Action
from app.models.content_rule import MAX_LANGUAGE_LENGTH
from app.parsers.message import MAX_RAW_BYTES
from app.services.content_analysis import ContentAnalysis, ContentInput, analyze_content

CHUNK = 64 * 1024
# Same shape as the API accepts (app.api.v1.content._LANGUAGE).
_LANGUAGE = re.compile(r"[a-z]{2,3}(?:-[a-z0-9]{2,8})*")
_CONTROL: Final = frozenset({"Cc", "Cs", "Cf", "Co", "Cn", "Zl", "Zp"})

CANNOT_READ_KEY = "cli.content.error.cannot_read"
TOO_LARGE_KEY = "cli.content.error.too_large"
EMPTY_KEY = "cli.content.error.empty"
NUL_KEY = "cli.content.error.nul_byte"
LANGUAGE_KEY = "cli.content.error.invalid_language"
STDIN_ONCE_KEY = "cli.content.error.stdin_once"


def _fail(msg_key: str, code: int, lang: str = i18n.DEFAULT_LANGUAGE) -> typer.Exit:
    # Copy of the minimal helper in app.cli.check (private there); see the M5-17 follow-up.
    typer.echo(t(msg_key, lang), err=True)
    return typer.Exit(code)


class InputRejected(Exception):
    """The input cannot be analysed; ``key`` is the i18n message key (no input is carried)."""

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def read_bounded(stream: BinaryIO, limit: int) -> bytes:
    """Read at most ``limit + 1`` bytes; more than ``limit`` means too large.
    (Copy of ``app.cli.analyze.read_bounded`` with a per-call limit; see the follow-up.)"""
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
        raise InputRejected(TOO_LARGE_KEY)
    return data


def _read(source: str, budget: int) -> bytes:
    try:
        if source == "-":
            return read_bounded(sys.stdin.buffer, budget)
        with open(source, "rb") as fh:
            return read_bounded(fh, budget)
    except InputRejected:
        raise
    except (OSError, ValueError):  # missing, directory, permissions, closed stdin, bad path
        raise InputRejected(CANNOT_READ_KEY) from None


def _decode(data: bytes) -> str:
    if b"\x00" in data:
        raise InputRejected(NUL_KEY)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputRejected(CANNOT_READ_KEY) from None


def build_input(
    html: str | None, text: str | None, eml: str | None, subject: str | None, language: str | None
) -> ContentInput:
    """Load and validate the inputs in the API's order: size, NUL, language, empty."""
    budget = MAX_RAW_BYTES
    raws: dict[str, bytes] = {}
    for name, source in (("html", html), ("text", text), ("eml", eml)):
        if source is None:
            continue
        raws[name] = _read(source, budget)
        budget -= len(raws[name])
    if subject is not None:
        if len(subject.encode("utf-8", "replace")) > budget:
            raise InputRejected(TOO_LARGE_KEY)
        if "\x00" in subject:
            raise InputRejected(NUL_KEY)
    eml_b = raws.get("eml")
    if eml_b is not None and b"\x00" in eml_b:
        raise InputRejected(NUL_KEY)
    html_s = _decode(raws["html"]) if "html" in raws else None
    text_s = _decode(raws["text"]) if "text" in raws else None
    if language is not None:
        language = language.lower()
        if len(language) > MAX_LANGUAGE_LENGTH or not _LANGUAGE.fullmatch(language):
            raise InputRejected(LANGUAGE_KEY)
    if not eml_b and not html_s and not text_s:
        raise InputRejected(EMPTY_KEY)
    return ContentInput(
        html=html_s or None,
        text=text_s or None,
        subject=subject,
        eml=eml_b or None,
        language_hint=language,
    )


def exit_code(a: ContentAnalysis) -> int:
    if a.status == "error":
        return EXIT_ERROR
    if a.status in ("warn", "fail", "not_evaluated") or not a.complete:
        return EXIT_WARN
    return EXIT_OK


def _visible(value: object) -> str:
    """Control, format and unassigned characters shown as escapes (no terminal injection)."""
    out: list[str] = []
    for ch in str(value):
        if unicodedata.category(ch) in _CONTROL:
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _status(status: str, lang: str) -> str:
    return t(f"cli.content.status.{status}", lang)


def render_text(a: ContentAnalysis, lang: str) -> str:
    out: list[str] = [f"{t('cli.content.status', lang)}: {_status(a.status, lang)}"]
    yn = "cli.content.complete.yes" if a.complete else "cli.content.complete.no"
    out.append(f"{t('cli.content.complete', lang)}: {t(yn, lang)}")
    if not a.complete:
        out.append("  " + t("cli.content.complete.note", lang))
    if a.not_evaluated_sections:
        names = ", ".join(t(f"cli.content.section.{s}", lang) for s in a.not_evaluated_sections)
        out.append(f"  {t('cli.content.complete.skipped', lang)}: {names}")

    out.append("")
    out.append(t("cli.content.sections", lang))
    sections = {
        "message": a.message,
        "body": a.body,
        "links": a.links,
        "subject": a.subject,
        "unsubscribe": a.unsubscribe,
        "rules": a.rules,
    }
    for key, sec in sections.items():
        if sec is None:
            continue
        reasons = " ".join(f"[{_visible(r)}]" for r in sec.reasons)
        line = f"  {t(f'cli.content.section.{key}', lang)}: {_status(sec.status, lang)}"
        out.append(f"{line} {reasons}" if reasons else line)

    out.append("")
    out.append(t("cli.content.section.rules", lang))
    facts = a.rules.facts
    if facts is None:
        out.append("  " + t("cli.content.rules.unavailable", lang))
    else:
        out.append(
            "  "
            + t(
                "cli.content.rules.summary",
                lang,
                score=facts.score,
                matched=facts.matched_rules,
                evaluated=facts.evaluated_rules,
            )
        )
        matched = [r for r in facts.results if r.status == "matched"]
        for r in matched:
            sev = t(f"cli.check.severity.{r.severity}", lang)
            issue = f" [{_visible(r.issue)}]" if r.issue else ""
            out.append(f"  [{sev}] {_visible(r.category)}: {_visible(r.name)}{issue}")
            if r.evidence:
                out.append("    " + t("cli.check.evidence", lang, text=_visible(r.evidence)))
        # "None matched" is only true when every rule reached a verdict (as the web result).
        verdict = (
            facts.evaluated_rules > 0
            and facts.error_rules == 0
            and facts.not_evaluated_rules == 0
            and not a.rules.reasons
        )
        if not verdict:
            out.append("  " + t("cli.content.rules.not_evaluated", lang))
        elif not matched:
            out.append("  " + t("cli.content.rules.none", lang))
        for r in facts.results:
            if r.status in ("error", "not_evaluated"):
                issue = f" [{_visible(r.issue)}]" if r.issue else ""
                failed = t(
                    "cli.content.rules.failed",
                    lang,
                    name=_visible(r.name),
                    status=_status(r.status, lang),
                )
                out.append(f"  {failed}{issue}")

    out.append("")
    out.append(t("cli.content.findings", lang))
    if not a.findings:
        out.append("  " + t("cli.check.no_findings", lang))
    for f in a.findings:
        params = {k: _visible(v) if isinstance(v, str) else v for k, v in dict(f.params).items()}
        sev = t(f"cli.check.severity.{f.severity}", lang)
        out.append(f"  [{sev}] {t(f.title_key, lang, **params)}")
        out.append("    " + t(f.detail_key, lang, **params))
        if f.remediation_key:
            out.append("    " + t("cli.check.fix", lang, text=t(f.remediation_key, lang, **params)))
        for e in f.evidence:
            out.append("    " + t("cli.check.evidence", lang, text=_visible(e)))

    out.append("")
    out.append(t("cli.content.summary", lang, count=len(a.findings), code=exit_code(a)))
    return "\n".join(out)


def content_command(
    tenant_id: TenantIdOption,
    user_id: UserIdOption,
    html: Annotated[
        str | None, typer.Option("--html", help=t("cli.content.opt.html"), show_default=False)
    ] = None,
    text: Annotated[
        str | None, typer.Option("--text", help=t("cli.content.opt.text"), show_default=False)
    ] = None,
    subject: Annotated[
        str | None, typer.Option("--subject", help=t("cli.content.opt.subject"), show_default=False)
    ] = None,
    eml: Annotated[
        str | None, typer.Option("--eml", help=t("cli.content.opt.eml"), show_default=False)
    ] = None,
    language: Annotated[
        str | None, typer.Option("--lang", help=t("cli.content.opt.lang"), show_default=False)
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help=t("cli.content.opt.json"))] = False,
    output_lang: Annotated[
        str, typer.Option("--output-lang", help=t("cli.check.opt.lang"), show_default=False)
    ] = i18n.DEFAULT_LANGUAGE,
) -> None:
    if output_lang not in i18n.SUPPORTED_LANGUAGES:
        raise _fail("cli.check.error.invalid_lang", EXIT_USAGE)
    if [html, text, eml].count("-") > 1:  # stdin can be read once
        raise _fail(STDIN_ONCE_KEY, EXIT_USAGE, output_lang)
    with operator_scope(tenant_id, user_id, Action.CONTENT_ANALYZE, lang=output_lang) as scope:
        try:
            content = build_input(html, text, eml, subject, language)
        except InputRejected as e:
            raise _fail(e.key, EXIT_ERROR, output_lang) from None
        analysis = analyze_content(scope.ctx, scope.session, content)
    typer.echo(analysis.model_dump_json() if as_json else render_text(analysis, output_lang))
    raise typer.Exit(exit_code(analysis))
