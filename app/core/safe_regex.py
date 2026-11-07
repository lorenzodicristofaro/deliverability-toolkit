"""ReDoS-safe regex runner with an enforced timeout (M5-03, ARCHITECTURE section 9).

Mechanism: every search runs in a short-lived, killable subprocess
(``sys.executable -I -S -c <worker>``) using the stdlib ``re`` engine. The parent waits with
``Popen.communicate(timeout=...)``; on ``TimeoutExpired`` it calls ``Popen.kill()`` and a second
``communicate()`` (without input) to reap the child. Nothing runs in a thread of the caller's
process, so a catastrophic pattern can never pin a CPU or leak a hung worker there.

Why not the ``regex`` package ``timeout=`` argument: its PyPI page (regex 2026.11.7, released
2026-11-06; https://pypi.org/project/regex/, checked 2026-11-07) only states that "the matching
methods and functions support timeouts" and that the timeout "applies to the entire operation",
raising ``TimeoutError``. It does not document how often the deadline is checked during
backtracking, so it cannot be relied on to cut off catastrophic backtracking. No new dependency.

Subprocess behaviour verified against the Python docs (https://docs.python.org/3/library/
subprocess.html, page for 3.15.2, checked 2026-11-07; project runs CPython 3.12):
- ``communicate(timeout=...)`` raises ``TimeoutExpired`` and does NOT kill the child; the
  documented cleanup is ``kill()`` then ``communicate()``; input must not be passed again;
- ``kill()`` sends SIGKILL on POSIX (on Windows it is an alias for ``terminate()``);
- ``returncode`` is ``-N`` when the child was terminated by signal N (POSIX only).

Caveats:
- the timeout covers the whole worker run, interpreter start-up included (tens of ms), hence
  ``MIN_TIMEOUT_S``; a heavily loaded host can turn a slow-but-finite search into a timeout,
  which is reported (``timed_out=True``), never hidden;
- each search costs one process spawn; callers must not run unbounded searches in parallel
  (no global concurrency limit is applied here);
- match positions are code-point offsets into the original ``str``.

Callers map any result where ``complete`` is False to a check ``error`` (never ``ok``).
``RegexRuleError`` carries a stable ``reason`` and never echoes the pattern; the ``re.error``
message (which can quote the pattern) is dropped.
"""

from __future__ import annotations

import enum
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Final

MAX_PATTERN_LENGTH: Final = 1024
MAX_TEXT_BYTES: Final = 1024 * 1024  # hard cap on the UTF-8 size of a searched text
DEFAULT_TEXT_BYTES: Final = 256 * 1024
MAX_MATCHES: Final = 1000
DEFAULT_MATCHES: Final = 100
MIN_TIMEOUT_S: Final = 0.2
MAX_TIMEOUT_S: Final = 5.0
DEFAULT_TIMEOUT_S: Final = 1.0
# Grace period to reap a killed worker; SIGKILL cannot be ignored, so this is never reached.
_REAP_TIMEOUT_S: Final = 5.0

# Plain int on purpose: `~` on a RegexFlag only complements the defined flag bits.
ALLOWED_FLAGS: Final = int(re.IGNORECASE | re.MULTILINE | re.DOTALL | re.VERBOSE | re.ASCII)

# Runs in the child under -I -S (no site, no user paths, PYTHON* env ignored). Reads one JSON
# request from stdin, writes a JSON list of [start, end] pairs (at most n + 1) to stdout.
_WORKER: Final = (
    "import json,re,sys\n"
    "d=json.loads(sys.stdin.read())\n"
    "p=re.compile(d['p'],d['f'])\n"
    "n=d['n']\n"
    "o=[]\n"
    "for m in p.finditer(d['t']):\n"
    "    o.append([m.start(),m.end()])\n"
    "    if len(o)>n:\n"
    "        break\n"
    "sys.stdout.write(json.dumps(o))\n"
)


class RegexRejectReason(enum.StrEnum):
    EMPTY = "empty"
    TOO_LONG = "too_long"
    NUL = "nul"
    NOT_A_STRING = "not_a_string"
    UNSUPPORTED_FLAGS = "unsupported_flags"
    INVALID_SYNTAX = "invalid_syntax"


class RegexRuleError(ValueError):
    """A pattern was rejected at compile time. Never contains the pattern."""

    def __init__(self, reason: RegexRejectReason) -> None:
        super().__init__(f"regex pattern rejected: {reason.value}")
        self.reason = reason


class SearchFailure(enum.StrEnum):
    TIMEOUT = "timeout"
    TEXT_TOO_LARGE = "text_too_large"
    WORKER_FAILED = "worker_failed"


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A validated pattern; only `compile_checked` should build one."""

    pattern: str
    flags: int


@dataclass(frozen=True, slots=True)
class Match:
    start: int
    end: int
    text: str


@dataclass(frozen=True, slots=True)
class MatchResult:
    matches: tuple[Match, ...]
    timed_out: bool
    truncated: bool
    failure: SearchFailure | None = None

    @property
    def complete(self) -> bool:
        """True only when `matches` is the full, evaluated answer."""
        return self.failure is None and not self.timed_out and not self.truncated


def compile_checked(pattern: str, flags: int = 0) -> CompiledRule:
    """Validate `pattern` and `flags`; raise `RegexRuleError` (no echo of the input)."""
    if not isinstance(pattern, str):
        raise RegexRuleError(RegexRejectReason.NOT_A_STRING)
    if pattern == "":
        raise RegexRuleError(RegexRejectReason.EMPTY)
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise RegexRuleError(RegexRejectReason.TOO_LONG)
    if "\x00" in pattern:
        raise RegexRuleError(RegexRejectReason.NUL)
    if isinstance(flags, bool) or not isinstance(flags, int) or int(flags) & ~ALLOWED_FLAGS:
        raise RegexRuleError(RegexRejectReason.UNSUPPORTED_FLAGS)
    try:
        # Compilation of a length-capped pattern is cheap; matching is what can blow up.
        re.compile(pattern, int(flags))
    except (re.error, OverflowError, RecursionError, ValueError):
        raise RegexRuleError(RegexRejectReason.INVALID_SYNTAX) from None
    return CompiledRule(pattern=pattern, flags=int(flags))


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _failed(failure: SearchFailure, *, truncated: bool = False) -> MatchResult:
    timed_out = failure is SearchFailure.TIMEOUT
    return MatchResult((), timed_out=timed_out, truncated=truncated, failure=failure)


def search_all(
    rule: CompiledRule,
    text: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_matches: int = DEFAULT_MATCHES,
    max_text_bytes: int = DEFAULT_TEXT_BYTES,
) -> MatchResult:
    """Find all non-overlapping matches of `rule` in `text` in a killable worker process.

    Caller limits are clamped to the module hard caps. Never raises on timeout or worker
    failure: check `MatchResult.complete` (or `timed_out`/`truncated`/`failure`).
    """
    timeout = _clamp(float(timeout_s), MIN_TIMEOUT_S, MAX_TIMEOUT_S)
    limit = int(_clamp(int(max_matches), 1, MAX_MATCHES))
    text_cap = int(_clamp(int(max_text_bytes), 0, MAX_TEXT_BYTES))

    if len(text.encode("utf-8", "surrogatepass")) > text_cap:
        return _failed(SearchFailure.TEXT_TOO_LARGE, truncated=True)

    request = json.dumps({"p": rule.pattern, "f": rule.flags, "n": limit, "t": text})
    proc = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", _WORKER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
    )
    try:
        out, _ = proc.communicate(request.encode("ascii"), timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate(timeout=_REAP_TIMEOUT_S)
        return _failed(SearchFailure.TIMEOUT)
    except BaseException:
        proc.kill()
        proc.communicate(timeout=_REAP_TIMEOUT_S)
        raise

    if proc.returncode != 0:
        return _failed(SearchFailure.WORKER_FAILED)
    try:
        spans = json.loads(out)
        pairs = [(int(s), int(e)) for s, e in spans]
    except (ValueError, TypeError):
        return _failed(SearchFailure.WORKER_FAILED)

    truncated = len(pairs) > limit
    matches = tuple(Match(s, e, text[s:e]) for s, e in pairs[:limit])
    return MatchResult(matches, timed_out=False, truncated=truncated)
