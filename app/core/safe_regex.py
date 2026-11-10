"""ReDoS-safe regex runner with an enforced timeout (M5-03, ARCHITECTURE section 9).

Mechanism: rules run with the stdlib ``re`` engine in a killable worker subprocess
(``sys.executable -I -S -c <worker>``). ``search_many`` sends the text once, then the rules one
by one, each with its own deadline. When a rule misses its deadline the worker is killed
(SIGKILL) and reaped, the rule is reported ``timed_out``, and a fresh worker runs the remaining
rules. Nothing runs in a thread of the caller's process, so a catastrophic pattern can never pin
a CPU or leave a hung worker there. ``search_all`` is ``search_many`` with one rule.

Why not the ``regex`` package ``timeout=`` argument: its PyPI page (regex 2026.11.7, released
2026-11-06; https://pypi.org/project/regex/, checked 2026-11-07) only states that "the matching
methods and functions support timeouts" and that the timeout "applies to the entire operation",
raising ``TimeoutError``. It does not document how often the deadline is checked during
backtracking, so it cannot be relied on to cut off catastrophic backtracking. No new dependency.

Subprocess behaviour verified against the Python docs (https://docs.python.org/3/library/
subprocess.html, page for 3.15.2, checked 2026-11-07; project runs CPython 3.12):
- ``kill()`` sends SIGKILL on POSIX (on Windows it is an alias for ``terminate()``);
- ``returncode`` is ``-N`` when the child was terminated by signal N (POSIX only);
- a child is only reaped by ``wait()``/``poll()``/``communicate()``, so every exit path here waits.
Pipe I/O uses ``selectors`` with non-blocking fds, which works on pipes on POSIX only (the
service runs on Linux).

Limits (callers cannot exceed the hard caps; values are clamped):
- pattern length, text UTF-8 size, matches per rule, per-rule timeout, rules per call;
- ``MAX_BATCH_S``: overall wall-clock budget of one call; when it runs out, the running rule and
  every rule not yet run are reported ``timed_out`` with ``failure=BATCH_DEADLINE``;
- ``MAX_LIVE_WORKERS``: live workers per process (a semaphore). A call waits for a slot for at
  most its per-rule timeout, then reports ``failure=BUSY`` for the rules not yet run.
  The limit is per OS process: N uvicorn workers allow N * MAX_LIVE_WORKERS children.

Caveats: the per-rule deadline starts when the rule is sent (worker start-up and text loading
have their own ``STARTUP_TIMEOUT_S``); a loaded host can turn a slow-but-finite rule into a
timeout, which is reported, never hidden. Match positions are code-point offsets.

Callers map any result where ``complete`` is False to a check ``error`` (never ``ok``).
``RegexRuleError`` carries a stable ``reason`` and never echoes the pattern; the ``re.error``
message (which can quote the pattern) is dropped.
"""

from __future__ import annotations

import contextlib
import enum
import json
import os
import re
import selectors
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

MAX_PATTERN_LENGTH: Final = 1024
MAX_TEXT_BYTES: Final = 1024 * 1024  # hard cap on the UTF-8 size of a searched text
DEFAULT_TEXT_BYTES: Final = 256 * 1024
MAX_MATCHES: Final = 1000
DEFAULT_MATCHES: Final = 100
MIN_TIMEOUT_S: Final = 0.05
MAX_TIMEOUT_S: Final = 5.0
DEFAULT_TIMEOUT_S: Final = 1.0
MAX_RULES: Final = 200
MAX_BATCH_S: Final = 15.0
STARTUP_TIMEOUT_S: Final = 3.0
MAX_LIVE_WORKERS: Final = 4
_REAP_TIMEOUT_S: Final = 5.0  # SIGKILL cannot be ignored, so this is never reached in practice
_MAX_REPLY_BYTES: Final = 1024 * 1024

# Plain int on purpose: `~` on a RegexFlag only complements the defined flag bits.
ALLOWED_FLAGS: Final = int(re.IGNORECASE | re.MULTILINE | re.DOTALL | re.VERBOSE | re.ASCII)

# Runs in the child under -I -S (no site, no user paths, PYTHON* env ignored). Protocol, one JSON
# document per line: parent sends the text, child answers "ready"; then per rule the parent
# sends {"p", "f", "n"} and the child answers a list of [start, end] pairs (at most n + 1).
_WORKER: Final = (
    "import json,re,sys\n"
    "r=sys.stdin.buffer.readline\n"
    "w=sys.stdout\n"
    "t=json.loads(r())\n"
    "w.write('\"ready\"\\n');w.flush()\n"
    "for line in iter(r,b''):\n"
    "    d=json.loads(line)\n"
    "    p=re.compile(d['p'],d['f'])\n"
    "    n=d['n']\n"
    "    o=[]\n"
    "    for m in p.finditer(t):\n"
    "        o.append([m.start(),m.end()])\n"
    "        if len(o)>n:\n"
    "            break\n"
    "    w.write(json.dumps(o)+'\\n');w.flush()\n"
)

_WORKER_SLOTS = threading.BoundedSemaphore(MAX_LIVE_WORKERS)


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
    TIMEOUT = "timeout"  # this rule exceeded its own deadline
    BATCH_DEADLINE = "batch_deadline"  # the call's overall budget ran out before/while running
    TEXT_TOO_LARGE = "text_too_large"
    TOO_MANY_RULES = "too_many_rules"  # rule beyond MAX_RULES, not run
    BUSY = "busy"  # no worker slot became free in time
    WORKER_FAILED = "worker_failed"


_TIMED_OUT: Final = frozenset({SearchFailure.TIMEOUT, SearchFailure.BATCH_DEADLINE})


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
    return MatchResult((), timed_out=failure in _TIMED_OUT, truncated=truncated, failure=failure)


class _WorkerDied(Exception):
    pass


class _Worker:
    """One worker subprocess holding one slot of `_WORKER_SLOTS` until `close`/`kill`."""

    def __init__(self) -> None:
        self._proc = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", _WORKER],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
        )
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._in = self._proc.stdin.fileno()
        self._out = self._proc.stdout.fileno()
        os.set_blocking(self._in, False)
        os.set_blocking(self._out, False)
        self._buf = bytearray()
        self._released = False

    def exchange(self, payload: bytes, deadline: float) -> bytes | None:
        """Send `payload`, return one reply line; None on deadline; `_WorkerDied` on EOF/EPIPE."""
        pending = memoryview(payload)
        with selectors.DefaultSelector() as sel:
            sel.register(self._out, selectors.EVENT_READ)
            if pending:
                sel.register(self._in, selectors.EVENT_WRITE)
            while True:
                if b"\n" in self._buf:
                    line, _, rest = bytes(self._buf).partition(b"\n")
                    self._buf = bytearray(rest)
                    return line
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                for key, _ in sel.select(remaining):
                    if key.fd == self._in:
                        try:
                            pending = pending[os.write(self._in, pending) :]
                        except BlockingIOError:
                            continue
                        except OSError as exc:  # EPIPE: the worker is gone
                            raise _WorkerDied from exc
                        if not pending:
                            sel.unregister(self._in)
                    else:
                        try:
                            chunk = os.read(self._out, 65536)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            raise _WorkerDied
                        self._buf += chunk
                        if len(self._buf) > _MAX_REPLY_BYTES:
                            raise _WorkerDied

    def kill(self) -> None:
        try:
            self._proc.kill()
            self._proc.wait(timeout=_REAP_TIMEOUT_S)
        finally:
            self._release()

    def close(self) -> None:
        """Normal shutdown: EOF on stdin ends the worker loop; kill it if it does not exit."""
        try:
            assert self._proc.stdin is not None
            with contextlib.suppress(OSError):
                self._proc.stdin.close()
            try:
                self._proc.wait(timeout=_REAP_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=_REAP_TIMEOUT_S)
        finally:
            self._release()

    def _release(self) -> None:
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        if self._proc.stdin is not None and not self._proc.stdin.closed:
            with contextlib.suppress(OSError):
                self._proc.stdin.close()
        if not self._released:
            self._released = True
            _WORKER_SLOTS.release()


def _start_worker(text_line: bytes, slot_wait_s: float, deadline: float) -> _Worker | SearchFailure:
    if not _WORKER_SLOTS.acquire(timeout=max(0.0, min(slot_wait_s, deadline - time.monotonic()))):
        return SearchFailure.BATCH_DEADLINE if time.monotonic() >= deadline else SearchFailure.BUSY
    try:
        worker = _Worker()
    except BaseException:
        _WORKER_SLOTS.release()
        raise
    startup_deadline = min(deadline, time.monotonic() + STARTUP_TIMEOUT_S)
    try:
        reply = worker.exchange(text_line, startup_deadline)
    except _WorkerDied:
        reply = None
    except BaseException:
        worker.kill()
        raise
    if reply is not None and reply.strip() == b'"ready"':
        return worker
    worker.kill()
    return (
        SearchFailure.BATCH_DEADLINE
        if time.monotonic() >= deadline
        else SearchFailure.WORKER_FAILED
    )


def _parse_reply(reply: bytes, text: str, limit: int) -> MatchResult:
    try:
        spans = json.loads(reply)
        if not isinstance(spans, list):
            raise ValueError
        pairs = [(int(s), int(e)) for s, e in spans]
    except (ValueError, TypeError):
        return _failed(SearchFailure.WORKER_FAILED)
    truncated = len(pairs) > limit
    matches = tuple(Match(s, e, text[s:e]) for s, e in pairs[:limit])
    return MatchResult(matches, timed_out=False, truncated=truncated)


def search_many(
    rules: Sequence[CompiledRule],
    text: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_matches: int = DEFAULT_MATCHES,
    max_text_bytes: int = DEFAULT_TEXT_BYTES,
    total_timeout_s: float = MAX_BATCH_S,
) -> list[MatchResult]:
    """Run `rules` in order against one `text`; one result per rule, same order.

    `timeout_s` is per rule; `total_timeout_s` bounds the whole call. Caller limits are clamped to
    the module hard caps. Never raises on timeout, saturation or worker failure: check
    `MatchResult.complete` (or `timed_out`/`truncated`/`failure`) for each rule.
    """
    timeout = _clamp(float(timeout_s), MIN_TIMEOUT_S, MAX_TIMEOUT_S)
    limit = int(_clamp(int(max_matches), 1, MAX_MATCHES))
    text_cap = int(_clamp(int(max_text_bytes), 0, MAX_TEXT_BYTES))
    deadline = time.monotonic() + _clamp(float(total_timeout_s), MIN_TIMEOUT_S, MAX_BATCH_S)

    runnable = list(rules[:MAX_RULES])
    overflow = [_failed(SearchFailure.TOO_MANY_RULES)] * (len(rules) - len(runnable))
    if len(text.encode("utf-8", "surrogatepass")) > text_cap:
        too_large = _failed(SearchFailure.TEXT_TOO_LARGE, truncated=True)
        return [too_large] * len(runnable) + overflow

    text_line = (json.dumps(text) + "\n").encode("ascii")
    results: list[MatchResult] = []
    worker: _Worker | None = None
    try:
        while len(results) < len(runnable):
            if worker is None:
                started = _start_worker(text_line, timeout, deadline)
                if isinstance(started, SearchFailure):
                    results += [_failed(started)] * (len(runnable) - len(results))
                    break
                worker = started
            rule = runnable[len(results)]
            request = json.dumps({"p": rule.pattern, "f": rule.flags, "n": limit}) + "\n"
            rule_deadline = min(deadline, time.monotonic() + timeout)
            try:
                reply = worker.exchange(request.encode("ascii"), rule_deadline)
            except _WorkerDied:
                worker.kill()
                worker = None
                results.append(_failed(SearchFailure.WORKER_FAILED))
                continue
            if reply is None:
                worker.kill()
                worker = None
                if time.monotonic() >= deadline:
                    results += [_failed(SearchFailure.BATCH_DEADLINE)] * (
                        len(runnable) - len(results)
                    )
                    break
                results.append(_failed(SearchFailure.TIMEOUT))
                continue
            result = _parse_reply(reply, text, limit)
            if result.failure is not None:
                worker.kill()
                worker = None
            results.append(result)
    finally:
        if worker is not None:
            if len(results) == len(runnable):
                worker.close()
            else:  # interrupted by an exception: do not wait for a possibly busy worker
                worker.kill()
    return results + overflow


def search_all(
    rule: CompiledRule,
    text: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_matches: int = DEFAULT_MATCHES,
    max_text_bytes: int = DEFAULT_TEXT_BYTES,
) -> MatchResult:
    """Find all non-overlapping matches of one rule; see `search_many`."""
    (result,) = search_many(
        [rule],
        text,
        timeout_s=timeout_s,
        max_matches=max_matches,
        max_text_bytes=max_text_bytes,
    )
    return result
