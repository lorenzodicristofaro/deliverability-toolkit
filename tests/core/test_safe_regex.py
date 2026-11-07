"""M5-03 ReDoS-safe regex runner. Workers are local subprocesses; no network."""

import os
import re
import signal
import subprocess
import time

import pytest

from app.core import safe_regex
from app.core.safe_regex import (
    MAX_MATCHES,
    MAX_PATTERN_LENGTH,
    MAX_TEXT_BYTES,
    MAX_TIMEOUT_S,
    MIN_TIMEOUT_S,
    CompiledRule,
    RegexRejectReason,
    RegexRuleError,
    SearchFailure,
    compile_checked,
    search_all,
)

TIMEOUT = 0.5
# Catastrophic inputs: each takes far longer than TIMEOUT on a backtracking engine.
CATASTROPHIC = [
    ("(a+)+$", "a" * 40 + "!"),  # nested quantifiers
    ("(a|a)+$", "a" * 40 + "!"),  # alternation overlap
    ("(a|aa)+$", "a" * 80 + "!"),  # overlapping alternation of different lengths
    ("(x+x+)+y", "x" * 40),  # adjacent overlapping quantifiers inside a repeat
    ("^(\\w+\\s?)*$", "word " * 20 + "!"),  # classic "email validator" shape
]


class _RecordingPopen(subprocess.Popen[bytes]):
    instances: list["_RecordingPopen"] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[call-overload]
        _RecordingPopen.instances.append(self)


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[_RecordingPopen]:
    _RecordingPopen.instances = []
    monkeypatch.setattr(subprocess, "Popen", _RecordingPopen)
    return _RecordingPopen.instances


def _assert_reaped_by_sigkill(proc: subprocess.Popen[bytes]) -> None:
    assert proc.returncode == -signal.SIGKILL
    with pytest.raises(ProcessLookupError):
        os.kill(proc.pid, 0)


# --- compile_checked -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "flags"),
    [
        ("abc", 0),
        (r"^v=spf1\s", re.IGNORECASE),
        (r"(?P<sel>[a-z0-9]+)\._domainkey", 0),
        ("é+", re.IGNORECASE),
        (r"^\w+$", re.ASCII | re.MULTILINE),
        (r"a . b  # comment", re.VERBOSE | re.DOTALL),
        ("x" * MAX_PATTERN_LENGTH, 0),
        ("(a+)+$", 0),  # catastrophic patterns compile; the runner contains them
    ],
)
def test_compile_valid(pattern: str, flags: int) -> None:
    rule = compile_checked(pattern, flags)
    assert rule == CompiledRule(pattern=pattern, flags=int(flags))


@pytest.mark.parametrize(
    ("pattern", "flags", "reason"),
    [
        ("", 0, RegexRejectReason.EMPTY),
        ("x" * (MAX_PATTERN_LENGTH + 1), 0, RegexRejectReason.TOO_LONG),
        ("a\x00b", 0, RegexRejectReason.NUL),
        (b"abc", 0, RegexRejectReason.NOT_A_STRING),
        (None, 0, RegexRejectReason.NOT_A_STRING),
        ("abc", re.DEBUG, RegexRejectReason.UNSUPPORTED_FLAGS),
        ("abc", re.LOCALE, RegexRejectReason.UNSUPPORTED_FLAGS),
        ("abc", 1 << 20, RegexRejectReason.UNSUPPORTED_FLAGS),
        ("abc", -1, RegexRejectReason.UNSUPPORTED_FLAGS),
        ("abc", True, RegexRejectReason.UNSUPPORTED_FLAGS),
        ("abc", "i", RegexRejectReason.UNSUPPORTED_FLAGS),
        ("(secret", 0, RegexRejectReason.INVALID_SYNTAX),
        ("secret[", 0, RegexRejectReason.INVALID_SYNTAX),
        ("*secret", 0, RegexRejectReason.INVALID_SYNTAX),
        (r"secret\k", 0, RegexRejectReason.INVALID_SYNTAX),
        ("(?P<x>a)(?P<x>b)secret", 0, RegexRejectReason.INVALID_SYNTAX),
        ("secret{99999999999}", 0, RegexRejectReason.INVALID_SYNTAX),
    ],
)
def test_compile_rejected(pattern: object, flags: object, reason: RegexRejectReason) -> None:
    with pytest.raises(RegexRuleError) as exc_info:
        compile_checked(pattern, flags)  # type: ignore[arg-type]
    err = exc_info.value
    assert err.reason is reason
    assert "secret" not in str(err)
    assert err.__cause__ is None
    assert err.__context__ is None or err.__suppress_context__  # re.error text not shown


# --- search_all: normal results --------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "flags", "text", "expected"),
    [
        ("b", 0, "abcabc", [(1, 2, "b"), (4, 5, "b")]),
        ("z", 0, "abc", []),
        ("a*", 0, "", [(0, 0, "")]),
        ("ABC", re.IGNORECASE, "xabc", [(1, 4, "abc")]),
        ("^x", re.MULTILINE, "x\nx", [(0, 1, "x"), (2, 3, "x")]),
        ("^x", 0, "x\nx", [(0, 1, "x")]),
        ("a.b", re.DOTALL, "a\nb", [(0, 3, "a\nb")]),
        ("a.b", 0, "a\nb", []),
        (r"\w+", 0, "über straße", [(0, 4, "über"), (5, 11, "straße")]),
        (r"\w+", re.ASCII, "über", [(1, 4, "ber")]),
        ("😀+", 0, "x😀😀y", [(1, 3, "😀😀")]),
        ("b", 0, "\ud800ab", [(2, 3, "b")]),  # lone surrogate survives the round trip
        ("v=spf1", 0, "v=spf1 -all\x00", [(0, 6, "v=spf1")]),
    ],
)
def test_search_matches(
    pattern: str, flags: int, text: str, expected: list[tuple[int, int, str]]
) -> None:
    result = search_all(compile_checked(pattern, flags), text, timeout_s=MAX_TIMEOUT_S)
    assert result.complete
    assert not result.timed_out and not result.truncated and result.failure is None
    assert [(m.start, m.end, m.text) for m in result.matches] == expected


def test_match_count_cap_marks_truncated() -> None:
    result = search_all(compile_checked("a"), "a" * 50, max_matches=10, timeout_s=MAX_TIMEOUT_S)
    assert len(result.matches) == 10
    assert result.truncated and not result.complete


def test_exactly_max_matches_is_complete() -> None:
    result = search_all(compile_checked("a"), "a" * 10, max_matches=10, timeout_s=MAX_TIMEOUT_S)
    assert len(result.matches) == 10
    assert result.complete


def test_match_count_cannot_exceed_hard_cap() -> None:
    text = "a" * (MAX_MATCHES + 5)
    result = search_all(
        compile_checked("a"), text, max_matches=MAX_MATCHES * 10, timeout_s=MAX_TIMEOUT_S
    )
    assert len(result.matches) == MAX_MATCHES
    assert result.truncated


@pytest.mark.parametrize(
    ("text", "cap", "too_large"),
    [
        ("a" * 100, 100, False),
        ("a" * 101, 100, True),
        ("é" * 50, 100, False),  # 2 UTF-8 bytes each: exactly 100
        ("é" * 51, 100, True),
        ("a" * (MAX_TEXT_BYTES + 1), MAX_TEXT_BYTES * 10, True),  # caller cannot raise hard cap
    ],
)
def test_text_size_cap(
    recorded: list[_RecordingPopen], text: str, cap: int, too_large: bool
) -> None:
    result = search_all(compile_checked("a"), text, max_text_bytes=cap, timeout_s=MAX_TIMEOUT_S)
    if too_large:
        assert result.failure is SearchFailure.TEXT_TOO_LARGE
        assert result.truncated and not result.complete and result.matches == ()
        assert recorded == []  # never handed to a worker
    else:
        assert result.complete


def test_huge_text_within_hard_cap() -> None:
    text = "x" * (MAX_TEXT_BYTES - 1) + "y"
    result = search_all(
        compile_checked("y$"), text, max_text_bytes=MAX_TEXT_BYTES, timeout_s=MAX_TIMEOUT_S
    )
    assert result.complete
    assert [(m.start, m.end) for m in result.matches] == [(MAX_TEXT_BYTES - 1, MAX_TEXT_BYTES)]


# --- search_all: cut-off ---------------------------------------------------------------------


@pytest.mark.parametrize(("pattern", "text"), CATASTROPHIC)
def test_catastrophic_pattern_is_cut_off(
    recorded: list[_RecordingPopen], pattern: str, text: str
) -> None:
    started = time.monotonic()
    result = search_all(compile_checked(pattern), text, timeout_s=TIMEOUT)
    elapsed = time.monotonic() - started

    assert result.timed_out
    assert result.failure is SearchFailure.TIMEOUT
    assert not result.complete and result.matches == ()
    assert elapsed < 2 * TIMEOUT + 1.0
    assert len(recorded) == 1
    _assert_reaped_by_sigkill(recorded[0])


def test_process_stays_responsive_after_timeout(recorded: list[_RecordingPopen]) -> None:
    rule = compile_checked("(a+)+$")
    text = "a" * 40 + "!"
    for _ in range(2):  # second run in the same process: nothing left hanging from the first
        started = time.monotonic()
        result = search_all(rule, text, timeout_s=TIMEOUT)
        assert result.timed_out
        assert time.monotonic() - started < 2 * TIMEOUT + 1.0

    ok = search_all(compile_checked("a+"), "aaa!", timeout_s=MAX_TIMEOUT_S)
    assert ok.complete and [m.text for m in ok.matches] == ["aaa"]

    assert len(recorded) == 3
    for proc in recorded[:2]:
        _assert_reaped_by_sigkill(proc)
    assert recorded[2].returncode == 0


@pytest.mark.parametrize(
    ("requested", "expected"),
    [(0.0, MIN_TIMEOUT_S), (-5.0, MIN_TIMEOUT_S), (3600.0, MAX_TIMEOUT_S), (1.0, 1.0)],
)
def test_timeout_is_clamped(
    monkeypatch: pytest.MonkeyPatch, requested: float, expected: float
) -> None:
    seen: list[float | None] = []
    real = subprocess.Popen.communicate

    def spy(self: subprocess.Popen[bytes], *args: object, **kwargs: object) -> object:
        if args:  # first call carries the input
            seen.append(kwargs.get("timeout"))  # type: ignore[arg-type]
        return real(self, *args, **kwargs)  # type: ignore[arg-type,misc]

    monkeypatch.setattr(subprocess.Popen, "communicate", spy)
    search_all(compile_checked("a"), "a", timeout_s=requested)
    assert seen == [expected]


# --- search_all: worker failures -------------------------------------------------------------


@pytest.mark.parametrize(
    "worker",
    [
        "import sys; sys.exit(3)",
        "import sys; sys.stdout.write('not json')",
        "import sys; sys.stdout.write('[[1]]')",
        "import sys; sys.stdout.write('{\"a\": 1}')",
    ],
)
def test_worker_failure_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch, worker: str
) -> None:
    monkeypatch.setattr(safe_regex, "_WORKER", worker)
    result = search_all(compile_checked("a"), "a", timeout_s=MAX_TIMEOUT_S)
    assert result.failure is SearchFailure.WORKER_FAILED
    assert not result.complete and result.matches == ()
