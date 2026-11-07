"""Offline Subject line facts (M5-11). Facts only: findings and i18n live in M5-14.

The Subject is hostile input. ``analyze_subject`` never raises on text and does no I/O.

Input: normally the *decoded* Subject (M4-01). With ``encoded=True`` the value is treated as
a raw header value: folding (CR/LF followed by whitespace) is removed and RFC 2047 encoded
words are decoded with the M4 decoder (``app.parsers.message.decode_rfc2047``, not a copy).

Evaluation contract: a fact that could not be evaluated is ``None``, never ``False``.
``subject=None`` (header absent) leaves every fact ``None`` except ``present=False``.

Length methods:
- ``length_codepoints``: ``len(str)`` of the (unfolded, decoded) text.
- ``length_bytes``: UTF-8 length; lone surrogates count as 3 bytes (``surrogatepass``).
- ``length_graphemes``: grapheme-ish approximation, NOT full UAX #29 (stdlib has no segmenter).
  Not counted as own units: combining marks (Mn/Me/Mc), ZWJ/ZWNJ, variation selectors,
  emoji skin-tone modifiers (U+1F3FB-1F3FF), tag characters, and the second regional
  indicator of a flag pair. Hangul jamo sequences and Indic conjuncts are not merged.
  Emoji ZWJ sequences count as one unit.

Heuristics: every threshold in this module (``SUBJECT_*`` constants) is a heuristic chosen
by this project. They are `unverified`: no official Gmail/Outlook/other vendor source has
been checked for them and none must be attributed to a vendor. Findings must be advisory.

Caveats: the caps ratio only considers cased letters, so scripts without case (CJK, Arabic,
Hebrew, Thai, ...) are excluded; ``caseless_letters`` reports how many were skipped. Emoji
detection is range based (approximation), and script detection uses Unicode character names.
Size facts (code points, bytes) describe the full text; all other facts describe the first
``max_chars`` characters (``capped=True`` when the text was longer).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from app.parsers.message import _Warnings, decode_rfc2047

# --- Heuristic thresholds (unverified, project-chosen, NOT vendor guidance) -------------
SUBJECT_LONG_GRAPHEMES = 100
SUBJECT_CAPS_RATIO = 0.7
SUBJECT_CAPS_MIN_CASED_LETTERS = 8
SUBJECT_PUNCT_RUN_MIN = 2
SUBJECT_MAX_ANALYSED_CHARS = 10_000  # input cap; analysis runs on the prefix


@dataclass(frozen=True)
class SubjectLimits:
    max_chars: int = SUBJECT_MAX_ANALYSED_CHARS
    long_graphemes: int = SUBJECT_LONG_GRAPHEMES
    caps_ratio: float = SUBJECT_CAPS_RATIO
    caps_min_cased_letters: int = SUBJECT_CAPS_MIN_CASED_LETTERS
    punct_run_min: int = SUBJECT_PUNCT_RUN_MIN


@dataclass(frozen=True)
class SubjectFacts:
    present: bool
    length_codepoints: int | None = None
    length_bytes: int | None = None
    length_graphemes: int | None = None  # of the analysed prefix
    is_long: bool | None = None  # graphemes > limits.long_graphemes (heuristic)
    empty: bool | None = None  # empty or whitespace-only
    capped: bool | None = None  # analysis ran on the first max_chars characters only
    cased_letters: int | None = None
    caseless_letters: int | None = None
    caps_ratio: float | None = None  # None when no cased letters
    all_caps: bool | None = None  # None when too few cased letters to judge
    max_punct_run: int | None = None  # longest run of ! / ? (ASCII and fullwidth)
    has_punct_run: bool | None = None
    emoji_count: int | None = None
    reply_prefix: str | None = None  # "re" or "fwd" (normalised) when present
    reply_prefix_without_in_reply_to: bool | None = None  # None if header state unknown
    control_chars: int | None = None  # Cc other than tab (NUL included)
    has_nul: bool | None = None
    bidi_controls: int | None = None
    has_bidi_override: bool | None = None  # U+202A-202E, U+2066-2069
    scripts: tuple[str, ...] | None = None
    mixed_scripts: bool | None = None
    mixed_script_word: bool | None = None  # one word mixing scripts (e.g. Latin + Cyrillic)


_FOLD = re.compile(r"\r\n?|\n")
_REPLY = re.compile(r"^\s*(re|fwd?)\s*(?:\[\d{1,4}\])?\s*:", re.IGNORECASE)
_PUNCT = frozenset("!?！？")
_BIDI_ALL = frozenset([0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])
_BIDI_OVERRIDE = frozenset([*range(0x202A, 0x202F), *range(0x2066, 0x206A)])
_ZERO_WIDTH_JOIN = frozenset([0x200C, 0x200D])
_SCRIPT_GROUPS = {"HIRAGANA": "CJK", "KATAKANA": "CJK", "CJK": "CJK", "BOPOMOFO": "CJK"}
_MISC_EMOJI = frozenset(
    [0x231A, 0x231B, 0x23E9, 0x23F0, 0x2B05, 0x2B06, 0x2B07, 0x2934, 0x2935, 0x2B1B, 0x2B1C]
)


def _is_emoji_base(cp: int) -> bool:
    return (
        0x1F300 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27BF
        or 0x1F000 <= cp <= 0x1F2FF
        or 0x2B50 <= cp <= 0x2B55
        or cp in _MISC_EMOJI
    )


def _is_extender(ch: str) -> bool:
    cp = ord(ch)
    return (
        cp in _ZERO_WIDTH_JOIN
        or 0xFE00 <= cp <= 0xFE0F
        or 0x1F3FB <= cp <= 0x1F3FF
        or 0xE0020 <= cp <= 0xE007F
        or unicodedata.category(ch) in ("Mn", "Me", "Mc")
    )


def _segment(text: str) -> tuple[int, int]:
    """Return (grapheme-ish units, emoji units) for ``text``."""
    units = 0
    emoji = 0
    i = 0
    n = len(text)
    while i < n:
        cp = ord(text[i])
        units += 1
        is_emoji = _is_emoji_base(cp)
        i += 1
        if 0x1F1E6 <= cp <= 0x1F1FF:  # flag: pair of regional indicators
            if i < n and 0x1F1E6 <= ord(text[i]) <= 0x1F1FF:
                i += 1
            is_emoji = True
        elif (0x30 <= cp <= 0x39 or cp in (0x23, 0x2A)) and text[i : i + 2] == "️⃣":
            is_emoji = True  # keycap sequence
        while i < n and _is_extender(text[i]):
            if ord(text[i]) == 0x200D and i + 1 < n and _is_emoji_base(ord(text[i + 1])):
                i += 2  # ZWJ joins the next emoji into the same unit
                is_emoji = True
                continue
            i += 1
        if is_emoji:
            emoji += 1
    return units, emoji


def _script(ch: str) -> str:
    try:
        first = unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return "UNKNOWN"
    return _SCRIPT_GROUPS.get(first, first)


def analyze_subject(
    subject: str | None,
    *,
    limits: SubjectLimits | None = None,
    has_in_reply_to: bool | None = None,
    encoded: bool = False,
) -> SubjectFacts:
    """Compute facts about ``subject``. ``has_in_reply_to`` is supplied by the caller."""
    lim = limits or SubjectLimits()
    if subject is None:
        return SubjectFacts(present=False)

    text = subject
    if encoded:
        text = _FOLD.sub("", text)  # unfold: line break removed, the whitespace stays
        text = decode_rfc2047(text, 0, _Warnings())
    length_cp = len(text)
    length_bytes = len(text.encode("utf-8", errors="surrogatepass"))
    capped = length_cp > lim.max_chars
    body = text[: lim.max_chars]

    graphemes, emoji = _segment(body)
    upper = lower = caseless = 0
    controls = nul = bidi = bidi_override = 0
    run = max_run = 0
    scripts: set[str] = set()
    mixed_word = False
    word_scripts: set[str] = set()
    for ch in body + " ":
        cp = ord(ch)
        cat = unicodedata.category(ch)
        if cat == "Cc" and ch != "\t":
            controls += 1
            nul += cp == 0
        if cp in _BIDI_ALL:
            bidi += 1
            bidi_override += cp in _BIDI_OVERRIDE
        if ch in _PUNCT:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 0
        if ch.isalpha():
            if ch.isupper():
                upper += 1
            elif ch.islower():
                lower += 1
            else:
                caseless += 1
            sc = _script(ch)
            scripts.add(sc)
            word_scripts.add(sc)
        elif cat not in ("Mn", "Mc", "Me", "Nd") and cp not in _ZERO_WIDTH_JOIN:
            if len(word_scripts) > 1:
                mixed_word = True
            word_scripts = set()

    cased = upper + lower
    ratio = upper / cased if cased else None
    all_caps: bool | None = None
    if ratio is not None and cased >= lim.caps_min_cased_letters:
        all_caps = ratio >= lim.caps_ratio

    prefix = None
    m = _REPLY.match(body)
    if m:
        prefix = "re" if m.group(1).lower() == "re" else "fwd"
    without_irt: bool | None
    if prefix is None:
        without_irt = False
    elif has_in_reply_to is None:
        without_irt = None
    else:
        without_irt = not has_in_reply_to

    return SubjectFacts(
        present=True,
        length_codepoints=length_cp,
        length_bytes=length_bytes,
        length_graphemes=graphemes,
        is_long=graphemes > lim.long_graphemes,
        empty=body.strip() == "" and not capped,
        capped=capped,
        cased_letters=cased,
        caseless_letters=caseless,
        caps_ratio=ratio,
        all_caps=all_caps,
        max_punct_run=max_run,
        has_punct_run=max_run >= lim.punct_run_min,
        emoji_count=emoji,
        reply_prefix=prefix,
        reply_prefix_without_in_reply_to=without_irt,
        control_chars=controls,
        has_nul=nul > 0,
        bidi_controls=bidi,
        has_bidi_override=bidi_override > 0,
        scripts=tuple(sorted(scripts)),
        mixed_scripts=len(scripts) > 1,
        mixed_script_word=mixed_word,
    )
