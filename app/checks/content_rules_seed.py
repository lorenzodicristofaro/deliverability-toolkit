"""Content rules seed: global rules loaded from `seeds/content_rules.yaml` (M5-12).

Follows the `app.dns.knowledge` / `app.checks.dkim_selectors` pattern: strict schema (unknown
keys rejected), per-rule `verified_on` (always a date, never in the future: the day the rule's
basis was last reviewed) and `sources`. A `verified` rule needs 1..MAX_SOURCES distinct https
sources; an `unverified` rule may have none and must ship `enabled: false`. Every regex pattern
goes through `app.core.safe_regex.compile_checked`. The bounds are the `content_rules` column
limits, so a parsed rule is also a valid global row. Language codes get the repository's format
check, not a lookup in a language registry.

Rule text is not in the seed: it comes from the i18n keys `CONTENT_RULE.<key>.title` and
`CONTENT_RULE.<key>.advice` (en + it), so seed keys are restricted to `[a-z0-9_]` (no dot that
would make the derived key ambiguous). No network.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from typing import Final
from urllib.parse import urlsplit

from app.core.safe_regex import MAX_PATTERN_LENGTH, RegexRuleError, compile_checked
from app.dns.knowledge import (
    KnowledgeError,
    _check_keys,
    _date,
    _fail,
    _status,
    _str,
    _url_list,
)
from app.models.content_rule import (
    KINDS,
    MAX_CATEGORY_LENGTH,
    MAX_LANGUAGE_LENGTH,
    MAX_SEED_KEY_LENGTH,
    MAX_SOURCE_URL_LENGTH,
    MAX_SOURCES,
    MAX_WEIGHT,
    MIN_WEIGHT,
    SEVERITIES,
)

CONTENT_RULES_FILE: Final = "content_rules.yaml"
MAX_SEED_RULES: Final = 200
I18N_PREFIX: Final = "CONTENT_RULE"

FLAG_NAMES: Final[dict[str, int]] = {
    "ignorecase": int(re.IGNORECASE),
    "multiline": int(re.MULTILINE),
    "dotall": int(re.DOTALL),
    "verbose": int(re.VERBOSE),
    "ascii": int(re.ASCII),
}

_KEY = re.compile(r"[a-z0-9][a-z0-9_]*")
_CATEGORY = re.compile(r"[a-z0-9][a-z0-9_.-]*")  # the repository's slug rule
_LANGUAGE = re.compile(r"[a-z]{2,3}(?:-[a-z0-9]{2,8})*")  # the repository's language rule
_REQUIRED: Final = {
    "key",
    "kind",
    "pattern",
    "weight",
    "category",
    "severity",
    "language",
    "enabled",
    "status",
    "verified_on",
    "sources",
}
_OPTIONAL: Final = frozenset({"flags"})


@dataclass(frozen=True, slots=True)
class SeedRule:
    key: str
    kind: str
    pattern: str
    flags: int
    weight: int
    category: str
    severity: str
    language: str | None
    enabled: bool
    status: str
    verified_on: date
    sources: tuple[str, ...]


def i18n_keys(seed_key: str) -> tuple[str, str]:
    """The (title, advice) message keys of a seeded rule."""
    return f"{I18N_PREFIX}.{seed_key}.title", f"{I18N_PREFIX}.{seed_key}.advice"


def _int(value: object, where: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise _fail(where, f"must be an integer between {low} and {high}")
    return value


def _choice(value: object, where: str, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise _fail(where, f"must be one of {choices}")
    return value


def _flags(value: object, where: str) -> int:
    if not isinstance(value, list):
        raise _fail(where, f"must be a list of flag names {sorted(FLAG_NAMES)}")
    result = 0
    for name in value:
        if not isinstance(name, str) or name not in FLAG_NAMES:
            raise _fail(where, f"unknown flag; allowed {sorted(FLAG_NAMES)}")
        result |= FLAG_NAMES[name]
    if len(set(value)) != len(value):
        raise _fail(where, "duplicate flag")
    return result


def _pattern(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise _fail(where, "must be a string")
    if any(unicodedata.category(c) == "Cs" for c in value):
        raise _fail(where, "lone surrogate code point")
    return value


def _language(value: object, where: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > MAX_LANGUAGE_LENGTH
        or not value.isascii()
        or not _LANGUAGE.fullmatch(value)
    ):
        raise _fail(where, "must be null or a lowercase language code such as 'en' or 'pt-br'")
    return value


def _sources(value: object, where: str) -> tuple[str, ...]:
    urls = _url_list(value, where)
    if len(urls) > MAX_SOURCES:
        raise _fail(where, f"at most {MAX_SOURCES} sources")
    if len(set(urls)) != len(urls):
        raise _fail(where, "duplicate source")
    for url in urls:
        if len(url) > MAX_SOURCE_URL_LENGTH or any(
            c.isspace() or unicodedata.category(c) in ("Cc", "Cs") for c in url
        ):
            raise _fail(where, "invalid source URL")
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if not host:
            raise _fail(where, "invalid source URL")
    return urls


def _rule(raw: object, w: str, today: date) -> SeedRule:
    e = _check_keys(raw, w, _REQUIRED, _OPTIONAL)
    key = _str(e["key"], f"{w}.key")
    if len(key) > MAX_SEED_KEY_LENGTH or not _KEY.fullmatch(key):
        raise _fail(f"{w}.key", "must be a lowercase [a-z0-9_] identifier")
    kind = _choice(e["kind"], f"{w}.kind", KINDS)
    pattern = _pattern(e["pattern"], f"{w}.pattern")
    flags = _flags(e.get("flags", []), f"{w}.flags")
    if kind == "regex":
        try:
            compile_checked(pattern, flags)
        except RegexRuleError as exc:
            raise _fail(
                f"{w}.pattern", f"rejected by compile_checked: {exc.reason.value}"
            ) from None
    else:
        # A keyword is a literal: the column bounds, no control characters (NUL included), no
        # surrounding whitespace. Regex flags would be silently meaningless on it.
        if (
            not pattern.strip()
            or pattern.strip() != pattern
            or len(pattern) > MAX_PATTERN_LENGTH
            or any(unicodedata.category(c) == "Cc" for c in pattern)
        ):
            raise _fail(f"{w}.pattern", "keyword must be 1..MAX_PATTERN_LENGTH trimmed chars")
        if flags:
            raise _fail(f"{w}.flags", "flags apply to regex rules only")
    category = _str(e["category"], f"{w}.category")
    if len(category) > MAX_CATEGORY_LENGTH or not _CATEGORY.fullmatch(category):
        raise _fail(f"{w}.category", "must be a lowercase slug")
    enabled = e["enabled"]
    if not isinstance(enabled, bool):
        raise _fail(f"{w}.enabled", "must be true or false")
    status = _status(e["status"], f"{w}.status")
    verified_on = _date(e["verified_on"], f"{w}.verified_on", today)
    sources = _sources(e["sources"], f"{w}.sources")
    if status == "verified" and not sources:
        raise _fail(w, "verified rules need a non-empty sources list")
    if status == "unverified" and enabled:
        raise _fail(w, "unverified rules must ship enabled: false")
    return SeedRule(
        key=key,
        kind=kind,
        pattern=pattern,
        flags=flags,
        weight=_int(e["weight"], f"{w}.weight", MIN_WEIGHT, MAX_WEIGHT),
        category=category,
        severity=_choice(e["severity"], f"{w}.severity", SEVERITIES),
        language=_language(e["language"], f"{w}.language"),
        enabled=enabled,
        status=status,
        verified_on=verified_on,
        sources=sources,
    )


def parse_content_rules(data: object, today: date | None = None) -> tuple[SeedRule, ...]:
    """Validate the parsed YAML document; raise `KnowledgeError` on any violation."""
    today = today or date.today()
    root = _check_keys(data, "content rules file", {"rules"})
    items = root["rules"]
    if not isinstance(items, list) or not items:
        raise _fail("rules", "must be a non-empty list")
    if len(items) > MAX_SEED_RULES:
        raise _fail("rules", f"at most {MAX_SEED_RULES} entries")
    out: list[SeedRule] = []
    seen: set[str] = set()
    for i, raw in enumerate(items):
        rule = _rule(raw, f"rules[{i}]", today)
        if rule.key in seen:
            raise _fail(f"rules[{i}].key", f"duplicate key {rule.key!r}")
        seen.add(rule.key)
        out.append(rule)
    return tuple(out)


__all__ = [
    "CONTENT_RULES_FILE",
    "FLAG_NAMES",
    "KnowledgeError",
    "SeedRule",
    "i18n_keys",
    "parse_content_rules",
]
