"""Message catalogue lookup and language resolution (ARCHITECTURE section 10).

Catalogues are flat ``dotted.key -> template`` JSON files in ``locales/``. Templates use
``str.format`` placeholders such as ``{entry}``. No network access.
"""

from __future__ import annotations

import json
import logging
import string
from functools import cache
from pathlib import Path

logger = logging.getLogger(__name__)

SUPPORTED_LANGUAGES = ("en", "it")
DEFAULT_LANGUAGE = "en"
LOCALES_DIR = Path(__file__).resolve().parents[2] / "locales"

_strict = False
_warned: set[str] = set()


class MissingKeyError(KeyError):
    """Raised for an unknown message key when strict mode is on (tests)."""


def set_strict(value: bool) -> None:
    """Strict mode raises on unknown keys; otherwise the key is returned and logged once."""
    global _strict
    _strict = value


@cache
def load_catalogue(lang: str) -> dict[str, str]:
    path = LOCALES_DIR / f"{lang}.json"
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def _missing(key: str, lang: str) -> str:
    if _strict:
        raise MissingKeyError(key)
    if key not in _warned:
        _warned.add(key)
        logger.warning("i18n key missing", extra={"i18n_key": key, "lang": lang})
    return key


def t(key: str, lang: str = DEFAULT_LANGUAGE, **params: object) -> str:
    """Translate ``key`` into ``lang``, falling back to English, then to the key itself."""
    template = load_catalogue(lang).get(key) if lang in SUPPORTED_LANGUAGES else None
    if template is None:
        template = load_catalogue(DEFAULT_LANGUAGE).get(key)
    if template is None:
        return _missing(key, lang)
    try:
        return template.format_map(params)
    except (KeyError, IndexError, ValueError):
        if _strict:
            raise
        return template


def placeholders(template: str) -> set[str]:
    """Names of the ``{placeholders}`` used by a template."""
    return {name for _, name, _, _ in string.Formatter().parse(template) if name}


def _normalise(lang: str | None) -> str | None:
    if not lang:
        return None
    primary = lang.strip().lower().replace("_", "-").split("-", 1)[0]
    return primary if primary in SUPPORTED_LANGUAGES else None


def parse_accept_language(header: str | None) -> list[str]:
    """Supported primary languages from an Accept-Language header, best first.

    Malformed entries and bad q-values are skipped; q=0 means "not acceptable".
    """
    if not header:
        return []
    ranked: list[tuple[float, int, str]] = []
    for index, part in enumerate(header.split(",")):
        tag, *attrs = (p.strip() for p in part.split(";"))
        lang = _normalise(tag)
        if lang is None:
            continue
        q = 1.0
        for attr in attrs:
            name, _, value = attr.partition("=")
            if name.strip().lower() == "q":
                try:
                    q = float(value.strip())
                except ValueError:
                    q = -1.0
        if 0 < q <= 1:
            ranked.append((-q, index, lang))
    return [lang for _, _, lang in sorted(ranked)]


def resolve_language(
    user_pref: str | None = None,
    tenant_pref: str | None = None,
    accept_language: str | None = None,
    default: str = DEFAULT_LANGUAGE,
) -> str:
    """Pick a language: user pref > tenant pref > Accept-Language > default."""
    for candidate in (user_pref, tenant_pref):
        lang = _normalise(candidate)
        if lang:
            return lang
    accepted = parse_accept_language(accept_language)
    if accepted:
        return accepted[0]
    return _normalise(default) or DEFAULT_LANGUAGE
