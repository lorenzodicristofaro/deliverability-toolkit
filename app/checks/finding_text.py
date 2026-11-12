"""Display values for finding params in the reader's language (M6-06b).

A ``Finding`` carries stable tokens in ``params``; the API wire format stays keys + params. The
text renderers (CLI text, web templates) call :func:`display_params` before formatting the
finding's templates, so tokens that are not meant to be read raw become localized phrases:

- ``reason`` of ``ESP_SPF_PERMERROR`` and ``ESP_DKIM_TARGET_MISMATCH``;
- ``part`` of ``ESP_DNS_ERROR`` and ``ESP_HOST_NOT_CONFIGURED`` (``dkim.selectors.<name>`` and,
  M6-23, ``dkim.alternatives.<name>`` name the selector);
- ``pitfall`` of ``ESP_PITFALL`` becomes the profile's note (``params.notes_key``) plus the code.

An unknown token keeps its raw value. A missing or unknown ``notes_key`` gives a localized
"no note available" text with the code, never the raw key. Malformed params never raise.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from app.core.i18n import has_key, t

DKIM_SELECTOR_PART_KEY: Final = "checks.esp.part.dkim_selector"
PITFALL_WITH_NOTE_KEY: Final = "checks.esp.pitfall.with_note"
PITFALL_NO_NOTE_KEY: Final = "checks.esp.pitfall.no_note"
DKIM_SELECTOR_PART_PREFIX: Final = "dkim.selectors."
DKIM_ALTERNATIVE_PART_PREFIX: Final = "dkim.alternatives."

_PARTS: Final[Mapping[str, str]] = {
    "spf.includes": "checks.esp.part.spf_includes",
    "spf.lookups": "checks.esp.part.spf_lookups",
    "return_path": "checks.esp.part.return_path",
    "tracking_domain": "checks.esp.part.tracking_domain",
    "domain": "checks.esp.part.domain",
}

# (finding code, param name) -> token -> catalogue key
TOKEN_KEYS: Final[Mapping[tuple[str, str], Mapping[str, str]]] = {
    ("ESP_SPF_PERMERROR", "reason"): {
        "multiple_records": "checks.esp.reason.spf_permerror.multiple_records",
        "syntax_error": "checks.esp.reason.spf_permerror.syntax_error",
    },
    ("ESP_DKIM_TARGET_MISMATCH", "reason"): {
        "chain_end": "checks.esp.reason.dkim_mismatch.chain_end",
        "loop": "checks.esp.reason.dkim_mismatch.loop",
        "empty_target": "checks.esp.reason.dkim_mismatch.empty_target",
        "hop_limit": "checks.esp.reason.dkim_mismatch.hop_limit",
    },
    ("ESP_DNS_ERROR", "part"): _PARTS,
    ("ESP_HOST_NOT_CONFIGURED", "part"): _PARTS,
}


def _dkim_part(value: str, lang: str) -> str:
    """``dkim.selectors.<name>`` or ``dkim.alternatives.<name>`` -> "the DKIM selector <name>";
    anything else stays raw."""
    for prefix in (DKIM_SELECTOR_PART_PREFIX, DKIM_ALTERNATIVE_PART_PREFIX):
        if value.startswith(prefix):
            selector = value[len(prefix) :]
            if selector:
                return t(DKIM_SELECTOR_PART_KEY, lang, selector=selector)
    return value


def _pitfall(params: Mapping[str, Any], lang: str) -> str | None:
    raw = params.get("pitfall")
    code = raw if isinstance(raw, str) else None
    notes_key = params.get("notes_key")
    if isinstance(notes_key, str) and notes_key and has_key(notes_key, lang):
        note = t(notes_key, lang, esp=params.get("esp", ""))  # a note may name {esp}, no more
        if code is None:
            return note
        return t(PITFALL_WITH_NOTE_KEY, lang, note=note, code=code)
    if code is None:
        return None
    return t(PITFALL_NO_NOTE_KEY, lang, code=code)


def display_params(code: str, params: Mapping[str, Any], lang: str) -> dict[str, Any]:
    """``params`` with known tokens replaced by text in ``lang``; every other value unchanged."""
    out = dict(params)
    for (c, name), table in TOKEN_KEYS.items():
        if c != code:
            continue
        value = out.get(name)
        if not isinstance(value, str):
            continue
        key = table.get(value)
        if key is not None:
            out[name] = t(key, lang)
        elif name == "part":
            out[name] = _dkim_part(value, lang)
    if code == "ESP_PITFALL":
        pitfall = _pitfall(params, lang)
        if pitfall is not None:
            out["pitfall"] = pitfall
    return out
