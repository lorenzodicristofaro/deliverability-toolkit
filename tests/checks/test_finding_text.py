"""M6-06b: localized rendering of ESP finding params (CLI text and web result template).

The API wire format is unchanged (keys + params); the text renderers turn tokens into phrases.
Table-driven, en + it, strict i18n mode (a missing key raises), no network.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import app.web.authentication  # noqa: F401  registers the finding_params filter
from app.checks.finding_text import (
    DKIM_SELECTOR_PART_KEY,
    PITFALL_NO_NOTE_KEY,
    PITFALL_WITH_NOTE_KEY,
    TOKEN_KEYS,
    display_params,
)
from app.checks.models import CheckResult, Finding, finding
from app.cli.check import render_text
from app.core import i18n
from app.core.i18n import LOCALES_DIR, has_key, placeholders, t
from app.web.templating import env

LANGS = ("en", "it")
NOTE_KEY = "esp.test_esp.link_branding"
NOTES = {
    "en": "Links are rewritten through a shared tracking domain unless you brand it.",
    "it": "I link passano da un dominio di tracking condiviso finché non lo personalizzi.",
}


@pytest.fixture(autouse=True)
def _strict() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture
def with_note(monkeypatch: pytest.MonkeyPatch) -> None:
    """A profile note key present in both catalogues (no shipped profile has one yet)."""
    real = i18n.load_catalogue

    def load(lang: str) -> dict[str, str]:
        return {**real(lang), NOTE_KEY: NOTES[lang]}

    monkeypatch.setattr(i18n, "load_catalogue", load)


def _catalogue(lang: str) -> dict[str, str]:
    data = json.loads((LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


# --- catalogue ----------------------------------------------------------------------------------


def _all_keys() -> set[str]:
    keys = {key for table in TOKEN_KEYS.values() for key in table.values()}
    return keys | {DKIM_SELECTOR_PART_KEY, PITFALL_WITH_NOTE_KEY, PITFALL_NO_NOTE_KEY}


@pytest.mark.parametrize("lang", LANGS)
def test_every_rendering_key_exists(lang: str) -> None:
    cat = _catalogue(lang)
    assert {k for k in _all_keys() if k not in cat} == set()


def test_rendering_keys_differ_between_languages() -> None:
    en, it = _catalogue("en"), _catalogue("it")
    same = {k for k in _all_keys() if en[k] == it[k]}
    assert same == {PITFALL_WITH_NOTE_KEY}  # "{code}: {note}" is language-neutral
    for k in _all_keys():
        assert placeholders(en[k]) == placeholders(it[k]), k


def test_no_unused_esp_rendering_key() -> None:
    ours = {k for k in _catalogue("en") if k.startswith("checks.esp.")}
    assert ours == _all_keys()


# --- display_params: tokens ---------------------------------------------------------------------

TOKEN_CASES = [
    (code, name, token, key)
    for (code, name), table in TOKEN_KEYS.items()
    for token, key in table.items()
]


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize(("code", "name", "token", "key"), TOKEN_CASES)
def test_known_tokens_are_localized(code: str, name: str, token: str, key: str, lang: str) -> None:
    out = display_params(code, {name: token, "esp": "Alpha"}, lang)
    assert out[name] == t(key, lang)
    assert out[name] != token
    assert out["esp"] == "Alpha"


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize(
    ("code", "params"),
    [
        ("ESP_SPF_PERMERROR", {"reason": "brand_new_reason"}),
        ("ESP_SPF_PERMERROR", {"reason": ""}),
        ("ESP_SPF_PERMERROR", {"reason": "chain_end"}),  # a DKIM token, not an SPF one
        ("ESP_DKIM_TARGET_MISMATCH", {"reason": "MULTIPLE_RECORDS"}),
        ("ESP_DKIM_TARGET_MISMATCH", {"reason": "loop "}),
        ("ESP_DNS_ERROR", {"part": "spf.unknown"}),
        ("ESP_DNS_ERROR", {"part": "dkim.selectors."}),  # no selector name
        ("ESP_DNS_ERROR", {"part": "dkim.selector"}),
        ("ESP_HOST_NOT_CONFIGURED", {"part": "{part}"}),
        ("ESP_DNS_ERROR", {"part": "checks.esp.part.return_path"}),  # a key is not a token
    ],
)
def test_unknown_tokens_keep_the_raw_value(code: str, params: dict[str, Any], lang: str) -> None:
    assert display_params(code, params, lang) == params


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize(
    ("code", "params"),
    [
        ("ESP_SPF_PERMERROR", {"reason": None}),
        ("ESP_SPF_PERMERROR", {"reason": 3}),
        ("ESP_SPF_PERMERROR", {"reason": ["multiple_records"]}),
        ("ESP_SPF_PERMERROR", {}),
        ("ESP_DNS_ERROR", {"part": {"spf": "includes"}}),
        ("ESP_PITFALL", {}),
        ("ESP_PITFALL", {"pitfall": 7, "notes_key": 7}),
        ("SPF_MISSING", {"reason": "multiple_records", "part": "spf.includes"}),  # other code
        ("", {"reason": "syntax_error"}),
    ],
)
def test_malformed_or_foreign_params_pass_through(
    code: str, params: dict[str, Any], lang: str
) -> None:
    assert display_params(code, params, lang) == params


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize("selector", ["s1", "k1", "selector-2024"])
def test_dkim_selector_part_names_the_selector(selector: str, lang: str) -> None:
    out = display_params("ESP_DNS_ERROR", {"part": f"dkim.selectors.{selector}"}, lang)
    assert out["part"] == t(DKIM_SELECTOR_PART_KEY, lang, selector=selector)
    assert selector in out["part"]
    assert "dkim.selectors." not in out["part"]


def test_display_params_does_not_mutate_the_input() -> None:
    params = {"reason": "loop", "esp": "Alpha"}
    display_params("ESP_DKIM_TARGET_MISMATCH", params, "it")
    assert params == {"reason": "loop", "esp": "Alpha"}


def test_unsupported_language_falls_back_to_english() -> None:
    out = display_params("ESP_SPF_PERMERROR", {"reason": "syntax_error"}, "fr")
    assert out["reason"] == t("checks.esp.reason.spf_permerror.syntax_error", "en")


# --- display_params: ESP_PITFALL note -----------------------------------------------------------


@pytest.mark.parametrize("lang", LANGS)
def test_pitfall_note_is_looked_up_in_the_language(with_note: None, lang: str) -> None:
    params = {"esp": "Alpha", "pitfall": "ESP_TEST_LINK", "notes_key": NOTE_KEY}
    out = display_params("ESP_PITFALL", params, lang)
    assert NOTES[lang] in out["pitfall"]
    assert "ESP_TEST_LINK" in out["pitfall"]
    assert NOTE_KEY not in out["pitfall"]
    assert out["notes_key"] == NOTE_KEY  # the key itself stays a param for the API/data


def test_pitfall_note_without_code_is_the_note(with_note: None) -> None:
    assert display_params("ESP_PITFALL", {"notes_key": NOTE_KEY}, "it")["pitfall"] == NOTES["it"]


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize(
    "notes_key",
    [None, "", "esp.not_in_catalogue.note", "no dots", 42, ["esp.x.y"]],
    ids=["none", "empty", "unknown", "malformed", "int", "list"],
)
def test_pitfall_without_a_usable_note_is_safe(notes_key: Any, lang: str) -> None:
    params: dict[str, Any] = {"esp": "Alpha", "pitfall": "ESP_TEST_LINK"}
    if notes_key is not None:
        params["notes_key"] = notes_key
    out = display_params("ESP_PITFALL", params, lang)
    assert out["pitfall"] == t(PITFALL_NO_NOTE_KEY, lang, code="ESP_TEST_LINK")
    if isinstance(notes_key, str) and notes_key:
        assert notes_key not in out["pitfall"]


def test_has_key() -> None:
    assert has_key("checks.esp.part.spf_includes", "it")
    assert has_key("checks.esp.part.spf_includes", "fr")  # English fallback
    assert not has_key("esp.not_in_catalogue.note", "en")
    assert not has_key("", "it")


# --- rendering paths: CLI text and web result template ------------------------------------------

_T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def _result(*findings: Finding) -> CheckResult:
    return CheckResult.build(
        check_id="esp",
        target="example.org",
        findings=findings,
        evaluated=False,
        started_at=_T0,
        duration_ms=1,
    )


def _cli(result: CheckResult, lang: str) -> str:
    return render_text([result], lang)


def _web(result: CheckResult, lang: str) -> str:
    return env.get_template("checks/_result.html").render(
        lang=lang, t=lambda key, **params: t(key, lang, **params), result=result
    )


RENDERERS: list[Callable[[CheckResult, str], str]] = [_cli, _web]
RENDERER_IDS = ["cli", "web"]

RENDER_CASES = [
    (
        "spf_permerror_multiple",
        finding(
            "ESP_SPF_PERMERROR",
            "high",
            {"esp": "Alpha", "name": "example.org", "reason": "multiple_records"},
        ),
        "checks.esp.reason.spf_permerror.multiple_records",
        {},
        "multiple_records",
    ),
    (
        "spf_permerror_syntax",
        finding(
            "ESP_SPF_PERMERROR",
            "high",
            {"esp": "Alpha", "name": "example.org", "reason": "syntax_error"},
        ),
        "checks.esp.reason.spf_permerror.syntax_error",
        {},
        "syntax_error",
    ),
    *[
        (
            f"dkim_{reason}",
            finding(
                "ESP_DKIM_TARGET_MISMATCH",
                "medium",
                {
                    "esp": "Alpha",
                    "selector": "s1",
                    "name": "s1._domainkey.example.org",
                    "pattern": "*.dkim.alpha.example",
                    "reason": reason,
                },
            ),
            f"checks.esp.reason.dkim_mismatch.{reason}",
            {},
            reason,
        )
        for reason in ("chain_end", "loop", "empty_target", "hop_limit")
    ],
    *[
        (
            f"dns_error_{part}",
            finding(
                "ESP_DNS_ERROR",
                "low",
                {
                    "esp": "Alpha",
                    "part": part,
                    "name": "example.org",
                    "rdtype": "TXT",
                    "state": "timeout",
                },
            ),
            key,
            {},
            part,
        )
        for part, key in (
            ("spf.includes", "checks.esp.part.spf_includes"),
            ("return_path", "checks.esp.part.return_path"),
            ("tracking_domain", "checks.esp.part.tracking_domain"),
        )
    ],
    (
        "dns_error_dkim_selector",
        finding(
            "ESP_DNS_ERROR",
            "low",
            {
                "esp": "Alpha",
                "part": "dkim.selectors.s1",
                "name": "s1._domainkey.example.org",
                "rdtype": "CNAME",
                "state": "servfail",
            },
        ),
        DKIM_SELECTOR_PART_KEY,
        {"selector": "s1"},
        "dkim.selectors.s1",
    ),
    (
        "host_not_configured",
        finding("ESP_HOST_NOT_CONFIGURED", "info", {"esp": "Alpha", "part": "tracking_domain"}),
        "checks.esp.part.tracking_domain",
        {},
        "tracking_domain",
    ),
]


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize("render", RENDERERS, ids=RENDERER_IDS)
@pytest.mark.parametrize(
    ("f", "key", "key_params", "raw"),
    [c[1:] for c in RENDER_CASES],
    ids=[c[0] for c in RENDER_CASES],
)
def test_tokens_render_localized(
    render: Callable[[CheckResult, str], str],
    f: Finding,
    key: str,
    key_params: dict[str, str],
    raw: str,
    lang: str,
) -> None:
    out = render(_result(f), lang)
    assert t(key, lang, **key_params) in out
    assert not re.search(rf"(?<![\w.]){re.escape(raw)}(?![\w.])", out), out
    assert "checks.esp." not in out and "finding.ESP_" not in out


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize("render", RENDERERS, ids=RENDERER_IDS)
@pytest.mark.parametrize(
    "esps", [["Alpha", "Beta"], ["Alpha", "Beta", "Gamma"]], ids=["two", "three"]
)
def test_spf_lookups_error_reads_with_several_esps(
    render: Callable[[CheckResult, str], str], esps: list[str], lang: str
) -> None:
    joined = ", ".join(esps)  # as the check builds it
    f = finding(
        "ESP_DNS_ERROR",
        "low",
        {"esp": joined, "part": "spf.lookups", "name": "example.org", "rdtype": "TXT"}
        | {"state": "timeout"},
    )
    out = render(_result(f), lang)
    label = t("checks.esp.part.spf_lookups", lang)
    connector = {"en": " of ", "it": " di "}[lang]
    assert f"{label}{connector}{joined}" in out
    assert "spf.lookups" not in out


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize("render", RENDERERS, ids=RENDERER_IDS)
def test_pitfall_renders_the_note(
    with_note: None, render: Callable[[CheckResult, str], str], lang: str
) -> None:
    f = finding(
        "ESP_PITFALL",
        "info",
        {"esp": "Alpha", "pitfall": "ESP_TEST_LINK", "notes_key": NOTE_KEY}
        | {"declared_severity": "low"},
    )
    out = render(_result(f), lang)
    assert NOTES[lang] in out.replace("&#39;", "'")
    assert NOTE_KEY not in out


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize("render", RENDERERS, ids=RENDERER_IDS)
@pytest.mark.parametrize("notes_key", [None, "esp.not_in_catalogue.note"], ids=["none", "unknown"])
def test_pitfall_without_note_renders_safely(
    render: Callable[[CheckResult, str], str], notes_key: str | None, lang: str
) -> None:
    f = finding(
        "ESP_PITFALL",
        "info",
        {"esp": "Alpha", "pitfall": "ESP_TEST_LINK", "notes_key": notes_key}
        | {"declared_severity": "low"},
    )
    out = render(_result(f), lang)
    expected = t(PITFALL_NO_NOTE_KEY, lang, code="ESP_TEST_LINK")
    assert expected in out.replace("&#39;", "'")
    assert "esp.not_in_catalogue" not in out


@pytest.mark.parametrize("render", RENDERERS, ids=RENDERER_IDS)
def test_unknown_token_renders_raw_without_crashing(
    render: Callable[[CheckResult, str], str],
) -> None:
    f = finding(
        "ESP_SPF_PERMERROR",
        "high",
        {"esp": "Alpha", "name": "example.org", "reason": "future_reason"},
    )
    for lang in LANGS:
        assert "future_reason" in render(_result(f), lang)


def test_web_keeps_dns_strings_visible_safe() -> None:
    f = finding(
        "ESP_DNS_ERROR",
        "low",
        {"esp": "Al\x00pha", "part": "spf.includes", "name": "ex\x1bample.org"}
        | {"rdtype": "TXT", "state": "timeout"},
    )
    out = _web(_result(f), "en")
    assert "\x00" not in out and "\x1b" not in out
    assert "Al\\x00pha" in out
