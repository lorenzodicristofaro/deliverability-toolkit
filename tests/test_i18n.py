"""i18n catalogue consistency, lookup and language resolution tests. No network."""

from __future__ import annotations

import ast
import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core import i18n
from app.core.i18n import (
    LOCALES_DIR,
    MissingKeyError,
    parse_accept_language,
    placeholders,
    resolve_language,
    t,
)

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def _load(lang: str) -> dict[str, str]:
    data = json.loads((LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def used_keys(source: str) -> set[str]:
    """Literal keys passed to ``t("...")`` plus string constants assigned to ``*_KEY`` names."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "t"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            found.add(node.args[0].value)
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            for target in targets:
                if isinstance(target, ast.Name) and target.id.endswith("_KEY"):
                    found.add(value.value)
    return found


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


# --- catalogue consistency -------------------------------------------------------------------


def test_en_and_it_have_the_same_keys() -> None:
    en, it = set(_load("en")), set(_load("it"))
    assert en - it == set(), "keys missing from it.json"
    assert it - en == set(), "keys missing from en.json"


@pytest.mark.parametrize("lang", ["en", "it"])
def test_no_empty_values(lang: str) -> None:
    empty = [k for k, v in _load(lang).items() if not isinstance(v, str) or not v.strip()]
    assert empty == []


@pytest.mark.parametrize("lang", ["en", "it"])
def test_keys_sorted(lang: str) -> None:
    keys = list(_load(lang))
    assert keys == sorted(keys)


def test_placeholders_match_between_languages() -> None:
    en, it = _load("en"), _load("it")
    mismatched = {k: (placeholders(en[k]), placeholders(it[k])) for k in en.keys() & it.keys()}
    assert {k: v for k, v in mismatched.items() if v[0] != v[1]} == {}


def test_every_key_used_in_app_exists_in_en() -> None:
    en = _load("en")
    missing: dict[str, set[str]] = {}
    for path in sorted(APP_DIR.rglob("*.py")):
        keys = used_keys(path.read_text(encoding="utf-8")) - en.keys()
        if keys:
            missing[str(path.relative_to(APP_DIR))] = keys
    assert missing == {}


def test_config_error_keys_are_all_declared() -> None:
    # The scan above would also catch these; this pins the config.py constants explicitly.
    from app.core import config

    declared = {v for k, v in vars(config).items() if k.endswith("_KEY") and isinstance(v, str)}
    assert declared >= {
        "config.resolver_addr.invalid",
        "config.missing",
        "config.invalid_value",
        "config.resolver_addrs_required",
    }
    for lang in ("en", "it"):
        assert declared <= _load(lang).keys()


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('t("a.b")', {"a.b"}),
        ('t("a.b", "it", x=1)', {"a.b"}),
        ('FOO_KEY = "c.d"', {"c.d"}),
        ('FOO_KEY: str = "c.d"', {"c.d"}),
        ("x = t(some_var)", set()),
        ('FOO = "not.a.key"', set()),
        ('obj.t("a.b")', set()),
        ("t()", set()),
        ("", set()),
    ],
)
def test_scanner_finds_keys(source: str, expected: set[str]) -> None:
    assert used_keys(source) == expected


def test_scanner_would_flag_a_missing_key() -> None:
    assert used_keys('NEW_KEY = "config.not_in_catalogue"') - _load("en").keys() == {
        "config.not_in_catalogue"
    }


# --- t() --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lang", "expected"),
    [
        ("en", 'Invalid RESOLVER_ADDRS entry "x"'),
        ("it", 'Voce RESOLVER_ADDRS non valida "x"'),
        ("fr", 'Invalid RESOLVER_ADDRS entry "x"'),  # unsupported -> en
    ],
)
def test_t_translates_and_falls_back(lang: str, expected: str) -> None:
    assert t("config.resolver_addr.invalid", lang, entry="x").startswith(expected)


def test_t_unknown_key_strict_raises() -> None:
    with pytest.raises(MissingKeyError):
        t("no.such.key")


def test_t_unknown_key_production_returns_key_and_logs_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    i18n.set_strict(False)
    with caplog.at_level(logging.WARNING, logger="app.core.i18n"):
        assert t("no.such.key") == "no.such.key"
        assert t("no.such.key", "it") == "no.such.key"
    assert len(caplog.records) == 1


def test_t_missing_param_strict_raises_and_production_returns_template() -> None:
    with pytest.raises(KeyError):
        t("config.missing")
    i18n.set_strict(False)
    assert t("config.missing") == _load("en")["config.missing"]


def test_t_falls_back_to_en_when_key_absent_in_lang(monkeypatch: pytest.MonkeyPatch) -> None:
    real = i18n.load_catalogue

    def fake(lang: str) -> dict[str, str]:
        return {} if lang == "it" else real(lang)

    monkeypatch.setattr(i18n, "load_catalogue", fake)
    assert t("config.invalid_value", "it", name="X") == "Invalid value for X."


# --- language resolution ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, []),
        ("", []),
        ("it", ["it"]),
        ("it-IT,it;q=0.9,en;q=0.8", ["it", "it", "en"]),
        ("en;q=0.5, it;q=0.9", ["it", "en"]),
        ("fr, de;q=0.8", []),
        ("it;q=0", []),
        ("it;q=abc, en", ["en"]),
        ("it;q=2, en", ["en"]),
        (";;;,,,", []),
        ("*", []),
        ("IT_it", ["it"]),
        ("\x00\xff garbage;q=", []),
    ],
)
def test_parse_accept_language(header: str | None, expected: list[str]) -> None:
    assert parse_accept_language(header) == expected


@pytest.mark.parametrize(
    ("user", "tenant", "accept", "expected"),
    [
        ("it", "en", "en", "it"),
        (None, "it", "en", "it"),
        (None, None, "it-IT,it;q=0.9", "it"),
        (None, None, None, "en"),
        ("fr", "it", "en", "it"),  # unsupported user pref falls through
        ("", "", "it", "it"),
        (None, None, "garbage;;q=x", "en"),
        ("IT", None, None, "it"),
        ("it-IT", None, None, "it"),
    ],
)
def test_resolve_language(
    user: str | None, tenant: str | None, accept: str | None, expected: str
) -> None:
    assert resolve_language(user, tenant, accept) == expected


def test_resolve_language_bad_default_is_en() -> None:
    assert resolve_language(default="xx") == "en"
