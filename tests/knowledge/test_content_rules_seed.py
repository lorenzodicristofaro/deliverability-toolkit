"""M5-12 schema of seeds/content_rules.yaml. Table-driven, malformed input included. No network,
no database."""

import datetime as dt
import re
from typing import Any

import pytest

from app.checks.content_rules_seed import CONTENT_RULES_FILE, i18n_keys, parse_content_rules
from app.core.i18n import load_catalogue
from app.core.safe_regex import MAX_PATTERN_LENGTH, compile_checked
from app.dns.knowledge import SEEDS_DIR, KnowledgeError, _load_yaml

TODAY = dt.date(2026, 11, 8)
URL = "https://acme.example/rules"


def _rule(**overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "key": "rule_a",
        "kind": "regex",
        "pattern": "a+b",
        "flags": ["ignorecase"],
        "weight": 10,
        "category": "formatting",
        "severity": "low",
        "language": None,
        "enabled": True,
        "status": "verified",
        "verified_on": dt.date(2026, 11, 1),
        "sources": [URL],
    }
    rule.update(overrides)
    return rule


def _without(field: str) -> dict[str, Any]:
    rule = _rule()
    del rule[field]
    return rule


def _unverified(**overrides: Any) -> dict[str, Any]:
    return _rule(status="unverified", enabled=False, sources=[], **overrides)


def _doc(*rules: dict[str, Any]) -> dict[str, Any]:
    return {"rules": list(rules)}


def test_valid_rule_is_parsed() -> None:
    (rule,) = parse_content_rules(_doc(_rule()), TODAY)
    assert (rule.key, rule.kind, rule.pattern) == ("rule_a", "regex", "a+b")
    assert rule.flags == int(re.IGNORECASE)
    assert (rule.weight, rule.category, rule.severity) == (10, "formatting", "low")
    assert (rule.language, rule.enabled, rule.status) == (None, True, "verified")
    assert (rule.verified_on, rule.sources) == (dt.date(2026, 11, 1), (URL,))


VALID: list[tuple[str, dict[str, Any]]] = [
    ("flags omitted", {k: v for k, v in _rule().items() if k != "flags"}),
    ("verified on today", _rule(verified_on=TODAY)),
    ("verified but disabled", _rule(enabled=False)),
    ("unverified disabled no sources", _unverified()),
    ("unverified with a source", _rule(status="unverified", enabled=False)),
    ("keyword", _rule(kind="keyword", pattern="free offer", flags=[])),
    ("language", _rule(language="it")),
    ("language with region", _rule(language="pt-br")),
    ("weight bounds low", _rule(weight=0)),
    ("weight bounds high", _rule(weight=100)),
    ("all flags", _rule(flags=["ignorecase", "multiline", "dotall", "verbose", "ascii"])),
]


@pytest.mark.parametrize(("case", "raw"), VALID, ids=[c for c, _ in VALID])
def test_valid_rules(case: str, raw: dict[str, Any]) -> None:
    assert len(parse_content_rules(_doc(raw), TODAY)) == 1


MALFORMED_DOCS: list[tuple[str, object]] = [
    ("none", None),
    ("list", []),
    ("string", "rules"),
    ("missing rules", {}),
    ("unknown top key", {"rules": [_rule()], "extra": 1}),
    ("rules not a list", {"rules": {"a": 1}}),
    ("rules empty", {"rules": []}),
    ("too many rules", {"rules": [_rule(key=f"r{i}") for i in range(201)]}),
    ("entry not a mapping", {"rules": ["x"]}),
    ("entry is none", {"rules": [None]}),
    ("non-string key in entry", {"rules": [{**_rule(), 1: "x"}]}),
    ("duplicate seed key", _doc(_rule(), _rule())),
]


@pytest.mark.parametrize(("case", "doc"), MALFORMED_DOCS, ids=[c for c, _ in MALFORMED_DOCS])
def test_malformed_documents(case: str, doc: object) -> None:
    with pytest.raises(KnowledgeError):
        parse_content_rules(doc, TODAY)


REQUIRED = [
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
]

MALFORMED_RULES: list[tuple[str, dict[str, Any]]] = [
    *[(f"missing {f}", _without(f)) for f in REQUIRED],
    ("unknown key", {**_rule(), "title": "x"}),
    ("key uppercase", _rule(key="Rule")),
    ("key with dot", _rule(key="a.b")),
    ("key with dash", _rule(key="a-b")),
    ("key leading underscore", _rule(key="_a")),
    ("key trailing newline", _rule(key="a\n")),
    ("key empty", _rule(key="")),
    ("key not a string", _rule(key=1)),
    ("key too long", _rule(key="a" * 129)),
    ("key with nul", _rule(key="a\x00")),
    ("kind unknown", _rule(kind="glob")),
    ("kind unhashable", _rule(kind=["regex"])),
    ("regex invalid", _rule(pattern="(")),
    ("regex empty", _rule(pattern="")),
    ("regex too long", _rule(pattern="a" * (MAX_PATTERN_LENGTH + 1))),
    ("regex with nul", _rule(pattern="a\x00")),
    ("regex surrogate", _rule(pattern="a\ud800")),
    ("pattern not a string", _rule(pattern=1)),
    ("pattern none", _rule(pattern=None)),
    ("keyword empty", _rule(kind="keyword", pattern="", flags=[])),
    ("keyword blank", _rule(kind="keyword", pattern="   ", flags=[])),
    ("keyword untrimmed", _rule(kind="keyword", pattern=" a", flags=[])),
    ("keyword too long", _rule(kind="keyword", pattern="a" * 1025, flags=[])),
    ("keyword with nul", _rule(kind="keyword", pattern="a\x00b", flags=[])),
    ("keyword control char", _rule(kind="keyword", pattern="a\x1bb", flags=[])),
    ("keyword surrogate", _rule(kind="keyword", pattern="a\ud800", flags=[])),
    ("keyword with flags", _rule(kind="keyword", pattern="a")),
    ("flags not a list", _rule(flags="ignorecase")),
    ("flags none", _rule(flags=None)),
    ("flag unknown", _rule(flags=["locale"])),
    ("flag not a string", _rule(flags=[2])),
    ("flag unhashable", _rule(flags=[["ignorecase"]])),
    ("flag duplicate", _rule(flags=["ascii", "ascii"])),
    ("weight negative", _rule(weight=-1)),
    ("weight too high", _rule(weight=101)),
    ("weight bool", _rule(weight=True)),
    ("weight float", _rule(weight=1.5)),
    ("weight string", _rule(weight="1")),
    ("category uppercase", _rule(category="Formatting")),
    ("category with space", _rule(category="a b")),
    ("category too long", _rule(category="a" * 65)),
    ("category with nul", _rule(category="a\x00")),
    ("severity unknown", _rule(severity="urgent")),
    ("severity none", _rule(severity=None)),
    ("language uppercase", _rule(language="EN")),
    ("language empty", _rule(language="")),
    ("language too short", _rule(language="e")),
    ("language with underscore", _rule(language="pt_br")),
    ("language not ascii", _rule(language="è1")),
    ("language too long", _rule(language="en-" + "a" * 14)),
    ("language not a string", _rule(language=1)),
    ("language with nul", _rule(language="en\x00")),
    ("enabled string", _rule(enabled="true")),
    ("enabled int", _rule(enabled=1)),
    ("enabled none", _rule(enabled=None)),
    ("status unknown", _rule(status="maybe")),
    ("status none", _rule(status=None)),
    ("status unhashable", _rule(status=["verified"])),
    ("verified_on future", _rule(verified_on=dt.date(2026, 11, 9))),
    ("verified_on none", _rule(verified_on=None)),
    ("unverified verified_on none", _unverified(verified_on=None)),
    ("unverified verified_on future", _unverified(verified_on=dt.date(2027, 1, 1))),
    ("verified_on string", _rule(verified_on="2026-11-01")),
    ("verified_on datetime", _rule(verified_on=dt.datetime(2026, 11, 1, 12, 0))),
    ("verified without sources", _rule(sources=[])),
    ("unverified enabled", _rule(status="unverified")),
    ("sources not a list", _rule(sources=URL)),
    ("sources none", _rule(sources=None)),
    ("source not a string", _rule(sources=[1])),
    ("source http", _rule(sources=["http://acme.example"])),
    ("source other scheme", _rule(sources=["ftp://acme.example"])),
    ("source no host", _rule(sources=["https://"])),
    ("source bad ipv6", _rule(sources=["https://[bad/x"])),
    ("source with space", _rule(sources=["https://acme.example/a b"])),
    ("source with nul", _rule(sources=["https://acme.example/\x00"])),
    ("source too long", _rule(sources=["https://acme.example/" + "a" * 2048])),
    ("source duplicate", _rule(sources=[URL, URL])),
    ("too many sources", _rule(sources=[f"{URL}/{i}" for i in range(11)])),
]


@pytest.mark.parametrize(("case", "raw"), MALFORMED_RULES, ids=[c for c, _ in MALFORMED_RULES])
def test_malformed_rules(case: str, raw: dict[str, Any]) -> None:
    with pytest.raises(KnowledgeError):
        parse_content_rules(_doc(raw), TODAY)


# --- the shipped seed ----------------------------------------------------------------------------


def _shipped() -> Any:
    return parse_content_rules(_load_yaml(SEEDS_DIR / CONTENT_RULES_FILE))


def test_shipped_seed_is_valid_and_small() -> None:
    assert 0 < len(_shipped()) <= 20


def test_shipped_regexes_pass_compile_checked() -> None:
    for rule in _shipped():
        if rule.kind == "regex":
            compile_checked(rule.pattern, rule.flags)


def test_shipped_unverified_rules_are_disabled_and_verified_rules_cite_sources() -> None:
    for rule in _shipped():
        if rule.status == "unverified":
            assert not rule.enabled, rule.key
        else:
            assert rule.sources, rule.key


@pytest.mark.parametrize("lang", ["en", "it"])
def test_every_shipped_rule_has_its_text(lang: str) -> None:
    catalogue = load_catalogue(lang)
    for rule in _shipped():
        for key in i18n_keys(rule.key):
            assert catalogue.get(key, "").strip(), key


def test_no_orphan_content_rule_text() -> None:
    expected = {key for rule in _shipped() for key in i18n_keys(rule.key)}
    assert {k for k in load_catalogue("en") if k.startswith("CONTENT_RULE.")} == expected


PATTERN_CASES: list[tuple[str, str, bool]] = [
    ("subject_fake_reply_forward_prefix", "Re: your invoice", True),
    ("subject_fake_reply_forward_prefix", "FWD: your invoice", True),
    ("subject_fake_reply_forward_prefix", "  re : your invoice", True),
    ("subject_fake_reply_forward_prefix", "Your invoice Re: May", False),
    ("subject_fake_reply_forward_prefix", "Regarding: your invoice", False),
    ("subject_fake_reply_forward_prefix", "", False),
    ("shouting_punctuation", "Buy now!!!", True),
    ("shouting_punctuation", "Really?!?", True),
    ("shouting_punctuation", "Buy now!!", False),
    ("shouting_punctuation", "", False),
    ("all_caps_run", "BUY NOW LIMITED OFFER", True),
    ("all_caps_run", "BUY NOW LIMITED offer", False),
    ("all_caps_run", "Plain sentence here", False),
    ("all_caps_run", "", False),
]


@pytest.mark.parametrize(("key", "text", "hit"), PATTERN_CASES)
def test_shipped_patterns(key: str, text: str, hit: bool) -> None:
    rule = {r.key: r for r in _shipped()}[key]
    assert (re.search(rule.pattern, text, rule.flags) is not None) is hit
