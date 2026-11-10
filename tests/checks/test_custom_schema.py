"""M5-22 custom check definition schema. Pure: no database, no DNS, no network."""

from __future__ import annotations

import json
from types import MappingProxyType
from typing import Any

import pytest

from app.core.custom_check_schema import (
    MAX_DEFINITION_JSON_LENGTH,
    MAX_RANGE_MAGNITUDE,
    PLACEHOLDER,
    RRTYPES,
    SEVERITIES,
    DefinitionInvalid,
    KindUnavailable,
    NameRenderError,
    parse_definition,
    render_name,
    validate_remediation_text,
    validate_severity,
)
from app.core.safe_regex import MAX_PATTERN_LENGTH
from app.dns.types import ALLOWED_RDTYPES
from app.models.custom_check import KINDS, MAX_REMEDIATION_LENGTH, RESERVED_KINDS

LONG_LABEL = "a" * 63
TEXT = {"en": "Publish it.", "it": "Pubblicalo."}


def _def(kind: str = "dns_exists", **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"name": "_x.{domain}", "rrtype": "TXT"}
    if kind == "dns_matches":
        base["pattern"] = "^v=spf1"
    if kind == "dns_value_range":
        base |= {"min": 0, "max": 10}
    return base | overrides


def _reason(kind: str, definition: object) -> tuple[str, str]:
    with pytest.raises(DefinitionInvalid) as err:
        parse_definition(kind, definition)
    return err.value.field, err.value.reason


GOOD_TEMPLATES = [
    "{domain}",
    "_dmarc.{domain}",
    "s1._domainkey.{domain}",
    "a-b.c1.{domain}",
    "0.{domain}",
    f"{LONG_LABEL}.{{domain}}",
]

BAD_TEMPLATES = [
    ("", "empty"),
    (None, "not_a_string"),
    (5, "not_a_string"),
    (b"{domain}", "not_a_string"),
    ("a" * 254, "too_long"),
    ("example.com", "placeholder_missing"),
    ("@", "placeholder_missing"),
    ("{domain}.{domain}", "placeholder_repeated"),
    ("a.{domain}.{domain}", "placeholder_repeated"),
    ("{domain}{domain}", "placeholder_repeated"),
    ("{domain}.evil.example", "placeholder_position"),
    ("a.{domain}.evil.example", "placeholder_position"),
    ("foo{domain}", "placeholder_position"),
    ("{domain!r}", "bad_placeholder"),
    ("{domain.__class__}", "bad_placeholder"),
    ("{domain:>300}", "bad_placeholder"),
    ("{domain[0]}", "bad_placeholder"),
    ("{0}", "bad_placeholder"),
    ("{}", "bad_placeholder"),
    ("{DOMAIN}", "bad_placeholder"),
    ("{{domain}}", "bad_placeholder"),
    ("a{b}.{domain}", "bad_placeholder"),
    ("}{domain}", "bad_placeholder"),
    ("{domain", "bad_placeholder"),
    ("domain}", "bad_placeholder"),
    (".{domain}", "dots"),
    ("{domain}.", "dots"),
    ("a..{domain}", "dots"),
    ("..{domain}", "dots"),
    ("a.{domain}.", "dots"),
    ("a b.{domain}", "whitespace"),
    (" {domain}", "whitespace"),
    ("{domain} ", "whitespace"),
    ("a b.{domain}", "whitespace"),
    ("a b.{domain}", "whitespace"),
    ("a\x00.{domain}", "nul"),
    ("a\ud800.{domain}", "surrogate"),
    ("a\n.{domain}", "control_char"),
    ("a\t.{domain}", "control_char"),
    ("a\x7f.{domain}", "control_char"),
    ("Foo.{domain}", "uppercase"),
    ("fOO.bar.{domain}", "uppercase"),
    ("selectör.{domain}", "idn"),
    ("例え.{domain}", "idn"),
    ("xn--bcher-kva.{domain}", "idn"),
    ("_xn--bcher-kva.{domain}", "idn"),
    ("*.{domain}", "label"),
    ("-a.{domain}", "label"),
    ("a-.{domain}", "label"),
    ("a_b.{domain}", "label"),
    ("__a.{domain}", "label"),
    ("_.{domain}", "label"),
    ("a/b.{domain}", "label"),
    (f"{'a' * 64}.{{domain}}", "label"),
    (".".join([LONG_LABEL] * 4) + ".{domain}", "too_long"),
]


@pytest.mark.parametrize("template", GOOD_TEMPLATES)
def test_good_templates(template: str) -> None:
    assert parse_definition("dns_exists", _def(name=template)).name_template == template


@pytest.mark.parametrize(("template", "reason"), BAD_TEMPLATES)
def test_bad_templates(template: object, reason: str) -> None:
    assert _reason("dns_exists", _def(name=template)) == ("definition.name", reason)


def test_errors_never_echo_the_value() -> None:
    with pytest.raises(DefinitionInvalid) as err:
        parse_definition("dns_exists", _def(name="secret-token{domain}"))
    assert "secret-token" not in str(err.value)
    with pytest.raises(DefinitionInvalid) as err:
        parse_definition("dns_matches", _def("dns_matches", pattern="(secret-token"))
    assert "secret-token" not in str(err.value)


RENDERED = [
    ("{domain}", "example.com", "example.com"),
    ("_x.{domain}", "example.com", "_x.example.com"),
    ("a.b.{domain}", "sub.example.com", "a.b.sub.example.com"),
    ("_x.{domain}", "EXAMPLE.com.", "_x.example.com"),
    ("_x.{domain}", "bücher.example", "_x.xn--bcher-kva.example"),
    ("{domain}", "bücher.example", "xn--bcher-kva.example"),
]


@pytest.mark.parametrize(("template", "domain", "expected"), RENDERED)
def test_render_name(template: str, domain: str, expected: str) -> None:
    assert render_name(template, domain) == expected


def _domain_of_length(length: int) -> str:
    """A valid domain of exactly `length` characters, ending in .example."""
    tail = ".example"
    room = length - len(tail)
    labels: list[str] = []
    while room > 0:
        size = min(63, room)
        if room - size == 1:  # a lone dot left over cannot be a label
            size -= 1
        labels.append("a" * size)
        room -= size + 1
    name = ".".join(labels) + tail
    assert len(name) == length
    return name


BAD_RENDERS = [
    ("_x.{domain}", _domain_of_length(251), "name_too_long"),
    ("aaaa.{domain}", _domain_of_length(249), "name_too_long"),
    ("_x.{domain}", "", "invalid_domain"),
    ("_x.{domain}", "localhost", "invalid_domain"),
    ("_x.{domain}", "192.0.2.1", "invalid_domain"),
    ("_x.{domain}", "a b.example", "invalid_domain"),
    ("_x.{domain}", "_foo.example.com", "invalid_domain"),
    ("_x.{domain}", None, "invalid_domain"),
]


@pytest.mark.parametrize(("template", "domain", "reason"), BAD_RENDERS)
def test_render_name_errors(template: str, domain: object, reason: str) -> None:
    with pytest.raises(NameRenderError) as err:
        render_name(template, domain)
    assert err.value.reason == reason


def test_render_name_at_the_253_limit() -> None:
    name = render_name("_x.{domain}", _domain_of_length(250))  # 3 + 250 would be 253
    assert len(name) == 253


def test_render_name_revalidates_the_template() -> None:
    with pytest.raises(DefinitionInvalid):
        render_name("{domain}.evil.example", "example.com")


GOOD_DEFINITIONS = [
    ("dns_exists", {"name": "{domain}", "rrtype": "A"}),
    ("dns_matches", {"name": "{domain}", "rrtype": "TXT", "pattern": "(?i)^v=spf1\\s"}),
    ("dns_value_range", {"name": "{domain}", "rrtype": "TXT", "min": -1.5, "max": 2}),
    ("dns_value_range", {"name": "{domain}", "rrtype": "TXT", "min": 3, "max": 3}),
    (
        "dns_value_range",
        {
            "name": "{domain}",
            "rrtype": "TXT",
            "min": -MAX_RANGE_MAGNITUDE,
            "max": MAX_RANGE_MAGNITUDE,
        },
    ),
]


@pytest.mark.parametrize(("kind", "definition"), GOOD_DEFINITIONS)
def test_good_definitions(kind: str, definition: dict[str, Any]) -> None:
    assert parse_definition(kind, definition).kind == kind
    assert parse_definition(kind, MappingProxyType(definition)).kind == kind  # stored records


def test_parsed_fields() -> None:
    matches = parse_definition("dns_matches", _def("dns_matches"))
    assert matches.rule is not None and matches.rule.pattern == "^v=spf1"
    assert matches.minimum is None and matches.rrtype == "TXT"
    ranged = parse_definition("dns_value_range", _def("dns_value_range", min=1, max=2.5))
    assert (ranged.minimum, ranged.maximum, ranged.rule) == (1, 2.5, None)


NAN = float("nan")
INF = float("inf")
BAD_DEFINITIONS = [
    ("dns_exists", None, ("definition", "not_an_object")),
    ("dns_exists", [1], ("definition", "not_an_object")),
    ("dns_exists", "{}", ("definition", "not_an_object")),
    ("dns_exists", {}, ("definition", "empty")),
    ("dns_exists", {1: "a", "name": "{domain}", "rrtype": "A"}, ("definition", "non_string_key")),
    ("dns_exists", _def(extra=1), ("definition", "unknown_key")),
    ("dns_exists", _def(pattern="a"), ("definition", "unknown_key")),
    ("dns_exists", _def(min=0), ("definition", "unknown_key")),
    ("dns_matches", _def("dns_matches", flags=2), ("definition", "unknown_key")),
    ("dns_matches", _def("dns_matches", contains="x"), ("definition", "unknown_key")),
    ("dns_value_range", _def("dns_value_range", pattern="a"), ("definition", "unknown_key")),
    ("dns_exists", {"rrtype": "A"}, ("definition.name", "required")),
    ("dns_exists", {"name": "{domain}"}, ("definition.rrtype", "required")),
    ("dns_matches", {"name": "{domain}", "rrtype": "A"}, ("definition.pattern", "required")),
    (
        "dns_value_range",
        {"name": "{domain}", "rrtype": "A", "max": 1},
        ("definition.min", "required"),
    ),
    (
        "dns_value_range",
        {"name": "{domain}", "rrtype": "A", "min": 1},
        ("definition.max", "required"),
    ),
    ("dns_exists", _def(rrtype="ANY"), ("definition.rrtype", "invalid_choice")),
    ("dns_exists", _def(rrtype="txt"), ("definition.rrtype", "invalid_choice")),
    ("dns_exists", _def(rrtype="PTR"), ("definition.rrtype", "invalid_choice")),
    ("dns_exists", _def(rrtype=5), ("definition.rrtype", "not_a_string")),
    ("dns_matches", _def("dns_matches", pattern=""), ("definition.pattern", "regex_empty")),
    ("dns_matches", _def("dns_matches", pattern=5), ("definition.pattern", "regex_not_a_string")),
    (
        "dns_matches",
        _def("dns_matches", pattern="(a"),
        ("definition.pattern", "regex_invalid_syntax"),
    ),
    (
        "dns_matches",
        _def("dns_matches", pattern="a" * (MAX_PATTERN_LENGTH + 1)),
        ("definition.pattern", "regex_too_long"),
    ),
    ("dns_matches", _def("dns_matches", pattern="a\x00"), ("definition.pattern", "nul")),
    ("dns_matches", _def("dns_matches", pattern="a\ud800"), ("definition.pattern", "surrogate")),
    ("dns_matches", _def("dns_matches", pattern="a\x07"), ("definition.pattern", "control_char")),
    ("dns_value_range", _def("dns_value_range", min=True), ("definition.min", "not_a_number")),
    ("dns_value_range", _def("dns_value_range", max=False), ("definition.max", "not_a_number")),
    ("dns_value_range", _def("dns_value_range", min="1"), ("definition.min", "not_a_number")),
    ("dns_value_range", _def("dns_value_range", max=None), ("definition.max", "not_a_number")),
    ("dns_value_range", _def("dns_value_range", min=[1]), ("definition.min", "not_a_number")),
    ("dns_value_range", _def("dns_value_range", min=NAN), ("definition.min", "not_finite")),
    ("dns_value_range", _def("dns_value_range", max=NAN), ("definition.max", "not_finite")),
    ("dns_value_range", _def("dns_value_range", max=INF), ("definition.max", "not_finite")),
    ("dns_value_range", _def("dns_value_range", min=-INF), ("definition.min", "not_finite")),
    ("dns_value_range", _def("dns_value_range", min=10**400), ("definition.min", "out_of_bounds")),
    (
        "dns_value_range",
        _def("dns_value_range", max=MAX_RANGE_MAGNITUDE + 1),
        ("definition.max", "out_of_bounds"),
    ),
    ("dns_value_range", _def("dns_value_range", min=2, max=1), ("definition.min", "min_above_max")),
    (
        "dns_matches",
        _def("dns_matches", pattern="é" * MAX_PATTERN_LENGTH),
        ("definition", "too_large"),
    ),
]


@pytest.mark.parametrize(("kind", "definition", "expected"), BAD_DEFINITIONS)
def test_bad_definitions(kind: str, definition: object, expected: tuple[str, str]) -> None:
    assert _reason(kind, definition) == expected


@pytest.mark.parametrize("rrtype", sorted(RRTYPES - {"TXT"}))
def test_range_is_txt_only(rrtype: str) -> None:
    definition = _def("dns_value_range", rrtype=rrtype)
    assert _reason("dns_value_range", definition) == ("definition.rrtype", "range_requires_txt")
    assert parse_definition("dns_exists", _def(rrtype=rrtype)).rrtype == rrtype
    assert parse_definition("dns_matches", _def("dns_matches", rrtype=rrtype)).rrtype == rrtype


def test_size_cap_measures_ascii_json() -> None:
    within = _def("dns_matches", pattern="a" * MAX_PATTERN_LENGTH)
    assert len(json.dumps(within)) < MAX_DEFINITION_JSON_LENGTH
    assert parse_definition("dns_matches", within).rule is not None


@pytest.mark.parametrize("definition", [_def(), {}, None, "x", {"url": "https://x.example"}])
def test_http_fetch_is_refused_with_a_typed_error(definition: object) -> None:
    with pytest.raises(KindUnavailable) as err:
        parse_definition("http_fetch", definition)
    assert (err.value.field, err.value.reason) == ("kind", "kind_unavailable")
    assert isinstance(err.value, DefinitionInvalid)


@pytest.mark.parametrize("kind", ["", "glob", "DNS_EXISTS", None, 5, True, ["dns_exists"]])
def test_unknown_kinds(kind: object) -> None:
    with pytest.raises(DefinitionInvalid) as err:
        parse_definition(kind, _def())
    assert (err.value.field, err.value.reason) == ("kind", "invalid_choice")
    assert not isinstance(err.value, KindUnavailable)


def test_enumerations_agree_with_the_model_and_dns_layer() -> None:
    assert RESERVED_KINDS == ("http_fetch",)
    assert "http_fetch" not in KINDS
    assert RRTYPES <= ALLOWED_RDTYPES
    assert PLACEHOLDER == "{domain}"


@pytest.mark.parametrize("value", SEVERITIES)
def test_severity_accepted(value: str) -> None:
    assert validate_severity(value) == value


@pytest.mark.parametrize("value", ["critical", "info", "HIGH", "", None, 1, True, ["low"]])
def test_severity_refused(value: object) -> None:
    with pytest.raises(DefinitionInvalid) as err:
        validate_severity(value)
    assert (err.value.field, err.value.reason) == ("severity", "invalid_choice")


BAD_REMEDIATIONS = [
    (None, "not_an_object"),
    ("text", "not_an_object"),
    ({"en": "only"}, "languages"),
    ({**TEXT, "fr": "x"}, "languages"),
    ({"en": "e", "it": None}, "not_a_string"),
    ({"en": "e", "it": 5}, "not_a_string"),
    ({"en": "", "it": "i"}, "empty"),
    ({"en": "e", "it": "i" * (MAX_REMEDIATION_LENGTH + 1)}, "too_long"),
    ({"en": "e\x00", "it": "i"}, "nul"),
    ({"en": "e", "it": "i\ud800"}, "surrogate"),
    ({"en": "e\x1b[31m", "it": "i"}, "control_char"),
    ({"en": " \n", "it": "i"}, "whitespace"),
]


@pytest.mark.parametrize(("value", "reason"), BAD_REMEDIATIONS)
def test_remediation_refused(value: object, reason: str) -> None:
    with pytest.raises(DefinitionInvalid) as err:
        validate_remediation_text(value)
    assert (err.value.field, err.value.reason) == ("remediation_text", reason)


def test_remediation_accepted_is_plain_text() -> None:
    multi = {"en": "Line.\n\tMore <b>", "it": "x" * MAX_REMEDIATION_LENGTH}
    assert validate_remediation_text(multi) == multi
    assert validate_remediation_text(MappingProxyType(TEXT)) == TEXT
