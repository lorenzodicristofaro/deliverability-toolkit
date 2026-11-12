"""Tests for app.esp.profile: schema, glob, YAML hardening, directory loader. No network."""

from __future__ import annotations

import copy
import dataclasses
import shutil
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.dns.knowledge import KnowledgeError
from app.esp import profile as esp
from app.esp.profile import (
    MAX_FILE_BYTES,
    EspProfile,
    EspProfileError,
    TargetPattern,
    check_unique_ids,
    get_esp_profile,
    load_esp_profiles,
    parse_esp_profile,
    read_esp_profiles,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "esp"
TODAY = date(2026, 11, 10)

GOOD: dict[str, Any] = {
    "id": "example-esp",
    "name": "Example ESP",
    "homepage": "https://esp.example.com",
    "spf": {"includes": ["spf.esp.example.com"]},
    "dkim": {
        "selectors": [
            {"name": "s1", "type": "cname", "target_pattern": "s1.dkim.*.esp.example.com"},
            {"name": "k1", "type": "txt"},
        ]
    },
    "return_path": {"type": "cname", "notes_key": "esp.example_esp.return_path"},
    "tracking_domain": {"type": "cname", "optional": True},
    "pitfalls": [
        {
            "code": "ESP_EXAMPLE_ESP_LINK_BRANDING",
            "notes_key": "esp.example_esp.link",
            "severity": "low",
        }
    ],
    "verified_on": date(2026, 1, 15),
    "sources": ["https://docs.esp.example.com/dns"],
    "status": "verified",
}


def _doc(**over: Any) -> dict[str, Any]:
    d = copy.deepcopy(GOOD)
    for key, value in over.items():
        if value is _DROP:
            d.pop(key, None)
        else:
            d[key] = value
    return d


_DROP = object()


def _parse(d: object) -> EspProfile:
    return parse_esp_profile(d, "example-esp", today=TODAY)


def _sel(**over: Any) -> dict[str, Any]:
    s: dict[str, Any] = {"name": "s1", "type": "cname"}
    s.update(over)
    return {"selectors": [s]}


def _pit(**over: Any) -> list[dict[str, Any]]:
    p: dict[str, Any] = {"code": "ESP_EXAMPLE_ESP_X", "notes_key": "esp.x.y", "severity": "low"}
    p.update(over)
    return [p]


# --- valid shapes -------------------------------------------------------------------------------


def test_good_profile_parses() -> None:
    p = _parse(GOOD)
    assert p.id == "example-esp"
    assert p.spf_includes == ("spf.esp.example.com",)
    assert [s.name for s in p.dkim_selectors] == ["s1", "k1"]
    assert p.dkim_selectors[0].target_pattern == TargetPattern(
        ("s1", "dkim", "*", "esp", "example", "com")
    )
    assert p.dkim_selectors[1].target_pattern is None
    assert p.return_path is not None and p.return_path.optional is False
    assert p.tracking_domain is not None and p.tracking_domain.optional is True
    assert p.pitfalls[0].severity == "low"
    assert p.unverified_fields == frozenset()
    assert p.is_verified("return_path") and p.is_verified("dkim.selectors.s1")


def test_minimal_profile_parses() -> None:
    d = _doc(
        return_path=_DROP,
        tracking_domain=_DROP,
        pitfalls=_DROP,
        spf={"includes": []},
        dkim={"selectors": []},
    )
    p = _parse(d)
    assert p.return_path is None and p.tracking_domain is None and p.pitfalls == ()


@pytest.mark.parametrize(
    ("spf", "expected"),
    [
        ({"includes": ["a.example.com"]}, False),
        ({"includes": ["a.example.com"], "only_if_record": False}, False),
        ({"includes": ["a.example.com"], "only_if_record": True}, True),
        ({"includes": [], "only_if_record": False}, False),
    ],
)
def test_spf_only_if_record(spf: dict[str, Any], expected: bool) -> None:
    assert _parse(_doc(spf=spf)).spf_only_if_record is expected


def test_result_is_immutable() -> None:
    p = _parse(GOOD)
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.id = "x"  # type: ignore[misc]
    assert isinstance(p.spf_includes, tuple) and isinstance(p.sources, tuple)
    assert isinstance(p.unverified_fields, frozenset)


@pytest.mark.parametrize(
    ("fields", "query", "expected"),
    [
        (["return_path"], "return_path", False),
        (["return_path"], "tracking_domain", True),
        (["dkim.selectors"], "dkim.selectors.s1", False),
        (["dkim.selectors.s1"], "dkim.selectors.s1", False),
        (["dkim.selectors.s1"], "dkim.selectors.k1", True),
        (["dkim.selectors.s1"], "dkim.selectors", True),
        (
            ["pitfalls.ESP_EXAMPLE_ESP_LINK_BRANDING"],
            "pitfalls.ESP_EXAMPLE_ESP_LINK_BRANDING",
            False,
        ),
        (["spf.includes"], "spf.includes", False),
        (["spf.includes"], "spf", True),
    ],
)
def test_unverified_fields_exclusion(fields: list[str], query: str, expected: bool) -> None:
    p = _parse(_doc(status="unverified", unverified_fields=fields))
    assert p.status == "unverified"
    assert p.is_verified(query) is expected


# --- schema violations (table) ------------------------------------------------------------------

BAD_CASES: list[tuple[str, Any, str]] = [
    # top level
    ("not a mapping", None, "must be a mapping"),
    ("list root", [GOOD], "must be a mapping"),
    ("unknown key", _doc(extra=1), "unknown keys"),
    ("missing sources", _doc(sources=_DROP), "missing keys"),
    ("missing verified_on", _doc(verified_on=_DROP), "missing keys"),
    ("missing status", _doc(status=_DROP), "missing keys"),
    ("non-string key", {**GOOD, 1: "x"}, "keys must be strings"),
    # id
    ("id uppercase", _doc(id="Example-esp"), "must match"),
    ("id leading hyphen", _doc(id="-example"), "must match"),
    ("id too long", _doc(id="a" * 41), "must match"),
    ("id int", _doc(id=5), "non-empty string"),
    ("id not file name", _doc(id="other-esp"), "must equal the file name"),
    ("id underscore", _doc(id="example_esp"), "must match"),
    # name / homepage
    ("name empty", _doc(name=""), "non-empty string"),
    ("name control char", _doc(name="Ex\x00ample"), "control characters"),
    ("name too long", _doc(name="x" * 101), "at most 100"),
    ("homepage http", _doc(homepage="http://esp.example.com"), "https URL"),
    ("homepage no host", _doc(homepage="https://"), "non-empty string"),
    ("homepage userinfo", _doc(homepage="https://u:p@esp.example.com"), "credentials"),
    ("homepage port", _doc(homepage="https://esp.example.com:8443"), "credentials or a port"),
    ("homepage bad port", _doc(homepage="https://esp.example.com:x"), "not a valid URL"),
    ("homepage upper host", _doc(homepage="https://ESP.example.com"), "lowercase"),
    ("homepage space", _doc(homepage="https://esp.example.com/a b"), "without spaces"),
    ("homepage ip", _doc(homepage="https://192.0.2.1/"), "numeric"),
    ("homepage javascript", _doc(homepage="javascript:alert(1)"), "https URL"),
    # spf
    ("spf not mapping", _doc(spf=["a.example.com"]), "must be a mapping"),
    ("spf unknown key", _doc(spf={"includes": [], "all": "~all"}), "unknown keys"),
    ("includes not list", _doc(spf={"includes": "a.example.com"}), "must be a list"),
    ("include scheme", _doc(spf={"includes": ["https://a.example.com"]}), "label"),
    ("include wildcard", _doc(spf={"includes": ["*.example.com"]}), "label"),
    ("include trailing dot", _doc(spf={"includes": ["a.example.com."]}), "label"),
    ("include single label", _doc(spf={"includes": ["localhost"]}), "two labels"),
    ("include uppercase", _doc(spf={"includes": ["A.example.com"]}), "label"),
    ("include NUL", _doc(spf={"includes": ["a\x00.example.com"]}), "control"),
    ("include space", _doc(spf={"includes": ["a .example.com"]}), "label"),
    ("include long label", _doc(spf={"includes": ["a" * 64 + ".example.com"]}), "label"),
    ("include too long", _doc(spf={"includes": [("a" * 60 + ".") * 5 + "com"]}), "at most 253"),
    ("include ip", _doc(spf={"includes": ["192.0.2.1"]}), "numeric"),
    ("include empty label", _doc(spf={"includes": ["a..example.com"]}), "label"),
    ("include unicode", _doc(spf={"includes": ["bücher.example.com"]}), "label"),
    ("include dup", _doc(spf={"includes": ["a.example.com", "a.example.com"]}), "duplicate"),
    ("include not str", _doc(spf={"includes": [1]}), "non-empty string"),
    (
        "only_if_record str",
        _doc(spf={"includes": ["a.example.com"], "only_if_record": "yes"}),
        "true or false",
    ),
    (
        "only_if_record int",
        _doc(spf={"includes": ["a.example.com"], "only_if_record": 1}),
        "true or false",
    ),
    (
        "only_if_record null",
        _doc(spf={"includes": ["a.example.com"], "only_if_record": None}),
        "true or false",
    ),
    (
        "only_if_record no includes",
        _doc(spf={"includes": [], "only_if_record": True}),
        "non-empty spf.includes",
    ),
    (
        "include too many",
        _doc(spf={"includes": [f"a{i}.example.com" for i in range(21)]}),
        "at most",
    ),
    # dkim
    ("dkim unknown key", _doc(dkim={"selectors": [], "x": 1}), "unknown keys"),
    ("selectors not list", _doc(dkim={"selectors": {}}), "must be a list"),
    ("selector not mapping", _doc(dkim={"selectors": ["s1"]}), "must be a mapping"),
    ("selector bad type", _doc(dkim=_sel(type="mx")), "must be one of"),
    ("selector name dot", _doc(dkim=_sel(name="s1._domainkey")), "DNS label"),
    ("selector name upper", _doc(dkim=_sel(name="S1")), "DNS label"),
    ("selector name empty", _doc(dkim=_sel(name="")), "non-empty"),
    ("selector name long", _doc(dkim=_sel(name="a" * 64)), "at most 63"),
    ("selector unknown key", _doc(dkim=_sel(record="x")), "unknown keys"),
    (
        "selector dup",
        _doc(dkim={"selectors": [{"name": "s1", "type": "txt"}, {"name": "s1", "type": "cname"}]}),
        "duplicate selector",
    ),
    (
        "txt with pattern",
        _doc(dkim=_sel(type="txt", target_pattern="a.example.com")),
        "only a cname",
    ),
    # target_pattern
    ("pattern partial glob", _doc(dkim=_sel(target_pattern="s1*.example.com")), "whole label"),
    ("pattern double star", _doc(dkim=_sel(target_pattern="**.a.example.com")), "whole label"),
    ("pattern regex", _doc(dkim=_sel(target_pattern="s1\\..+\\.example\\.com")), "label"),
    ("pattern star in tld", _doc(dkim=_sel(target_pattern="s1.example.*")), "last two labels"),
    ("pattern star sld", _doc(dkim=_sel(target_pattern="s1.*.com")), "last two labels"),
    ("pattern single", _doc(dkim=_sel(target_pattern="*")), "at least two labels"),
    ("pattern trailing dot", _doc(dkim=_sel(target_pattern="s1.example.com.")), "label"),
    ("pattern question", _doc(dkim=_sel(target_pattern="s?.example.com")), "label"),
    ("pattern upper", _doc(dkim=_sel(target_pattern="S1.example.com")), "label"),
    ("pattern scheme", _doc(dkim=_sel(target_pattern="https://s1.example.com")), "label"),
    ("pattern not str", _doc(dkim=_sel(target_pattern=["a"])), "non-empty string"),
    # return_path / tracking_domain
    ("rp bad type", _doc(return_path={"type": "a"}), "must be one of"),
    ("rp missing type", _doc(return_path={"optional": True}), "missing keys"),
    ("rp optional str", _doc(return_path={"type": "mx", "optional": "yes"}), "true or false"),
    ("rp optional int", _doc(return_path={"type": "mx", "optional": 1}), "true or false"),
    ("rp notes key bad", _doc(return_path={"type": "mx", "notes_key": "no dots"}), "i18n key"),
    ("rp notes key single", _doc(return_path={"type": "mx", "notes_key": "esp"}), "i18n key"),
    ("td unknown key", _doc(tracking_domain={"type": "cname", "host": "x"}), "unknown keys"),
    ("td not mapping", _doc(tracking_domain="cname"), "must be a mapping"),
    # pitfalls
    ("pitfall when", _doc(pitfalls=_pit(when="True")), "conditions are not supported"),
    ("pitfall bad prefix", _doc(pitfalls=_pit(code="ESP_OTHER_X")), "ESP_EXAMPLE_ESP_"),
    ("pitfall lower", _doc(pitfalls=_pit(code="ESP_EXAMPLE_ESP_x")), "upper snake"),
    ("pitfall no name", _doc(pitfalls=_pit(code="ESP_EXAMPLE_ESP_")), "upper snake"),
    ("pitfall double _", _doc(pitfalls=_pit(code="ESP_EXAMPLE_ESP_A__B")), "upper snake"),
    ("pitfall severity", _doc(pitfalls=_pit(severity="urgent")), "must be one of"),
    ("pitfall missing key", _doc(pitfalls=[{"code": "ESP_EXAMPLE_ESP_X"}]), "missing keys"),
    ("pitfall notes", _doc(pitfalls=_pit(notes_key="x")), "i18n key"),
    ("pitfalls not list", _doc(pitfalls={"code": "x"}), "must be a list"),
    ("pitfall dup", _doc(pitfalls=_pit() + _pit()), "duplicate code"),
    # provenance
    ("verified_on str", _doc(verified_on="2026-01-15"), "ISO date"),
    (
        "verified_on datetime",
        _doc(verified_on=__import__("datetime").datetime(2026, 1, 1)),
        "ISO date",
    ),
    ("verified_on future", _doc(verified_on=TODAY + timedelta(days=1)), "future"),
    ("sources empty", _doc(sources=[]), "must not be empty"),
    ("sources not list", _doc(sources="https://docs.example.com"), "must be a list"),
    ("source http", _doc(sources=["http://docs.example.com"]), "https URL"),
    ("source dup", _doc(sources=["https://a.example.com", "https://a.example.com"]), "duplicate"),
    ("sources too many", _doc(sources=[f"https://d{i}.example.com" for i in range(11)]), "at most"),
    ("status bad", _doc(status="draft"), "must be one of"),
    ("unverified without fields", _doc(status="unverified"), "needs the list"),
    ("verified with fields", _doc(unverified_fields=["return_path"]), "only allowed with status"),
    (
        "unverified empty fields",
        _doc(status="unverified", unverified_fields=[]),
        "must not be empty",
    ),
    (
        "unverified unknown field",
        _doc(status="unverified", unverified_fields=["homepage"]),
        "names no field",
    ),
    (
        "unverified absent selector",
        _doc(status="unverified", unverified_fields=["dkim.selectors.zz"]),
        "names no field",
    ),
    (
        "unverified absent part",
        _doc(status="unverified", tracking_domain=_DROP, unverified_fields=["tracking_domain"]),
        "names no field",
    ),
    (
        "unverified dup",
        _doc(status="unverified", unverified_fields=["return_path", "return_path"]),
        "duplicate entry",
    ),
]


@pytest.mark.parametrize(
    ("data", "match"), [c[1:] for c in BAD_CASES], ids=[c[0] for c in BAD_CASES]
)
def test_schema_violations_rejected(data: Any, match: str) -> None:
    with pytest.raises(EspProfileError, match=match):
        _parse(data)


def test_error_is_a_knowledge_error_and_names_the_file() -> None:
    with pytest.raises(KnowledgeError, match=r"^example-esp\.yaml: status"):
        _parse(_doc(status="draft"))


# --- restricted glob ----------------------------------------------------------------------------

PATTERN = TargetPattern(("s1", "dkim", "*", "esp", "example", "com"))


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("s1.dkim.u123.esp.example.com", True),
        ("S1.DKIM.U123.ESP.Example.COM", True),  # case-insensitive
        ("s1.dkim.u123.esp.example.com.", True),  # one trailing dot
        ("s1.dkim.u-1.esp.example.com", True),
        ("s1.dkim.esp.example.com", False),  # missing label
        ("s1.dkim..esp.example.com", False),  # empty label
        ("s1.dkim.a.b.esp.example.com", False),  # `*` is exactly one label
        ("x.s1.dkim.u1.esp.example.com", False),  # extra leading label
        ("s1.dkim.u1.esp.example.com.evil.example", False),  # extra trailing labels
        ("s2.dkim.u1.esp.example.com", False),  # literal mismatch
        ("s1.dkim.u1.esp.example.com..", False),  # two trailing dots
        ("s1.dkim.*.esp.example.com", False),  # a literal `*` is not a label
        ("s1.dkim.-a.esp.example.com", False),
        ("s1.dkim.a b.esp.example.com", False),
        ("s1.dkim.u\x001.esp.example.com", False),
        ("s1.dkim.K.esp.example.com", False),  # KELVIN SIGN lowercases to "k"
        ("s1.dkim." + "a" * 64 + ".esp.example.com", False),
        ("s1.dkim." + "a" * 63 + ".esp.example.com", True),
        ("", False),
        (".", False),
        (None, False),
        (b"s1.dkim.u1.esp.example.com", False),
        ("s1.dkim.u1.esp.example.com" + "a" * 300, False),
    ],
)
def test_target_pattern_matching(name: object, expected: bool) -> None:
    assert PATTERN.matches(name) is expected


def test_literal_pattern_and_str() -> None:
    p = _parse(_doc(dkim=_sel(target_pattern="s1.example.com"))).dkim_selectors[0].target_pattern
    assert p is not None and str(p) == "s1.example.com"
    assert p.matches("S1.example.com.") and not p.matches("s1.example.net")


# --- YAML hardening (raw text through the directory loader) -------------------------------------

GOOD_YAML = (FIXTURES / "valid" / "example-esp.yaml").read_text(encoding="utf-8")

RAW_CASES: list[tuple[str, bytes, str]] = [
    ("empty file", b"", "must be a mapping"),
    ("only comment", b"# nothing\n", "must be a mapping"),
    ("bad yaml", b"id: [unclosed\n", "cannot parse"),
    ("tab indent", b"id: x\n\tname: y\n", "cannot parse"),
    ("scalar root", b"just a string\n", "must be a mapping"),
    ("list root", b"- id: example-esp\n", "must be a mapping"),
    ("duplicate key", b"id: a\nid: b\n", "duplicate key"),
    ("nested duplicate", b"spf: {includes: [], includes: []}\n", "duplicate key"),
    ("alias", b"spf: &x {includes: []}\ndkim: *x\n", "anchors and aliases"),
    ("anchor only", b"spf: &x {includes: []}\n", "anchors and aliases"),
    ("merge key", b"spf:\n  <<: {includes: []}\n", "merge keys"),
    ("python tag", b"id: !!python/object/apply:os.getcwd []\n", "cannot parse"),
    ("not utf-8", b"name: \xff\xfe\n", "cannot parse"),
    ("huge file", b"# " + b"x" * MAX_FILE_BYTES + b"\n", "larger than"),
    ("multi document", GOOD_YAML.encode() + b"---\nid: x\n", "cannot parse"),
    ("deep nesting", b"[" * 20000 + b"]" * 20000, "nesting too deep"),
    ("deep nested maps", b"{a: " * 10000 + b"1" + b"}" * 10000, "nesting too deep"),
]


@pytest.mark.parametrize(
    ("raw", "match"), [c[1:] for c in RAW_CASES], ids=[c[0] for c in RAW_CASES]
)
def test_malformed_files_rejected(tmp_path: Path, raw: bytes, match: str) -> None:
    (tmp_path / "example-esp.yaml").write_bytes(raw)
    with pytest.raises(EspProfileError, match=match):
        read_esp_profiles(tmp_path, today=TODAY)


def test_file_at_size_cap_is_read(tmp_path: Path) -> None:
    body = GOOD_YAML.encode()
    padded = body + b"#" * (MAX_FILE_BYTES - len(body))
    assert len(padded) == MAX_FILE_BYTES
    (tmp_path / "example-esp.yaml").write_bytes(padded)
    assert read_esp_profiles(tmp_path, today=TODAY)[0].id == "example-esp"


@pytest.mark.parametrize(
    ("fixture", "match"),
    [
        ("when-condition.yaml", "conditions are not supported"),
        ("duplicate-key.yaml", "duplicate key"),
        ("python-tag.yaml", "cannot parse"),
    ],
)
def test_malformed_fixtures_rejected(tmp_path: Path, fixture: str, match: str) -> None:
    shutil.copy(FIXTURES / "malformed" / fixture, tmp_path / "example-esp.yaml")
    with pytest.raises(EspProfileError, match=match):
        read_esp_profiles(tmp_path, today=TODAY)


# --- directory loader ---------------------------------------------------------------------------


def _valid_dir(tmp_path: Path) -> Path:
    d = tmp_path / "esp"
    shutil.copytree(FIXTURES / "valid", d)
    return d


def test_valid_fixture_directory_loads_in_order(tmp_path: Path) -> None:
    got = read_esp_profiles(_valid_dir(tmp_path), today=TODAY)
    assert [p.id for p in got] == ["example-esp", "other-esp"]
    other = got[1]
    assert other.status == "unverified"
    assert not other.is_verified("return_path") and not other.is_verified("dkim.selectors.mx1")
    assert got[0].spf_includes == ("spf.esp.example.com", "_spf.esp.example.net")


def test_one_bad_file_fails_the_whole_directory(tmp_path: Path) -> None:
    d = _valid_dir(tmp_path)
    (d / "zz-bad.yaml").write_text("id: zz-bad\n")
    with pytest.raises(EspProfileError, match="zz-bad.yaml"):
        read_esp_profiles(d, today=TODAY)


@pytest.mark.parametrize(
    ("name", "kind"),
    [("README.md", "file"), ("x.yml", "file"), ("sub", "dir"), ("link.yaml", "symlink")],
)
def test_unexpected_directory_entries_rejected(tmp_path: Path, name: str, kind: str) -> None:
    d = _valid_dir(tmp_path)
    target = d / name
    if kind == "file":
        target.write_text("x")
    elif kind == "dir":
        target.mkdir()
    else:
        target.symlink_to(d / "example-esp.yaml")
    with pytest.raises(EspProfileError, match="unexpected entry"):
        read_esp_profiles(d, today=TODAY)


def test_hidden_files_ignored_and_empty_dir_ok(tmp_path: Path) -> None:
    (tmp_path / ".gitkeep").write_text("")
    assert read_esp_profiles(tmp_path) == ()


def test_missing_directory_rejected(tmp_path: Path) -> None:
    with pytest.raises(EspProfileError, match="not found"):
        read_esp_profiles(tmp_path / "nope")


def test_too_many_files_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(esp, "MAX_PROFILES", 1)
    with pytest.raises(EspProfileError, match="at most 1 profiles"):
        read_esp_profiles(_valid_dir(tmp_path), today=TODAY)


def test_duplicate_ids_rejected() -> None:
    p = _parse(GOOD)
    with pytest.raises(EspProfileError, match="duplicate profile id"):
        check_unique_ids((p, p))


def test_load_is_cached_per_path(tmp_path: Path) -> None:
    d = _valid_dir(tmp_path)
    first = load_esp_profiles(d)
    (d / "other-esp.yaml").unlink()
    assert load_esp_profiles(d) is first
    assert get_esp_profile("other-esp", d) is not None
    assert get_esp_profile("missing", d) is None
