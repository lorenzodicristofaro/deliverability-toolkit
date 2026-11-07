"""Tests for the URL shortener seed loader and the shipped seed (M5-09). No network."""

from __future__ import annotations

import copy
from datetime import date
from typing import Any

import pytest

from app.dns.knowledge import SEEDS_DIR, _load_yaml
from app.parsers.url_shorteners import (
    SHORTENERS_FILE,
    KnowledgeError,
    list_shorteners,
    parse_shorteners,
)

TODAY = date(2026, 11, 7)
GOOD: dict[str, Any] = {
    "verified_on": date(2026, 11, 7),
    "sources": [],
    "shorteners": [
        {
            "domain": "bit.ly",
            "operator": "bitly",
            "notes": "n",
            "status": "verified",
            "sources": ["https://dev.bitly.com/api-reference/"],
        },
        {"domain": "ow.ly", "operator": None, "notes": "n", "status": "unverified", "sources": []},
    ],
}


def test_shipped_seed_loads_and_is_honest() -> None:
    entries = list_shorteners()
    assert entries
    raw = _load_yaml(SEEDS_DIR / SHORTENERS_FILE)
    assert isinstance(raw, dict) and "verified_on" in raw and "sources" in raw
    for e in entries:
        if e.status == "verified":
            assert e.sources and all(s.startswith("https://") for s in e.sources)
            assert e.operator is not None
        else:
            assert e.operator is None


def test_good_parses_sorted() -> None:
    out = parse_shorteners(GOOD, TODAY)
    assert [s.domain for s in out] == ["bit.ly", "ow.ly"]
    assert out[0].sources == ("https://dev.bitly.com/api-reference/",)


def _mutate(path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    data = copy.deepcopy(GOOD)
    target: Any = data
    for key in path[:-1]:
        target = target[key]
    if value is KeyError:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return data


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("verified_on",), KeyError, "missing keys"),
        (("verified_on",), "2026-11-07", "ISO date"),
        (("verified_on",), date(2099, 1, 1), "future"),
        (("sources",), ["http://insecure.example"], "https"),
        (("shorteners",), [], "non-empty"),
        (("shorteners",), "bit.ly", "non-empty"),
        (("shorteners", 0, "domain"), "BIT.LY", "normalised"),
        (("shorteners", 0, "domain"), "bit.ly ", "surrounding whitespace"),
        (("shorteners", 0, "domain"), "localhost", "invalid domain"),
        (("shorteners", 0, "domain"), "192.0.2.1", "invalid domain"),
        (("shorteners", 0, "domain"), "ow.ly", "duplicate"),
        (("shorteners", 0, "domain"), 3, "non-empty string"),
        (("shorteners", 0, "status"), "maybe", "must be one of"),
        (("shorteners", 0, "sources"), [], "verified entries need"),
        (("shorteners", 0, "sources"), ["ftp://x.example"], "https"),
        (("shorteners", 1, "operator"), "someone", "must not claim"),
        (("shorteners", 1, "extra"), 1, "unknown keys"),
        (("shorteners", 1), "ow.ly", "mapping"),
    ],
)
def test_malformed_rejected(path: tuple[Any, ...], value: Any, message: str) -> None:
    with pytest.raises(KnowledgeError, match=message):
        parse_shorteners(_mutate(path, value), TODAY)


def test_not_a_mapping() -> None:
    with pytest.raises(KnowledgeError):
        parse_shorteners(["bit.ly"], TODAY)


def test_too_many_entries() -> None:
    data = copy.deepcopy(GOOD)
    data["shorteners"] = [
        {
            "domain": f"s{i}.example",
            "operator": None,
            "notes": "n",
            "status": "unverified",
            "sources": [],
        }
        for i in range(501)
    ]
    with pytest.raises(KnowledgeError, match="at most"):
        parse_shorteners(data, TODAY)
