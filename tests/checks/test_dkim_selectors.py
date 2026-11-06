from __future__ import annotations

import copy
from datetime import date, timedelta
from typing import Any
from urllib.parse import urlparse

import pytest

from app.checks.dkim_selectors import MAX_SELECTORS, list_selectors, parse_selectors
from app.dns.knowledge import KnowledgeError


def _entry(**kw: Any) -> dict[str, Any]:
    e: dict[str, Any] = {
        "name": "default",
        "provider": None,
        "record_type": "txt",
        "notes": "n",
        "status": "unverified",
        "sources": [],
    }
    e.update(kw)
    return e


def _doc(*entries: dict[str, Any], **kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "verified_on": date(2026, 1, 1),
        "sources": [],
        "selectors": list(entries) or [_entry()],
    }
    d.update(kw)
    return d


def test_valid_sorted() -> None:
    out = parse_selectors(_doc(_entry(name="s2"), _entry(name="k1")))
    assert [s.name for s in out] == ["k1", "s2"]


def test_verified_with_source_ok() -> None:
    e = _entry(status="verified", provider="X", sources=["https://example.com/d"])
    assert parse_selectors(_doc(e))[0].status == "verified"


_BAD_ENTRIES = [
    ("verified no source", _entry(status="verified", provider="X")),
    ("unverified provider claim", _entry(provider="Google")),
    ("http source", _entry(sources=["http://x.example"])),
    ("bad status", _entry(status="maybe")),
    ("bad record_type", _entry(record_type="mx")),
    ("dotted name", _entry(name="a.b")),
    ("uppercase", _entry(name="Default")),
    ("empty name", _entry(name="")),
    ("space in name", _entry(name="a b")),
    ("long label", _entry(name="a" * 64)),
    ("trailing dot", _entry(name="a.")),
    ("root", _entry(name=".")),
    ("non-str name", _entry(name=5)),
    ("padded notes", _entry(notes=" x")),
    ("unknown key", _entry(extra=1)),
    ("sources not list", _entry(sources="https://x")),
]


@pytest.mark.parametrize(("label", "entry"), _BAD_ENTRIES, ids=[b[0] for b in _BAD_ENTRIES])
def test_bad_entry(label: str, entry: dict[str, Any]) -> None:
    with pytest.raises(KnowledgeError):
        parse_selectors(_doc(entry))


def test_missing_key() -> None:
    e = _entry()
    del e["notes"]
    with pytest.raises(KnowledgeError, match="missing"):
        parse_selectors(_doc(e))


_BAD_DOCS = [
    ("not mapping", []),
    ("none", None),
    ("unknown top key", _doc(x=1)),
    ("bad date", _doc(verified_on="2026-01-01x")),
    ("future date", _doc(verified_on=date.today() + timedelta(days=2))),
    ("bad top sources", _doc(sources=["http://x"])),
    ("empty list", _doc(selectors=[])),
    ("selectors not list", _doc(selectors={})),
    ("entry not mapping", _doc(selectors=["default"])),
    ("too many", _doc(selectors=[_entry(name=f"s{i}") for i in range(MAX_SELECTORS + 1)])),
]


@pytest.mark.parametrize(("label", "doc"), _BAD_DOCS, ids=[b[0] for b in _BAD_DOCS])
def test_bad_doc(label: str, doc: object) -> None:
    with pytest.raises(KnowledgeError):
        parse_selectors(doc)


def test_cap_boundary_ok() -> None:
    n = MAX_SELECTORS
    assert len(parse_selectors(_doc(*[_entry(name=f"s{i}") for i in range(n)]))) == n


def test_duplicate_name() -> None:
    with pytest.raises(KnowledgeError, match="duplicate"):
        parse_selectors(_doc(_entry(), copy.deepcopy(_entry())))


def test_today_injectable() -> None:
    parse_selectors(_doc(), today=date(2026, 1, 1))
    with pytest.raises(KnowledgeError, match="future"):
        parse_selectors(_doc(), today=date(2025, 12, 31))


def test_shipped_file_loads_and_guards() -> None:
    sels = list_selectors()
    assert sels and sels == tuple(sorted(sels, key=lambda s: s.name))
    assert list_selectors() is list_selectors()
    assert len(sels) <= MAX_SELECTORS
    for s in sels:
        assert s.status != "verified" or s.sources
        assert s.status != "unverified" or s.provider is None


_VENDOR_HOSTS = {
    "learn.microsoft.com": "microsoft365",
    "knowledge.workspace.google.com": "google_workspace",
    "www.twilio.com": "sendgrid",
    "mailchimp.com": "mailchimp_transactional",
    "help.klaviyo.com": "klaviyo",
    "help.activecampaign.com": "activecampaign",
}
# MailUp's official help centre is hosted on Atlassian Cloud. An atlassian.net subdomain is
# tenant-specific, so it is allowed only as this exact host for this exact provider.
_PROVIDER_HOST_EXCEPTIONS = {
    "helpmailup.atlassian.net": "mailup",
}


def _source_allowed(url: str, provider: str | None) -> bool:
    host = urlparse(url).hostname or ""
    if not url.startswith("https://"):
        return False
    allowed = {**_VENDOR_HOSTS, **_PROVIDER_HOST_EXCEPTIONS}
    return allowed.get(host) == provider


@pytest.mark.parametrize(
    ("url", "provider", "ok"),
    [
        ("https://helpmailup.atlassian.net/wiki/x", "mailup", True),
        ("https://otherco.atlassian.net/wiki/x", "mailup", False),
        ("https://otherco.atlassian.net/wiki/x", "klaviyo", False),
        ("https://helpmailup.atlassian.net/wiki/x", "klaviyo", False),
        ("https://atlassian.net/wiki/x", "mailup", False),
        ("http://helpmailup.atlassian.net/wiki/x", "mailup", False),
        ("https://evil.helpmailup.atlassian.net/x", "mailup", False),
    ],
)
def test_source_host_rules(url: str, provider: str, ok: bool) -> None:
    assert _source_allowed(url, provider) is ok


def test_shipped_verified_entries_have_vendor_source_and_provider() -> None:
    verified = [s for s in list_selectors() if s.status == "verified"]
    assert verified
    for s in verified:
        assert s.provider, s.name
        for url in s.sources:
            assert _source_allowed(url, s.provider), (s.name, url)
