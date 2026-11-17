"""M7-08 DNS snapshot content, normalisation, storage form and diff. Pure; no network, no DB."""

import json
from typing import Any

import pytest

from app.models.dns_snapshot import MAX_ENTRIES, MAX_ENTRIES_BYTES
from app.services.dns_diff import (
    MAX_NAME_LENGTH,
    MAX_RAW_CHARS,
    MAX_VALUE_CHARS,
    MAX_VALUES_PER_ENTRY,
    Entry,
    Snapshot,
    SnapshotFormatError,
    build_entry,
    build_snapshot,
    diff_snapshots,
    from_stored,
    is_dmarc,
    is_spf,
    normalise_mx,
    normalise_ns,
    normalise_txt,
    to_stored,
)

SPF1 = "v=spf1 include:_spf.example.net -all"
SPF2 = "v=spf1 include:_spf.example.net ~all"
DMARC1 = "v=DMARC1; p=none"


def entry(name: str, rdtype: str, state: str = "ok", *values: str) -> Entry:
    return build_entry(name, rdtype, state, values)


def snap(*entries: Entry) -> Snapshot:
    return build_snapshot(entries)


def spf(*values: str, state: str = "ok") -> Entry:
    return entry("@", "TXT", state, *values)


# --- normalisation -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (SPF1, SPF1),
        ("  v=spf1   include:_spf.example.net\t-all \n", SPF1),
        ('"v=spf1 include:_spf.example.net" " -all"', "v=spf1 include:_spf.example.net -all"),
        ('"v=spf1 inc" "lude:_spf.example.net -all"', SPF1),  # joined, no separator added
        ('"v=spf1 include:_spf.example.net -all"', SPF1),
        ("V=SPF1 INCLUDE:_SPF.EXAMPLE.NET -ALL", SPF1.upper().replace("V=SPF1", "v=spf1").lower()),
        ("v=DKIM1; k=rsa; p=AbCd", "v=DKIM1; k=rsa; p=AbCd"),  # not SPF: case kept
        ('"unterminated', '"unterminated'),
        ('"a" b', '"a" b'),  # not only quoted strings: left as it is
        ('"a\\"b"', 'a"b'),
        ('""', ""),
        ("", ""),
        ("   ", ""),
        ("a\x00b\x07c", "a�b�c"),  # controls
        ("a\ud800b", "a�b"),  # lone surrogate
        ("café 中文", "café 中文"),  # non-ASCII is kept
        ("a  b", "a b"),  # unicode spaces collapse
    ],
)
def test_normalise_txt(raw: str, expected: str) -> None:
    assert normalise_txt(raw) == expected


def test_txt_string_splitting_is_the_same_record() -> None:
    whole = normalise_txt(SPF1)
    assert normalise_txt('"v=spf1 include:_spf.example.net " "-all"') == whole
    assert normalise_txt('"v=spf1 include:_spf" ".example.net -all"') == whole


def test_normalise_txt_is_bounded_in_work() -> None:
    assert len(normalise_txt("a" * (MAX_RAW_CHARS * 3))) == MAX_RAW_CHARS


@pytest.mark.parametrize(
    ("value", "spf_", "dmarc_"),
    [
        ("v=spf1", True, False),
        ("v=spf1 -all", True, False),
        ("V=SPF1 -all", True, False),
        ("v=spf10 -all", False, False),
        ("xv=spf1", False, False),
        ("v=DMARC1; p=none", False, True),
        ("v=dmarc1", False, True),
        ("v=DMARC10", False, False),
        ("", False, False),
    ],
)
def test_record_kind_filters(value: str, spf_: bool, dmarc_: bool) -> None:
    assert is_spf(value) is spf_
    assert is_dmarc(value) is dmarc_


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10 Mail.Example.COM.", "10 mail.example.com"),
        ("010  mail.example.com", "10 mail.example.com"),
        ("0 .", "0 "),
        ("mail.example.com", "mail.example.com"),
        ("x y z", "x y z"),
        ("10 mail\x00.example.com", "10 mail�.example.com"),
        ("999999 mail.example.com", "999999 mail.example.com"),
        ("", ""),
    ],
)
def test_normalise_mx(raw: str, expected: str) -> None:
    assert normalise_mx(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("NS1.Example.NET.", "ns1.example.net"), ("  ns1.example.net ", "ns1.example.net"), ("", "")],
)
def test_normalise_ns(raw: str, expected: str) -> None:
    assert normalise_ns(raw) == expected


# --- entries and snapshots ---------------------------------------------------------------------


def test_values_are_sorted_distinct_and_hashed_in_full() -> None:
    e = entry("@", "NS", "ok", "b.example.net", "a.example.net", "a.example.net")
    assert [v.text for v in e.values] == ["a.example.net", "b.example.net"]
    assert e.count == 2
    assert entry("@", "NS", "ok", "a.example.net", "b.example.net").entry_hash == e.entry_hash


@pytest.mark.parametrize("state", ["nxdomain", "nodata", "error"])
def test_absent_and_error_states_carry_no_values(state: str) -> None:
    e = entry("@", "NS", state, "a.example.net")
    assert e.values == () and e.count == 0


@pytest.mark.parametrize(
    ("name", "rdtype", "state", "values"),
    [
        ("", "TXT", "ok", ["x"]),
        ("a" * (MAX_NAME_LENGTH + 1), "TXT", "ok", ["x"]),
        ("@", "A", "ok", ["x"]),
        ("@", "TXT", "servfail", []),
        ("@", "TXT", "ok", []),
        (None, "TXT", "ok", ["x"]),
    ],
)
def test_build_entry_rejects_bad_input(
    name: Any, rdtype: str, state: str, values: list[str]
) -> None:
    with pytest.raises(SnapshotFormatError):
        build_entry(name, rdtype, state, values)


def test_long_value_is_truncated_for_display_but_hashed_in_full() -> None:
    a = entry("@", "TXT", "ok", "x" * 5000)
    b = entry("@", "TXT", "ok", "x" * 4999 + "y")
    assert len(a.values[0].text or "") == MAX_VALUE_CHARS
    assert a.entry_hash != b.entry_hash  # the change is beyond the cut and still seen
    assert snap(a).truncated
    changes = diff_snapshots(snap(a), snap(b))
    assert [c.kind for c in changes] == ["changed"]
    assert all(
        len(t) <= MAX_VALUE_CHARS for t in changes[0].before_values + changes[0].after_values
    )


def test_value_exactly_at_the_cap_is_not_truncated() -> None:
    assert not snap(entry("@", "TXT", "ok", "x" * MAX_VALUE_CHARS)).truncated


def test_many_values_are_capped_and_flagged_but_counted_and_hashed() -> None:
    values = [f"v{i:04d}" for i in range(MAX_VALUES_PER_ENTRY + 30)]
    a = entry("@", "TXT", "ok", *values)
    assert len(a.values) == MAX_VALUES_PER_ENTRY and a.count == len(values)
    assert snap(a).truncated
    b = entry("@", "TXT", "ok", *values[:-1], "other")  # differs only in a value past the cap
    assert [c.kind for c in diff_snapshots(snap(a), snap(b))] == ["changed"]


def test_snapshot_hash_is_order_independent_and_state_sensitive() -> None:
    a, b = spf(SPF1), entry("@", "NS", "ok", "ns1.example.net")
    assert build_snapshot([a, b]).content_hash == build_snapshot([b, a]).content_hash
    assert snap(spf(state="nodata")).content_hash != snap(spf(state="error")).content_hash
    assert snap(spf(SPF1)).content_hash != snap(spf(SPF2)).content_hash


def test_duplicate_entries_and_too_many_entries_are_rejected() -> None:
    with pytest.raises(SnapshotFormatError):
        snap(spf(SPF1), spf(SPF2))
    many = [entry(f"s{i}._domainkey", "TXT", "nodata") for i in range(MAX_ENTRIES + 1)]
    with pytest.raises(SnapshotFormatError):
        build_snapshot(many)


def test_caller_truncated_flag_is_kept() -> None:
    assert build_snapshot([spf(SPF1)], truncated=True).truncated


# --- storage form ------------------------------------------------------------------------------


def test_stored_round_trip_keeps_content_and_diff() -> None:
    s = snap(
        spf(SPF1), entry("@", "MX", "ok", "10 mx.example.net"), entry("_dmarc", "TXT", "nxdomain")
    )
    stored, truncated = to_stored(s)
    assert not truncated
    back = from_stored(json.loads(json.dumps(stored)), s.content_hash, truncated)
    assert back.content_hash == s.content_hash
    assert diff_snapshots(s, back) == ()
    assert [(e.name, e.rdtype, e.state, e.count) for e in back.entries] == [
        (e.name, e.rdtype, e.state, e.count) for e in s.entries
    ]


def test_stored_size_is_measured_on_the_stored_text_and_degrades_to_hashes() -> None:
    # Non-ASCII text costs up to 6 bytes per character in the stored JSON (\uXXXX escapes).
    entries = [
        entry(f"{i:060d}._domainkey", "TXT", "ok", *(f"{j}中" * 60 for j in range(8)))
        for i in range(MAX_ENTRIES)
    ]
    s = build_snapshot(entries)
    assert len(json.dumps([{"v": v.text} for e in s.entries for v in e.values])) > 100_000
    stored, truncated = to_stored(s)
    assert len(json.dumps(stored)) <= MAX_ENTRIES_BYTES
    assert truncated
    assert all("v" not in v for item in stored for v in item["values"])
    back = from_stored(stored, s.content_hash, truncated)
    # Without texts the diff still sees a real change, with no values to show.
    other = build_snapshot([*entries[:-1], entry(entries[-1].name, "TXT", "ok", "different")])
    changes = diff_snapshots(back, other)
    assert [(c.name, c.kind, c.before_values) for c in changes] == [
        (entries[-1].name, "changed", ())
    ]


def test_stored_within_the_cap_keeps_texts() -> None:
    stored, truncated = to_stored(snap(spf(SPF1)))
    assert stored[0]["values"][0]["v"] == SPF1 and not truncated


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: "not a list",
        lambda s: [*s, "x"],
        lambda s: [{**s[0], "type": "A"}],
        lambda s: [{**s[0], "state": "servfail"}],
        lambda s: [{**s[0], "name": ""}],
        lambda s: [{**s[0], "name": "x" * 200}],
        lambda s: [{**s[0], "count": "1"}],
        lambda s: [{**s[0], "count": True}],
        lambda s: [{**s[0], "count": -1}],
        lambda s: [{**s[0], "eh": "zz"}],
        lambda s: [{**s[0], "values": "x"}],
        lambda s: [{**s[0], "values": [{"h": "bad"}]}],
        lambda s: [{**s[0], "values": [{"h": s[0]["eh"], "v": 5}]}],
        lambda s: [{**s[0], "values": [{"h": s[0]["eh"], "v": "x" * (MAX_VALUE_CHARS + 1)}]}],
        lambda s: [{**s[0], "values": [s[0]["values"][0]] * 9}],  # more values than count
        lambda s: [{**s[0], "state": "error"}],  # error with a count
        lambda s: [s[0], s[0]],  # duplicate key
        lambda s: [{k: v for k, v in s[0].items() if k != "eh"}],
    ],
)
def test_from_stored_rejects_malformed_content(mutate: Any) -> None:
    good, _ = to_stored(snap(spf(SPF1)))
    with pytest.raises(SnapshotFormatError):
        from_stored(mutate(good), "a" * 64)


@pytest.mark.parametrize("bad_hash", ["", "A" * 64, "a" * 63, None, 5])
def test_from_stored_rejects_a_bad_content_hash(bad_hash: Any) -> None:
    with pytest.raises(SnapshotFormatError):
        from_stored([], bad_hash)


# --- diff --------------------------------------------------------------------------------------


def kinds(before: Snapshot, after: Snapshot) -> list[tuple[str, str, str]]:
    return [(c.name, c.rdtype, c.kind) for c in diff_snapshots(before, after)]


def test_identical_snapshots_have_no_changes() -> None:
    s = snap(spf(SPF1), entry("@", "NS", "ok", "a.example.net"))
    assert diff_snapshots(s, s) == ()


def test_record_reordering_is_not_a_change() -> None:
    a = snap(entry("@", "MX", "ok", "10 a.example.net", "20 b.example.net"))
    b = snap(entry("@", "MX", "ok", "20 b.example.net", "10 a.example.net"))
    assert diff_snapshots(a, b) == ()


def test_txt_multi_string_equality_is_not_a_change() -> None:
    a = snap(spf(normalise_txt('"v=spf1 include:_spf" ".example.net -all"')))
    b = snap(spf(normalise_txt(SPF1)))
    c = snap(spf(normalise_txt("  V=SPF1   include:_SPF.example.net\t-ALL ")))
    assert diff_snapshots(a, b) == () and diff_snapshots(b, c) == ()


def test_spf_change() -> None:
    changes = diff_snapshots(snap(spf(SPF1)), snap(spf(SPF2)))
    assert len(changes) == 1
    c = changes[0]
    assert (c.name, c.rdtype, c.kind) == ("@", "TXT", "changed")
    assert c.before_values == (SPF1,) and c.after_values == (SPF2,)
    assert c.before_hash != c.after_hash and c.before_hash and c.after_hash


def test_ns_change() -> None:
    a = snap(entry("@", "NS", "ok", "ns1.example.net", "ns2.example.net"))
    b = snap(entry("@", "NS", "ok", "ns1.example.net", "ns3.example.net"))
    (c,) = diff_snapshots(a, b)
    assert (c.name, c.rdtype, c.kind) == ("@", "NS", "changed")
    assert c.before_values == ("ns1.example.net", "ns2.example.net")
    assert c.after_values == ("ns1.example.net", "ns3.example.net")


@pytest.mark.parametrize("gone", ["nxdomain", "nodata"])
def test_dmarc_removed_is_removed(gone: str) -> None:
    a = snap(entry("_dmarc", "TXT", "ok", DMARC1))
    b = snap(entry("_dmarc", "TXT", gone))
    (c,) = diff_snapshots(a, b)
    assert c.kind == "removed" and c.before_values == (DMARC1,)
    assert c.after_hash is None and c.after_values == ()


@pytest.mark.parametrize("gone", ["nxdomain", "nodata"])
def test_dmarc_added(gone: str) -> None:
    (c,) = diff_snapshots(
        snap(entry("_dmarc", "TXT", gone)), snap(entry("_dmarc", "TXT", "ok", DMARC1))
    )
    assert c.kind == "added" and c.before_hash is None and c.after_values == (DMARC1,)


def test_dmarc_lookup_error_is_inconclusive_never_removed() -> None:
    ok = snap(entry("_dmarc", "TXT", "ok", DMARC1))
    err = snap(entry("_dmarc", "TXT", "error"))
    assert kinds(ok, err) == [("_dmarc", "TXT", "inconclusive")]
    assert kinds(err, ok) == [("_dmarc", "TXT", "inconclusive")]
    assert kinds(err, err) == [("_dmarc", "TXT", "inconclusive")]
    gone = snap(entry("_dmarc", "TXT", "nxdomain"))
    assert kinds(gone, err) == [("_dmarc", "TXT", "inconclusive")]
    (c,) = diff_snapshots(ok, err)
    assert c.after_hash is None and c.before_values == () and c.after_values == ()


def test_entry_on_one_side_only_is_inconclusive() -> None:
    a = snap(spf(SPF1))
    b = snap(spf(SPF1), entry("sel._domainkey", "TXT", "ok", "v=DKIM1; p=abc"))
    assert kinds(a, b) == [("sel._domainkey", "TXT", "inconclusive")]
    assert kinds(b, a) == [("sel._domainkey", "TXT", "inconclusive")]


def test_two_absent_states_are_no_change() -> None:
    assert diff_snapshots(snap(spf(state="nxdomain")), snap(spf(state="nodata"))) == ()


def test_changes_are_sorted_and_stable() -> None:
    a = snap(
        spf(SPF1), entry("@", "NS", "ok", "a.example.net"), entry("_dmarc", "TXT", "ok", DMARC1)
    )
    b = snap(spf(SPF2), entry("@", "NS", "ok", "b.example.net"), entry("_dmarc", "TXT", "nodata"))
    first = diff_snapshots(a, b)
    assert [(c.name, c.rdtype) for c in first] == [("@", "NS"), ("@", "TXT"), ("_dmarc", "TXT")]
    assert diff_snapshots(a, b) == first


def test_hostile_values_stay_bounded_and_safe() -> None:
    hostile = [
        normalise_txt("\x00" * 100_000),
        normalise_txt("‮" + "x" * 300 + "\x1b[31m"),
        normalise_txt('"' * 5000),
        normalise_txt("𐏿" * 400),
    ]
    a = snap(entry("@", "TXT", "ok", *hostile))
    stored, _ = to_stored(a)
    text = json.dumps(stored)
    assert "\\u0000" not in text and "\x00" not in text
    assert len(text) <= MAX_ENTRIES_BYTES
    assert all(len(v.text or "") <= MAX_VALUE_CHARS for e in a.entries for v in e.values)
    other = snap(entry("@", "TXT", "ok", "benign"))
    (c,) = diff_snapshots(a, other)
    assert c.kind == "changed"
