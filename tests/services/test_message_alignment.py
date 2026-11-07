import pytest

from app.parsers.message import parse_header_block
from app.services.message_alignment import MAX_DKIM_PAIRS, AlignmentPair, analyze_alignment


def _report(*headers: str):
    raw = ("\r\n".join(headers) + "\r\n\r\nbody").encode()
    return analyze_alignment(parse_header_block(raw))


def _pair(report, kind: str, index: int = 0) -> AlignmentPair:
    return [p for p in report.pairs if p.kind == kind][index]


AR_PASS = (
    "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=bounce@example.com;"
    " dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
)


def test_fully_aligned_with_stated_pass():
    r = _report("From: A <a@example.com>", AR_PASS)
    spf, dkim = _pair(r, "spf"), _pair(r, "dkim")
    assert (spf.state, spf.relaxed_aligned, spf.strict_aligned) == ("aligned", True, True)
    assert (dkim.state, dkim.identifier_source) == ("aligned", "authres_header_d")
    assert r.computed_dmarc == "pass" and r.stated_dmarc == "pass" and not r.dmarc_mismatch
    assert not dkim.unverified_signature


# (from header, authres spf part, expected state, relaxed, strict, reason)
SPF_CASES = [
    ("a@example.com", "pass smtp.mailfrom=b@mail.example.com", "aligned", True, False, None),
    ("a@mail.example.com", "pass smtp.mailfrom=b@example.com", "aligned", True, False, None),
    ("a@EXAMPLE.com", "pass smtp.mailfrom=b@example.COM.", "aligned", True, True, None),
    ("a@bücher.example", "pass smtp.mailfrom=b@xn--bcher-kva.example", "aligned", True, True, None),
    ("a@xn--bcher-kva.example", "pass smtp.mailfrom=b@bücher.example", "aligned", True, True, None),
    ("a@example.com", "pass smtp.mailfrom=b@other.org", "misaligned", False, False, None),
    (
        "a@example.com",
        "fail smtp.mailfrom=b@example.com",
        "aligned_but_not_passed",
        True,
        True,
        None,
    ),
    (
        "a@example.com",
        "softfail smtp.mailfrom=example.com",
        "aligned_but_not_passed",
        True,
        True,
        None,
    ),
    ("a@a.github.io", "pass smtp.mailfrom=b@b.github.io", "misaligned", False, False, None),
    ("a@a.example.co.uk", "pass smtp.mailfrom=x@b.example.co.uk", "aligned", True, False, None),
    ("a@example.co.uk", "pass smtp.mailfrom=x@other.co.uk", "misaligned", False, False, None),
    ("a@github.io", "pass smtp.mailfrom=x@github.io", "aligned", True, True, None),
    ("a@example.com", "pass smtp.mailfrom=", "unknown", False, False, "null_return_path"),
    ("a@example.com", "pass smtp.mailfrom=<>", "unknown", False, False, "null_return_path"),
    (
        "a@example.com",
        "pass smtp.mailfrom=b@[192.0.2.1]",
        "unknown",
        False,
        False,
        "invalid_domain_ip_address",
    ),
    (
        "a@example.com",
        "pass smtp.mailfrom=b@192.0.2.1",
        "unknown",
        False,
        False,
        "invalid_domain_ip_address",
    ),
    (
        "a@example.com",
        "pass smtp.mailfrom=b@localhost",
        "unknown",
        False,
        False,
        "invalid_domain_single_label",
    ),
    (
        "a@example.com",
        "pass smtp.mailfrom=b@exa_mple.com",
        "unknown",
        False,
        False,
        "invalid_domain_idna",
    ),
    ("a@example.com", "pass smtp.mailfrom=b@", "unknown", False, False, "invalid_domain_empty"),
    (
        "a@[192.0.2.1]",
        "pass smtp.mailfrom=b@example.com",
        "unknown",
        False,
        False,
        "invalid_address",
    ),
]


@pytest.mark.parametrize(("frm", "spf", "state", "relaxed", "strict", "reason"), SPF_CASES)
def test_spf_table(frm, spf, state, relaxed, strict, reason):
    r = _report(f"From: {frm}", f"Authentication-Results: mx.example.net; spf={spf}")
    p = _pair(r, "spf")
    assert (p.state, p.relaxed_aligned, p.strict_aligned, p.reason) == (
        state,
        relaxed,
        strict,
        reason,
    )


def test_org_domains_reported():
    r = _report("From: a@x.example.com", "Return-Path: <b@y.example.com>")
    p = _pair(r, "spf")
    assert (p.from_org, p.identifier_org, p.identifier_source) == (
        "example.com",
        "example.com",
        "return_path",
    )
    # no stated spf result: domain match is never "aligned"
    assert p.state == "aligned_but_not_passed" and p.stated_result is None


RETURN_PATH_CASES = [
    ("Return-Path: <b@example.com>", "aligned_but_not_passed", None),
    ("Return-Path: <>", "unknown", "null_return_path"),
    ("Return-Path:", "unknown", "null_return_path"),
    ("Return-Path: nonsense", "unknown", "invalid_address"),
    ("Return-Path: <a@x.org>\r\nReturn-Path: <a@y.org>", "unknown", "multiple_return_path"),
    ("Return-Path: <b@other.org>", "misaligned", None),
]


@pytest.mark.parametrize(("header", "state", "reason"), RETURN_PATH_CASES)
def test_return_path_header_table(header, state, reason):
    r = _report("From: a@example.com", header)
    p = _pair(r, "spf")
    assert (p.state, p.reason) == (state, reason)


FROM_CASES = [
    (["From: a@example.com, b@mail.example.com"], "aligned", ("example.com", "mail.example.com")),
    (["From: a@example.com, b@example.com"], "aligned", ("example.com",)),
    (["From: a@example.com, b@other.org"], "unknown", ("example.com", "other.org")),
    (["From: a@example.com", "From: b@example.com"], "unknown", ()),
    (["X-Other: 1"], "unknown", ()),
    (["From:"], "unknown", ()),
    (["From: not an address"], "unknown", ()),
    (["From: undisclosed-recipients:;"], "unknown", ()),
]


@pytest.mark.parametrize(("from_headers", "state", "domains"), FROM_CASES)
def test_from_table(from_headers, state, domains):
    r = _report(*from_headers, AR_PASS)
    spf = _pair(r, "spf")
    if state == "aligned":
        # From example.com (+ maybe subdomain) vs example.com identifiers
        assert spf.state == "aligned" or spf.from_domain is None
    else:
        assert spf.state == "unknown"
        assert spf.reason is not None
        assert r.computed_dmarc == "not_evaluated"
    assert r.from_domains == domains


def test_from_reason_codes():
    assert _pair(_report("X: 1", AR_PASS), "spf").reason == "missing_from"
    two = _report("From: a@example.com", "From: b@example.com", AR_PASS)
    assert _pair(two, "spf").reason == "multiple_from_headers"
    many = _report("From: a@example.com, b@other.org", AR_PASS)
    assert _pair(many, "spf").reason == "multiple_from_domains"


def test_dkim_subdomain_and_parent_and_multiple_results():
    r = _report(
        "From: a@mail.example.com",
        "Authentication-Results: mx.example.net;"
        " dkim=pass header.d=example.com; dkim=fail header.d=other.org;"
        " dkim=pass header.d=sub.mail.example.com",
    )
    dk = [p for p in r.pairs if p.kind == "dkim"]
    assert len(dk) == 3
    parent, other, sub = dk
    assert (parent.state, parent.relaxed_aligned, parent.strict_aligned) == ("aligned", True, False)
    assert other.state == "misaligned" and other.stated_result == "fail"
    assert (sub.state, sub.strict_aligned) == ("aligned", False)
    assert r.computed_dmarc == "pass"


def test_dkim_signature_unverified():
    r = _report(
        "From: a@example.com",
        "DKIM-Signature: v=1; a=rsa-sha256; d=Example.COM; s=sel;\r\n bh=x; b=y",
    )
    p = _pair(r, "dkim")
    assert p.unverified_signature and p.stated_result is None
    assert p.identifier_source == "dkim_signature"
    assert p.state == "aligned_but_not_passed" and p.strict_aligned
    assert r.computed_dmarc == "fail"


def test_dkim_signature_matching_stated_result_is_not_duplicated():
    r = _report(
        "From: a@example.com",
        "DKIM-Signature: v=1; d=example.com; s=a; b=y",
        "DKIM-Signature: v=1; d=other.org; s=a; b=y",
        "Authentication-Results: mx.example.net; dkim=pass header.d=example.com",
    )
    dk = [p for p in r.pairs if p.kind == "dkim"]
    assert [(p.identifier_domain, p.unverified_signature, p.state) for p in dk] == [
        ("example.com", False, "aligned"),
        ("other.org", True, "misaligned"),
    ]


@pytest.mark.parametrize(
    ("sig", "reason"),
    [
        ("DKIM-Signature: v=1; s=a; b=y", "missing_d"),
        ("DKIM-Signature: v=1; d=; s=a", "missing_d"),
        ("DKIM-Signature: v=1; d=[192.0.2.1]", "invalid_domain_ip_address"),
        ("DKIM-Signature: garbage", "missing_d"),
        ("DKIM-Signature: d=exa_mple.com", "invalid_domain_idna"),
    ],
)
def test_dkim_signature_malformed(sig, reason):
    p = _pair(_report("From: a@example.com", sig), "dkim")
    assert (p.state, p.reason, p.unverified_signature) == ("unknown", reason, True)


def test_dkim_missing_header_d_in_authres():
    r = _report("From: a@example.com", "Authentication-Results: mx.example.net; dkim=pass")
    p = _pair(r, "dkim")
    assert (p.state, p.reason) == ("unknown", "missing_d")


def test_no_data_is_not_evaluated():
    r = _report("From: a@example.com")
    assert [p.state for p in r.pairs] == ["not_evaluated", "not_evaluated"]
    assert all(p.reason == "no_identifier" for p in r.pairs)
    assert r.computed_dmarc == "not_evaluated" and not r.dmarc_mismatch
    assert r.stated_dmarc is None


def test_no_authres_and_misaligned_means_computed_fail():
    r = _report("From: a@example.com", "Return-Path: <b@other.org>")
    assert r.computed_dmarc == "fail"


@pytest.mark.parametrize(
    ("stated", "computed", "mismatch"),
    [
        ("pass", "fail", True),
        ("fail", "pass", True),
        ("pass", "pass", False),
        ("none", "pass", False),
        ("temperror", "fail", False),
    ],
)
def test_dmarc_mismatch(stated, computed, mismatch):
    if computed == "pass":
        body = "spf=pass smtp.mailfrom=a@example.com"
    else:
        body = "spf=pass smtp.mailfrom=a@other.org"
    r = _report(
        "From: a@example.com",
        f"Authentication-Results: mx.example.net; {body}; dmarc={stated} header.from=example.com",
    )
    assert r.computed_dmarc == computed
    assert r.dmarc_mismatch is mismatch


def test_topmost_authres_used_per_method():
    r = _report(
        "From: a@example.com",
        "Authentication-Results: mx.a.net; spf=pass smtp.mailfrom=a@example.com",
        "Authentication-Results: forged.net; spf=pass smtp.mailfrom=a@other.org",
    )
    assert _pair(r, "spf").state == "aligned"


def test_malformed_authres_does_not_crash():
    r = _report("From: a@example.com", "Authentication-Results: ;;;==", "Return-Path: <>")
    assert _pair(r, "spf").state == "unknown"


def test_dkim_pairs_capped():
    sigs = [f"DKIM-Signature: v=1; d=d{i}.example.com; s=a" for i in range(MAX_DKIM_PAIRS + 5)]
    r = _report("From: a@example.com", *sigs)
    assert r.truncated
    assert len([p for p in r.pairs if p.kind == "dkim"]) == MAX_DKIM_PAIRS
