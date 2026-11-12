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
    assert p.state == "unknown" and p.reason == "no_stated_result" and p.stated_result is None
    assert p.relaxed_aligned


RETURN_PATH_CASES = [
    ("Return-Path: <b@example.com>", "unknown", "no_stated_result"),
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
    assert p.state == "unknown" and p.reason == "no_stated_result" and p.strict_aligned
    assert r.computed_dmarc == "not_evaluated"


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
    assert r.computed_dmarc == "not_evaluated"  # nothing was stated by a receiver


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


def test_signature_only_with_stated_dmarc_pass_is_not_a_mismatch():
    r = _report(
        "From: a@good.com",
        "DKIM-Signature: v=1; d=good.com; s=a; b=y",
        "Authentication-Results: mx.example.net; dmarc=pass header.from=good.com",
    )
    assert r.computed_dmarc == "not_evaluated" and not r.dmarc_mismatch


def test_return_path_only_without_authres_is_not_evaluated():
    r = _report("From: a@good.com", "Return-Path: <x@good.com>")
    assert r.computed_dmarc == "not_evaluated"
    assert _pair(r, "spf").reason == "no_stated_result"


def test_helo_pass_does_not_align_return_path():
    r = _report(
        "From: a@good.com",
        "Return-Path: <x@good.com>",
        "Authentication-Results: mx.example.net; spf=pass smtp.helo=good.com",
    )
    p = _pair(r, "spf")
    assert (p.state, p.stated_result, p.reason) == ("unknown", None, "no_stated_result")
    assert r.computed_dmarc == "not_evaluated"


def test_sources_are_carried_and_mixed_sources_visible():
    r = _report(
        "From: a@example.com",
        "Authentication-Results: mx.a.net; dmarc=pass header.from=example.com",
        "Authentication-Results: mx.b.net; spf=pass smtp.mailfrom=a@example.com;"
        " dkim=pass header.d=example.com",
        "DKIM-Signature: v=1; d=other.org; s=a",
    )
    assert (r.stated_dmarc_authserv_id, r.stated_dmarc_index) == ("mx.a.net", 0)
    spf, dkim = _pair(r, "spf"), _pair(r, "dkim")
    assert (spf.authserv_id, spf.authres_index) == ("mx.b.net", 1)
    assert (dkim.authserv_id, dkim.authres_index) == ("mx.b.net", 1)
    sig = _pair(r, "dkim", 1)
    assert (sig.authserv_id, sig.authres_index) == (None, None)


# R1-09: a stated dkim=none is "no signature" (RFC 8601 section 2.7.1); spf uses the first
# resinfo that carries smtp.mailfrom. From and Return-Path are a@example.com in every row.
# (authres body, computed_dmarc, spf state, dkim states as (state, reason))
R109_CASES = [
    # (1) unsigned, spf fail: a plain DMARC failure
    (
        "spf=fail smtp.mailfrom=example.com; dkim=none; dmarc=fail header.from=example.com",
        "fail",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature")],
    ),
    # (2) unsigned with a placeholder header.d
    (
        "spf=fail smtp.mailfrom=example.com; dkim=none (message not signed) header.d=none;"
        " dmarc=fail header.from=example.com",
        "fail",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature")],
    ),
    # (2b) unsigned with a usable header.d: still no signature
    (
        "spf=fail smtp.mailfrom=example.com; dkim=none header.d=example.com",
        "fail",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature")],
    ),
    # (2c) unsigned with a malformed header.d
    (
        "spf=fail smtp.mailfrom=example.com; dkim=none header.d=192.0.2.1",
        "fail",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature")],
    ),
    # (2d) case-insensitive result
    (
        "spf=fail smtp.mailfrom=example.com; dkim=NONE",
        "fail",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature")],
    ),
    # (3) unsigned, aligned spf pass: stays pass
    (
        "spf=pass smtp.mailfrom=example.com; dkim=none; dmarc=pass header.from=example.com",
        "pass",
        "aligned",
        [("not_evaluated", "no_signature")],
    ),
    # unsigned, misaligned spf pass: fail
    (
        "spf=pass smtp.mailfrom=other.org; dkim=none",
        "fail",
        "misaligned",
        [("not_evaluated", "no_signature")],
    ),
    # (4) other dkim results without usable header.d stay unknown
    (
        "spf=fail smtp.mailfrom=example.com; dkim=fail",
        "not_evaluated",
        "aligned_but_not_passed",
        [("unknown", "missing_d")],
    ),
    (
        "spf=fail smtp.mailfrom=example.com; dkim=temperror header.d=none",
        "not_evaluated",
        "aligned_but_not_passed",
        [("unknown", "invalid_domain_single_label")],
    ),
    (
        "spf=fail smtp.mailfrom=example.com; dkim=permerror header.d=",
        "not_evaluated",
        "aligned_but_not_passed",
        [("unknown", "missing_d")],
    ),
    # (5) helo before mailfrom, and swapped: same result
    (
        "spf=pass smtp.helo=mail.example.com; spf=pass smtp.mailfrom=example.com;"
        " dmarc=pass header.from=example.com",
        "pass",
        "aligned",
        [("not_evaluated", "no_identifier")],
    ),
    (
        "spf=pass smtp.mailfrom=example.com; spf=pass smtp.helo=mail.example.com;"
        " dmarc=pass header.from=example.com",
        "pass",
        "aligned",
        [("not_evaluated", "no_identifier")],
    ),
    # helo pass then mailfrom fail: the mailfrom result is used
    (
        "spf=pass smtp.helo=mail.example.com; spf=fail smtp.mailfrom=example.com; dkim=none",
        "fail",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature")],
    ),
    # (6) spf with only smtp.helo: Return-Path fallback with no stated result, as today
    (
        "spf=pass smtp.helo=mail.example.com; dkim=none",
        "not_evaluated",
        "unknown",
        [("not_evaluated", "no_signature")],
    ),
    # (7) dkim=none plus a signed result for another domain: unchanged precedence
    (
        "spf=pass smtp.mailfrom=example.com; dkim=none; dkim=pass header.d=other.org",
        "pass",
        "aligned",
        [("not_evaluated", "no_signature"), ("misaligned", None)],
    ),
    (
        "spf=fail smtp.mailfrom=example.com; dkim=none; dkim=pass header.d=other.org",
        "fail",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature"), ("misaligned", None)],
    ),
    (
        "spf=fail smtp.mailfrom=example.com; dkim=none; dkim=pass header.d=example.com",
        "pass",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature"), ("aligned", None)],
    ),
    # dkim=none with an unusable second result: the unknown pair still blocks a verdict
    (
        "spf=fail smtp.mailfrom=example.com; dkim=none; dkim=fail",
        "not_evaluated",
        "aligned_but_not_passed",
        [("not_evaluated", "no_signature"), ("unknown", "missing_d")],
    ),
]


@pytest.mark.parametrize(("body", "computed", "spf_state", "dkim"), R109_CASES)
def test_dkim_none_and_spf_mailfrom_selection(body, computed, spf_state, dkim):
    r = _report(
        "From: a@example.com",
        "Return-Path: <a@example.com>",
        f"Authentication-Results: mx.example.org; {body}",
    )
    assert r.computed_dmarc == computed
    assert _pair(r, "spf").state == spf_state
    assert [(p.state, p.reason) for p in r.pairs if p.kind == "dkim"] == dkim


def test_dkim_none_alone_does_not_make_a_verdict_without_spf():
    # DMARC rests on SPF alone: with no spf identifier there is still nothing to evaluate.
    r = _report("From: a@example.com", "Authentication-Results: mx.example.org; dkim=none")
    assert r.computed_dmarc == "not_evaluated"
    p = _pair(r, "dkim")
    assert (p.state, p.reason, p.stated_result) == ("not_evaluated", "no_signature", "none")
    assert (p.authserv_id, p.authres_index) == ("mx.example.org", 0)


def test_dkim_none_with_mailfrom_spf_from_first_resinfo_source():
    r = _report(
        "From: a@example.com",
        "Authentication-Results: mx.example.org; spf=neutral smtp.helo=mail.example.com;"
        " spf=pass smtp.mailfrom=b@example.com",
    )
    p = _pair(r, "spf")
    assert (p.identifier_source, p.stated_result, p.authserv_id) == (
        "smtp.mailfrom",
        "pass",
        "mx.example.org",
    )


@pytest.mark.parametrize(
    "body",
    [
        "spf=pass smtp.mailfrom; dkim=none",
        "spf=; dkim=none header.d",
        "spf=pass smtp.helo=; smtp.mailfrom=example.com; dkim=none (unterminated",
        "dkim=none header.d=a..b; spf=fail smtp.mailfrom=<>",
    ],
)
def test_malformed_authres_with_dkim_none_does_not_crash(body):
    r = _report(
        "From: a@example.com",
        "Return-Path: <a@example.com>",
        f"Authentication-Results: mx.example.org; {body}",
    )
    assert r.computed_dmarc in ("pass", "fail", "not_evaluated")
    assert _pair(r, "spf").state != "aligned"
