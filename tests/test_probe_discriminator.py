"""Unit tests (no docker) for the host-probe discriminator used by the integration tests."""

from __future__ import annotations

import pytest

from tests.integration.stack import host_probe_is_unbound

_HDR = (
    ";; ->>HEADER<<- opcode: QUERY, rcode: {rcode}, id: 1\n"
    ";; flags: {flags}; QUERY: 1, ANSWER: {n}, AUTHORITY: 0, ADDITIONAL: 0\n"
)
_ANS = ";; ANSWER SECTION:\nietf.org.\t300\tIN\tA\t104.16.44.99\n"

CASES = [
    ("timeout", ";; No response from 127.0.0.1\n", False),
    ("empty", "", False),
    ("garbage", "\x00\xff not dns \n", False),
    ("refused", _HDR.format(rcode="REFUSED", flags="qr rd", n=0), False),
    ("noerror_no_ra_empty", _HDR.format(rcode="NOERROR", flags="qr", n=0), False),
    ("noerror_no_ra_answer", _HDR.format(rcode="NOERROR", flags="qr aa", n=1) + _ANS, False),
    ("servfail_ra", _HDR.format(rcode="SERVFAIL", flags="qr rd ra", n=0), False),
    ("valid_ad", _HDR.format(rcode="NOERROR", flags="qr rd ra ad", n=1) + _ANS, True),
    ("valid_ra_answer", _HDR.format(rcode="NOERROR", flags="qr rd ra", n=1) + _ANS, True),
]


@pytest.mark.parametrize(("name", "output", "expected"), CASES, ids=[c[0] for c in CASES])
def test_host_probe_is_unbound(name: str, output: str, expected: bool) -> None:
    assert host_probe_is_unbound(output) is expected
