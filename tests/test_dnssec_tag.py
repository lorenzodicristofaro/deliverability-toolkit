from pathlib import Path

import pytest

from tests.dnssec_tag import key_tag, root_key_tags

# /usr/share/dns/root.key of Debian dns-root-data 2025080400~deb13u1 (public data, IANA).
FIXTURE = Path(__file__).parent / "fixtures" / "root.key.dns-root-data-2025080400"
KEY = next(line.split()[6] for line in FIXTURE.read_text().splitlines() if "keytag 38696" in line)


def test_fixture_has_both_ksks() -> None:
    # Tags computed from the records themselves (RFC 4034 App. B), not read from comments.
    assert root_key_tags(FIXTURE.read_text()) == {20326, 38696}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", set()),
        ("; only a comment\n;;id: . 1\n", set()),
        (f". IN DNSKEY 257 3 8 {KEY}\n", {38696}),
        (f".\t3600\tIN\tDNSKEY\t257 3 8 {KEY} ;{{id = 38696 (ksk)}} ;;state=2\n", {38696}),
        (". IN DS 20326 8 2 abcdef\n", set()),
    ],
)
def test_root_key_tags(text: str, expected: set[int]) -> None:
    assert root_key_tags(text) == expected


@pytest.mark.parametrize(
    "text",
    [". IN DNSKEY 257 3 8\n", ". IN DNSKEY 257 3 8 !!!notbase64\n", ". IN DNSKEY x 3 8 AAAA\n"],
)
def test_root_key_tags_malformed(text: str) -> None:
    with pytest.raises(ValueError):
        root_key_tags(text)


def test_key_tag_rejects_rsamd5() -> None:
    with pytest.raises(ValueError):
        key_tag(257, 3, 1, b"\x00")
