"""M1-18 edge validation of domain names (IDNA 2008 / UTS #46 via `idna`). No DNS, no network."""

import pytest

from app.core.domain_names import (
    MAX_INPUT_LENGTH,
    InvalidDomainName,
    to_ascii_domain,
    to_display_name,
)
from app.models.domain import normalize_domain_name

LABEL_63 = "a" * 63
NAME_253 = ".".join([LABEL_63, LABEL_63, LABEL_63, "a" * 57, "com"])  # 63*3 + 57 + 3 + 4 dots
assert len(NAME_253) == 253


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.Com", "example.com"),
        ("example.com.", "example.com"),  # one trailing dot normalised
        ("mail.sub.example.co.uk", "mail.sub.example.co.uk"),
        ("a-b.example", "a-b.example"),
        ("1example.com", "1example.com"),
        ("123.com", "123.com"),  # numeric labels are fine except the last one
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("MÜNCHEN.DE", "xn--mnchen-3ya.de"),  # UTS #46 case mapping
        ("faß.de", "xn--fa-hia.de"),  # IDNA 2008 non-transitional: ß kept (2003 gives fass.de)
        ("Königsgäßchen.de", "xn--knigsgchen-b4a3dun.de"),
        ("例え.テスト", "xn--r8jz45g.xn--zckzah"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),  # A-label kept
        ("XN--MNCHEN-3YA.DE", "xn--mnchen-3ya.de"),
        ("example。com", "example.com"),  # ideographic full stop (UTS #46 mapping)
        ("ｅｘａｍｐｌｅ.com", "example.com"),  # full-width letters
        (f"{LABEL_63}.com", f"{LABEL_63}.com"),
        (NAME_253, NAME_253),
        (NAME_253 + ".", NAME_253),
    ],
)
def test_valid_names(raw: str, expected: str) -> None:
    result = to_ascii_domain(raw)
    assert result == expected
    assert normalize_domain_name(result) == result  # accepted unchanged by the M1-10 model


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (None, "not_a_string"),
        (123, "not_a_string"),
        (b"example.com", "not_a_string"),
        (["example.com"], "not_a_string"),
        ("", "empty"),
        ("x" * (MAX_INPUT_LENGTH + 1), "too_long"),
        # whitespace anywhere (no silent strip)
        (" example.com", "forbidden_character"),
        ("example.com ", "forbidden_character"),
        ("exa mple.com", "forbidden_character"),
        ("example.com\n", "forbidden_character"),
        ("example.com\t", "forbidden_character"),
        ("example .com", "forbidden_character"),  # NBSP
        ("example　.com", "forbidden_character"),  # ideographic space
        ("example .com", "forbidden_character"),  # line separator
        # NUL and other control characters (PostgreSQL rejects NUL in text)
        ("example.com\x00", "forbidden_character"),
        ("\x00", "forbidden_character"),
        ("exa\x00mple.com", "forbidden_character"),
        ("example.com\x01", "forbidden_character"),
        ("example\x1f.com", "forbidden_character"),
        ("example.com\x7f", "forbidden_character"),
        ("example\x85.com", "forbidden_character"),
        ("\ud800example.com", "forbidden_character"),  # lone surrogate
        ("example.com", "forbidden_character"),  # private use
        # IP addresses in any form
        ("192.0.2.1", "ip_address"),
        ("192.0.2.1.", "ip_address"),
        ("127.1", "ip_address"),
        ("１９２.０.２.１", "ip_address"),  # full-width digits map to an IPv4 address
        ("::1", "ip_address"),
        ("[::1]", "ip_address"),
        ("2001:db8::1", "ip_address"),
        ("example.123", "ip_address"),  # all-numeric TLD
        # structure and length
        ("com", "single_label"),
        ("localhost.", "single_label"),
        (".", "idna"),
        ("..", "idna"),
        ("example..com", "idna"),
        (".example.com", "idna"),
        ("example.com..", "idna"),
        ("a" * 64 + ".com", "idna"),
        (NAME_253 + "a", "idna"),  # 254 chars (idna checks the total length too)
        ("é" * 70 + ".com", "idna"),  # U-label whose A-label exceeds 63
        # label rules (STD3 / IDNA 2008)
        ("-example.com", "idna"),
        ("example-.com", "idna"),
        ("ab--cd.com", "idna"),  # hyphens in 3rd and 4th position
        ("xn--zz.com", "idna"),  # invalid punycode A-label
        ("xn--a.com", "idna"),  # decodes to a disallowed code point
        ("_dmarc.example.com", "idna"),
        ("ex_ample.com", "idna"),
        ("*.example.com", "idna"),
        ("example.com/path", "idna"),
        ("user@example.com", "idna"),
        ("http://example.com", "idna"),
        ("example.com:25", "idna"),
        ("‍example.com", "idna"),  # ZWJ outside its CONTEXTJ context
        ("اb.com", "idna"),  # bidi rule violation
        ("♥.com", "idna"),  # symbol, DISALLOWED in IDNA 2008 (valid in IDNA 2003)
    ],
)
def test_invalid_names(raw: object, reason: str) -> None:
    with pytest.raises(InvalidDomainName) as caught:
        to_ascii_domain(raw)
    assert caught.value.reason == reason
    if isinstance(raw, str) and raw:
        assert raw not in str(caught.value)  # the error never echoes the input


@pytest.mark.parametrize(
    ("stored", "shown"),
    [
        ("xn--mnchen-3ya.de", "münchen.de"),
        ("example.com", "example.com"),
        ("xn--zz.com", "xn--zz.com"),  # undecodable: shown as stored
    ],
)
def test_display_name(stored: str, shown: str) -> None:
    assert to_display_name(stored) == shown
