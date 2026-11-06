import pytest

from app.core.domain_names import InvalidDomainName
from app.core.org_domain import is_subdomain_of_org, organizational_domain

OK_CASES = [
    ("example.com", "example.com"),
    ("www.example.com", "example.com"),
    ("a.b.c.example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("Mail.Example.Com.", "example.com"),
    ("  mail.example.com  ", "example.com"),
    ("example.co.uk", "example.co.uk"),
    ("www.example.co.uk", "example.co.uk"),
    ("münchen.de", "xn--mnchen-3ya.de"),
    ("www.münchen.de", "xn--mnchen-3ya.de"),
    ("www.xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
    ("a.b.ck", "a.b.ck"),  # wildcard *.ck: "b.ck" is a suffix
    ("x.a.b.ck", "a.b.ck"),
    ("www.ck", "www.ck"),  # exception !www.ck: "ck" is the suffix
    ("x.www.ck", "www.ck"),
    ("foo.blogspot.com", "foo.blogspot.com"),  # private section respected
    ("x.foo.blogspot.com", "foo.blogspot.com"),
    ("a.github.io", "a.github.io"),
    ("example.unknowntld", "example.unknowntld"),  # PSL default rule "*"
]
NONE_CASES = [
    "blogspot.com",
    "github.io",
    "com",
    "co.uk",
    "b.ck",
    "uk",
    "COM.",
    "localhost",
    "xn--mnchen-3ya",
]
INVALID_CASES = [
    "",
    "   ",
    ".",
    "a..com",
    "1.2.3.4",
    "[::1]",
    "xn--a.com",
    "a b.com",
    "x" * 2000,
    None,
    5,
]


@pytest.mark.parametrize(("name", "expected"), OK_CASES)
def test_organizational_domain(name: str, expected: str) -> None:
    assert organizational_domain(name) == expected


@pytest.mark.parametrize("name", NONE_CASES)
def test_no_organizational_domain(name: str) -> None:
    assert organizational_domain(name) is None
    assert is_subdomain_of_org(name) is False


@pytest.mark.parametrize("name", INVALID_CASES)
def test_invalid_input(name: object) -> None:
    with pytest.raises(InvalidDomainName):
        organizational_domain(name)
    with pytest.raises(InvalidDomainName):
        is_subdomain_of_org(name)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("example.com", False),
        ("www.example.com", True),
        ("EXAMPLE.com.", False),
        ("a.b.example.co.uk", True),
        ("com", False),
        ("www.ck", False),
        ("x.www.ck", True),
    ],
)
def test_is_subdomain_of_org(name: str, expected: bool) -> None:
    assert is_subdomain_of_org(name) is expected
