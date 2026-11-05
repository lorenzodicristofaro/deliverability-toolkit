"""Domain name validation at the edge (M1-18): user input -> normalised ASCII (A-label) name.

IDNA 2008 with UTS #46 mapping via the `idna` package (BSD-3-Clause), NOT the stdlib `idna` codec
(IDNA 2003). `idna.encode(name, uts46=True, std3_rules=True, transitional=False)`:
- UTS #46 mapping: case folding, full-width characters and ideographic dots are mapped;
- non-transitional processing: deviation characters such as "ß" are kept (IDNA 2008), not mapped
  to "ss" (IDNA 2003 behaviour);
- STD3 rules: only letters, digits and hyphen in the ASCII result (so no "_", "*", "/", spaces).

On top of that we reject, before IDNA runs: non-strings, over-long input, control characters
(incl. NUL), surrogates and any whitespace; and after it: IP addresses (v4/v6 in any form), names
with fewer than two labels or an all-numeric last label, and length violations (253 total / 63 per
label). One trailing dot is removed. No DNS lookup is done here.

`InvalidDomainName` carries a stable `reason` code for logs/tests; it never carries the input,
and the `idna` error message (which echoes the input) is not kept.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from typing import Final

import idna

MAX_DOMAIN_LENGTH: Final = 253
MAX_LABEL_LENGTH: Final = 63
# Upper bound on the raw input, checked before any processing (a U-label name can be longer than
# its A-label form, but never by this much).
MAX_INPUT_LENGTH: Final = 1024
# Control, surrogate, private-use and unassigned code points; format characters (Cf) are left to
# IDNA, which allows ZWJ/ZWNJ only in their CONTEXTJ contexts.
_REJECTED_CATEGORIES: Final = frozenset({"Cc", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"})


class InvalidDomainName(ValueError):
    """The input is not an acceptable domain name. `reason` is a stable code (no user input)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"invalid domain name: {reason}")
        self.reason = reason


def _reject_characters(value: str) -> None:
    for char in value:
        if char.isspace() or unicodedata.category(char) in _REJECTED_CATEGORIES:
            raise InvalidDomainName("forbidden_character")


def _is_ip_address(value: str) -> bool:
    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def to_ascii_domain(value: object) -> str:
    """Return the normalised ASCII form of `value` (lowercase A-labels, no trailing dot).

    Raises InvalidDomainName for anything that is not a valid multi-label host name."""
    if not isinstance(value, str):
        raise InvalidDomainName("not_a_string")
    if not value:
        raise InvalidDomainName("empty")
    if len(value) > MAX_INPUT_LENGTH:
        raise InvalidDomainName("too_long")
    _reject_characters(value)
    if _is_ip_address(value):
        raise InvalidDomainName("ip_address")
    try:
        encoded = idna.encode(value, uts46=True, std3_rules=True, transitional=False)
    except (idna.IDNAError, UnicodeError):
        raise InvalidDomainName("idna") from None
    name = encoded.decode("ascii").lower()
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > MAX_DOMAIN_LENGTH:
        raise InvalidDomainName("length")
    labels = name.split(".")
    if any(not label or len(label) > MAX_LABEL_LENGTH for label in labels):
        raise InvalidDomainName("label")
    if len(labels) < 2:
        raise InvalidDomainName("single_label")
    if labels[-1].isdigit() or _is_ip_address(name):
        raise InvalidDomainName("ip_address")
    return name


def to_display_name(ascii_name: str) -> str:
    """Unicode (U-label) form of a stored ASCII name for display; the input if it cannot be
    decoded (stored names are already validated, so this is a display-only fallback)."""
    try:
        return idna.decode(ascii_name)
    except (idna.IDNAError, UnicodeError):
        return ascii_name
