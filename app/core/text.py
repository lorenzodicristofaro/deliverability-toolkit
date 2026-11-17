"""Small text helpers shared by the web layer and services (no web or I/O imports)."""

from __future__ import annotations

import unicodedata
from typing import Final

_CONTROL: Final = frozenset({"Cc", "Cs", "Cf", "Co", "Cn", "Zl", "Zp"})


def visible(value: object) -> str:
    """`value` with control/format/unassigned characters replaced by visible escapes."""
    out: list[str] = []
    for ch in str(value):
        if unicodedata.category(ch) in _CONTROL:
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)
