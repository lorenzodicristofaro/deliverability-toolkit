"""Shared CLI text helper: escape what a terminal would interpret (no terminal injection)."""

from __future__ import annotations

import unicodedata
from typing import Final

_CONTROL: Final = frozenset({"Cc", "Cs", "Cf", "Co", "Cn", "Zl", "Zp"})


def visible(value: object) -> str:
    """Control, format and unassigned characters shown as escapes (no terminal injection)."""
    out: list[str] = []
    for ch in str(value):
        if unicodedata.category(ch) in _CONTROL:
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)
