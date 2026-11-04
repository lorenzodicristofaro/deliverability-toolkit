"""DNSKEY key tag (RFC 4034 Appendix B) and a parser for root.key files. Pure, no network."""

from __future__ import annotations

import base64


def key_tag(flags: int, protocol: int, algorithm: int, public_key: bytes) -> int:
    """Key tag of a DNSKEY, RFC 4034 Appendix B (algorithm 1 / RSAMD5 is not supported)."""
    if algorithm == 1:
        raise ValueError("RSAMD5 key tags are computed differently and are not supported")
    rdata = flags.to_bytes(2, "big") + bytes([protocol, algorithm]) + public_key
    acc = 0
    for i, byte in enumerate(rdata):
        acc += byte << 8 if i % 2 == 0 else byte
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def root_key_tags(text: str) -> set[int]:
    """Key tags of all root DNSKEY records in a root.key file (plain or unbound autotrust format).

    Lines are ``. [ttl] IN DNSKEY flags protocol algorithm base64 [; comment]``. Comment lines and
    other record types are ignored; a malformed DNSKEY line raises ValueError.
    """
    tags: set[int] = set()
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if "DNSKEY" not in fields:
            continue
        rest = fields[fields.index("DNSKEY") + 1 :]
        if len(rest) < 4:
            raise ValueError(f"malformed DNSKEY line: {raw!r}")
        flags, protocol, algorithm = (int(x) for x in rest[:3])
        key = base64.b64decode("".join(rest[3:]), validate=True)
        tags.add(key_tag(flags, protocol, algorithm, key))
    return tags
