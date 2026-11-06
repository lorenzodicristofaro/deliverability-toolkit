"""DKIM key record parser (RFC 6376 sections 3.2 and 3.6.1, RFC 8463 for ed25519).

Pure syntax and key decoding: no DNS, no network, no selector probing, no findings (M3-13).

``parse_dkim_key`` never raises on bad input. It returns a :class:`DkimKey` with the parsed
tags, the decoded key metadata and a list of :class:`~app.parsers.spf.ParseIssue`.
``severity="error"`` means a verifier could not use the record (invalid tag-list, record
discarded, unusable key), ``"warning"`` means the record is usable but something in it is
ignored by verifiers (unknown tags, hash algorithms, service types or flags).

Grammar notes (RFC 6376):

- Section 3.2: tag names are case-sensitive, ``ALPHA *(ALPHA / DIGIT / "_")``; values are
  visible ASCII except ``;`` with folding whitespace around them; a duplicated tag makes the
  whole tag-list invalid; unknown tags are ignored.
- Section 3.6.1: ``v=`` must be ``DKIM1`` and the first tag when present; ``k=`` defaults to
  ``rsa``; ``p=`` is required and an empty value means the key is revoked; ``s=`` defaults
  to ``*``; ``t=`` flags ``y`` (testing) and ``s`` (strict i=/d=); unknown ``h``/``k``/``s``/
  ``t`` values are ignored by verifiers.
- Section 2.10: base64 values may contain folding whitespace, so it is removed from ``p=``.
- ``k=rsa``: section 3.6.1 names an ``RSAPublicKey``; deployed keys are almost always a
  ``SubjectPublicKeyInfo`` (rsaEncryption). Both forms are accepted.
- ``k=ed25519`` (RFC 8463 section 4.2): ``p=`` is the base64 Ed25519 public key, 44 base64
  characters, i.e. the bare 32-byte key.

Resource bounds: the record is cut at :data:`MAX_RECORD_LENGTH` characters and
:data:`MAX_TAGS` tags; the decoded key is limited to :data:`MAX_DER_LENGTH` bytes and the
DER reader to :data:`MAX_DER_DEPTH` nesting levels. All scans are linear.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass
from typing import Literal

from app.parsers.spf import ParseIssue

MAX_RECORD_LENGTH = 4096
MAX_TAGS = 64
MAX_DER_LENGTH = 2048
MAX_DER_DEPTH = 4
ED25519_KEY_LENGTH = 32

KeyFormat = Literal["spki", "rsa_public_key", "raw"]

KNOWN_TAGS: frozenset[str] = frozenset({"v", "h", "k", "n", "p", "s", "t"})
KNOWN_KEY_TYPES: frozenset[str] = frozenset({"rsa", "ed25519"})
KNOWN_HASH_ALGORITHMS: frozenset[str] = frozenset({"sha1", "sha256"})
KNOWN_SERVICE_TYPES: frozenset[str] = frozenset({"*", "email"})
KNOWN_FLAGS: frozenset[str] = frozenset({"y", "s"})

# Issue codes (stable, lowercase).
EMPTY_RECORD = "empty_record"
RECORD_TOO_LONG = "record_too_long"
TOO_MANY_TAGS = "too_many_tags"
NON_ASCII = "non_ascii"
CONTROL_CHARACTER = "control_character"
EMPTY_TAG = "empty_tag"
INVALID_TAG = "invalid_tag"
INVALID_TAG_NAME = "invalid_tag_name"
DUPLICATE_TAG = "duplicate_tag"
UNKNOWN_TAG = "unknown_tag"
BAD_VERSION = "bad_version"
VERSION_NOT_FIRST = "version_not_first"
BAD_TAG_VALUE = "bad_tag_value"
UNKNOWN_KEY_TYPE = "unknown_key_type"
UNKNOWN_HASH_ALGORITHM = "unknown_hash_algorithm"
UNKNOWN_SERVICE_TYPE = "unknown_service_type"
SERVICE_EXCLUDES_EMAIL = "service_excludes_email"
UNKNOWN_FLAG = "unknown_flag"
MISSING_P_TAG = "missing_key"
BAD_BASE64 = "bad_base64"
KEY_TOO_LARGE = "key_too_large"
BAD_DER = "bad_der"
WRONG_KEY_ALGORITHM = "wrong_key_algorithm"
KEY_TYPE_MISMATCH = "key_type_mismatch"
BAD_KEY_LENGTH = "bad_key_length"
PARSE_FAILED = "parse_failed"

_FWS = " \t\r\n"
_ASCII_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_NAME_CHARS = _ASCII_ALPHA | frozenset("0123456789_")
_BASE64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

# DER tags and object identifiers (content octets).
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_OID_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1
_OID_ED25519 = bytes.fromhex("2b6570")  # 1.3.101.112 (RFC 8410)


@dataclass(frozen=True, slots=True)
class DkimTag:
    """One ``name=value`` tag. ``value`` has surrounding whitespace removed."""

    name: str
    value: str
    position: int


@dataclass(frozen=True, slots=True)
class DkimKey:
    raw: str
    tags: tuple[DkimTag, ...]
    issues: tuple[ParseIssue, ...]
    version: str | None = None
    key_type: str = "rsa"  # k= as written, "rsa" when absent
    public_key: str | None = None  # p= with whitespace removed; None when absent
    revoked: bool = False
    key_format: KeyFormat | None = None
    bits: int | None = None
    hash_algorithms: tuple[str, ...] | None = None  # None: h= absent (all allowed)
    service_types: tuple[str, ...] = ("*",)
    flags: tuple[str, ...] = ()
    notes: str | None = None
    unknown_tags: tuple[str, ...] = ()
    truncated: bool = False

    @property
    def testing(self) -> bool:
        """``t=y``: the domain is testing DKIM."""
        return "y" in self.flags

    @property
    def strict_identity(self) -> bool:
        """``t=s``: the i= domain must equal d= (no subdomains)."""
        return "s" in self.flags

    @property
    def is_valid(self) -> bool:
        """True when no ``error`` issue was found."""
        return not any(i.severity == "error" for i in self.issues)

    def issue_codes(self) -> tuple[str, ...]:
        return tuple(i.code for i in self.issues)


class _DerError(Exception):
    """Internal: malformed DER. Never escapes this module."""


def parse_dkim_key(text: str) -> DkimKey:
    """Parse a DKIM key TXT record (strings already concatenated). Never raises."""
    try:
        return _parse(text)
    except Exception:  # pragma: no cover - defensive: the contract is "never raises"
        raw = text if isinstance(text, str) else ""
        return DkimKey(raw=raw, tags=(), issues=(ParseIssue(PARSE_FAILED, "", 0),))


def _parse(text: str) -> DkimKey:
    if not isinstance(text, str):
        return DkimKey(raw="", tags=(), issues=(ParseIssue(EMPTY_RECORD, "", 0),))
    issues: list[ParseIssue] = []
    raw = text
    truncated = False
    if len(text) > MAX_RECORD_LENGTH:
        text = text[:MAX_RECORD_LENGTH]
        truncated = True
        issues.append(ParseIssue(RECORD_TOO_LONG, "", MAX_RECORD_LENGTH))

    _check_chars(text, issues)
    if not text.strip(_FWS):
        issues.append(ParseIssue(EMPTY_RECORD, "", 0))
        return DkimKey(raw=raw, tags=(), issues=tuple(issues), truncated=truncated)

    tags, cut = _split_tags(text, issues)
    truncated = truncated or cut

    by_name: dict[str, DkimTag] = {}
    unknown: list[str] = []
    for index, tag in enumerate(tags):
        if tag.name in by_name:
            issues.append(ParseIssue(DUPLICATE_TAG, tag.name, tag.position))
            continue
        by_name[tag.name] = tag
        if tag.name == "v" and index != 0:
            issues.append(ParseIssue(VERSION_NOT_FIRST, tag.name, tag.position))
        if tag.name not in KNOWN_TAGS:
            unknown.append(tag.name)
            issues.append(ParseIssue(UNKNOWN_TAG, tag.name, tag.position, "warning"))

    version: str | None = None
    if (v := by_name.get("v")) is not None:
        version = v.value
        if v.value != "DKIM1":
            issues.append(ParseIssue(BAD_VERSION, v.value, v.position))

    key_type = "rsa"
    if (k := by_name.get("k")) is not None:
        key_type = k.value
        if k.value not in KNOWN_KEY_TYPES:
            issues.append(ParseIssue(UNKNOWN_KEY_TYPE, k.value, k.position))

    hash_algorithms: tuple[str, ...] | None = None
    if (h := by_name.get("h")) is not None:
        hash_algorithms = _colon_list(h, KNOWN_HASH_ALGORITHMS, UNKNOWN_HASH_ALGORITHM, issues)

    service_types: tuple[str, ...] = ("*",)
    if (s := by_name.get("s")) is not None:
        service_types = _colon_list(s, KNOWN_SERVICE_TYPES, UNKNOWN_SERVICE_TYPE, issues)
        if service_types and not any(x in ("*", "email") for x in service_types):
            issues.append(ParseIssue(SERVICE_EXCLUDES_EMAIL, s.value, s.position))

    flags: tuple[str, ...] = ()
    if (t := by_name.get("t")) is not None:
        flags = _colon_list(t, KNOWN_FLAGS, UNKNOWN_FLAG, issues)

    notes = n.value if (n := by_name.get("n")) is not None else None

    public_key: str | None = None
    revoked = False
    key_format: KeyFormat | None = None
    bits: int | None = None
    p = by_name.get("p")
    if p is None:
        issues.append(ParseIssue(MISSING_P_TAG, "", 0))
    else:
        public_key = "".join(c for c in p.value if c not in _FWS)
        if not public_key:
            revoked = True
        else:
            key_format, bits = _decode_key(public_key, key_type, p.position, issues)

    return DkimKey(
        raw=raw,
        tags=tuple(tags),
        issues=tuple(issues),
        version=version,
        key_type=key_type,
        public_key=public_key,
        revoked=revoked,
        key_format=key_format,
        bits=bits,
        hash_algorithms=hash_algorithms,
        service_types=service_types,
        flags=flags,
        notes=notes,
        unknown_tags=tuple(unknown),
        truncated=truncated,
    )


def _check_chars(text: str, issues: list[ParseIssue]) -> None:
    """Flag non-ASCII and control characters (FWS characters are allowed) once each."""
    seen: set[str] = set()
    for i, ch in enumerate(text):
        o = ord(ch)
        if 0x20 <= o <= 0x7E or ch in _FWS:
            continue
        code = NON_ASCII if o > 0x7F else CONTROL_CHARACTER
        if code not in seen:
            seen.add(code)
            issues.append(ParseIssue(code, "", i))


def _split_tags(text: str, issues: list[ParseIssue]) -> tuple[list[DkimTag], bool]:
    """Split ``tag-spec *(";" tag-spec) [";"]`` in one linear pass."""
    tags: list[DkimTag] = []
    start = 0
    length = len(text)
    while start <= length:
        end = text.find(";", start)
        last = end == -1
        if last:
            end = length
        segment = text[start:end]
        stripped = segment.strip(_FWS)
        if not stripped:
            if not last:  # ";;" or a leading ";": tag-spec requires a tag-name
                issues.append(ParseIssue(EMPTY_TAG, "", start))
        else:
            if len(tags) == MAX_TAGS:
                issues.append(ParseIssue(TOO_MANY_TAGS, "", start))
                return tags, True
            pos = start + (len(segment) - len(segment.lstrip(_FWS)))
            tag = _parse_tag(stripped, pos, issues)
            if tag is not None:
                tags.append(tag)
        if last:
            break
        start = end + 1
    return tags, False


def _parse_tag(spec: str, pos: int, issues: list[ParseIssue]) -> DkimTag | None:
    eq = spec.find("=")
    if eq == -1:
        issues.append(ParseIssue(INVALID_TAG, spec[:64], pos))
        return None
    name = spec[:eq].rstrip(_FWS)
    if not name or name[0] not in _ASCII_ALPHA or any(c not in _NAME_CHARS for c in name):
        issues.append(ParseIssue(INVALID_TAG_NAME, name[:64], pos))
        return None
    value = spec[eq + 1 :].strip(_FWS)
    return DkimTag(name=name, value=value, position=pos)


def _colon_list(
    tag: DkimTag, known: frozenset[str], unknown_code: str, issues: list[ParseIssue]
) -> tuple[str, ...]:
    """Parse a ``x *([FWS] ":" [FWS] x)`` list; unknown items are warnings (ignored)."""
    items = tuple(item.strip(_FWS) for item in tag.value.split(":"))
    if any(not item for item in items):
        issues.append(ParseIssue(BAD_TAG_VALUE, tag.value[:64], tag.position))
        items = tuple(item for item in items if item)
    reported: set[str] = set()
    for item in items:
        if item not in known and item not in reported:
            reported.add(item)
            issues.append(ParseIssue(unknown_code, item[:64], tag.position, "warning"))
    return items


def _decode_key(
    b64: str, key_type: str, pos: int, issues: list[ParseIssue]
) -> tuple[KeyFormat | None, int | None]:
    """Decode ``p=`` and derive the key length. Issues are appended; never raises."""
    data = _b64decode(b64)
    if data is None:
        issues.append(ParseIssue(BAD_BASE64, "p", pos))
        return None, None
    if len(data) > MAX_DER_LENGTH:
        issues.append(ParseIssue(KEY_TOO_LARGE, "p", pos))
        return None, None
    if key_type not in KNOWN_KEY_TYPES:
        return None, None  # already reported as unknown_key_type; key length unknown

    if key_type == "ed25519":
        if len(data) == ED25519_KEY_LENGTH:
            return "raw", ED25519_KEY_LENGTH * 8
        try:
            algorithm, _ = _read_public_key(data)
        except _DerError:
            issues.append(ParseIssue(BAD_KEY_LENGTH, "p", pos))
            return None, None
        # An RSA key, or an Ed25519 key wrapped in SubjectPublicKeyInfo instead of the bare
        # 32-byte key RFC 8463 section 4.2 specifies.
        code = BAD_KEY_LENGTH if algorithm == "ed25519" else KEY_TYPE_MISMATCH
        issues.append(ParseIssue(code, algorithm, pos))
        return None, None

    try:
        algorithm, result = _read_public_key(data)
    except _DerError:
        code = KEY_TYPE_MISMATCH if len(data) == ED25519_KEY_LENGTH else BAD_DER
        issues.append(ParseIssue(code, "p", pos))
        return None, None
    if algorithm == "ed25519":
        issues.append(ParseIssue(KEY_TYPE_MISMATCH, algorithm, pos))
        return None, None
    if algorithm != "rsa" or result is None:
        issues.append(ParseIssue(WRONG_KEY_ALGORITHM, algorithm, pos))
        return None, None
    return result


def _b64decode(s: str) -> bytes | None:
    """Strict base64: alphabet only, at most two trailing ``=``, length multiple of 4."""
    body = s.rstrip("=")
    if len(s) - len(body) > 2 or len(s) % 4 or any(c not in _BASE64_CHARS for c in body):
        return None
    try:
        return binascii.a2b_base64(s.encode("ascii"), strict_mode=True)
    except (binascii.Error, ValueError):
        return None


# --- bounded DER reader ----------------------------------------------------------------


def _read_tlv(buf: bytes, pos: int, end: int, depth: int) -> tuple[int, int, int]:
    """Read one DER TLV in ``buf[pos:end]``. Returns (tag, content_start, content_end).

    Single-byte tags only, definite minimal lengths, content must fit in the parent.
    """
    if depth > MAX_DER_DEPTH:
        raise _DerError("nesting")
    if pos + 2 > end:
        raise _DerError("truncated")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise _DerError("high tag number")
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 2:  # indefinite, or longer than MAX_DER_LENGTH allows
            raise _DerError("length")
        if pos + count > end:
            raise _DerError("truncated")
        length = int.from_bytes(buf[pos : pos + count], "big")
        if length < 0x80 or buf[pos] == 0:
            raise _DerError("non-minimal length")
        pos += count
    if length > end - pos:
        raise _DerError("truncated")
    return tag, pos, pos + length


def _expect(buf: bytes, pos: int, end: int, tag: int, depth: int) -> tuple[int, int]:
    got, start, stop = _read_tlv(buf, pos, end, depth)
    if got != tag:
        raise _DerError("unexpected tag")
    return start, stop


def _read_public_key(data: bytes) -> tuple[str, tuple[KeyFormat, int] | None]:
    """Identify a DER public key. Returns (algorithm, (format, bits) for RSA).

    Accepts ``SubjectPublicKeyInfo`` and the bare ``RSAPublicKey`` (RFC 8017 A.1.1).
    Raises :class:`_DerError` on malformed input.
    """
    start, stop = _expect(data, 0, len(data), _TAG_SEQUENCE, 1)
    if stop != len(data):
        raise _DerError("trailing data")
    first_tag, _, _ = _read_tlv(data, start, stop, 2)
    if first_tag == _TAG_INTEGER:
        return "rsa", ("rsa_public_key", _rsa_modulus_bits(data, start, stop, 2))

    alg_start, alg_stop = _expect(data, start, stop, _TAG_SEQUENCE, 2)
    oid_start, oid_stop = _expect(data, alg_start, alg_stop, _TAG_OID, 3)
    oid = data[oid_start:oid_stop]
    if oid_stop != alg_stop:
        param_tag, param_start, param_stop = _read_tlv(data, oid_stop, alg_stop, 3)
        params_null = param_tag == _TAG_NULL and param_start == param_stop
        if param_stop != alg_stop:
            raise _DerError("trailing algorithm data")
    else:
        params_null = True  # parameters absent
    bit_start, bit_stop = _expect(data, alg_stop, stop, _TAG_BIT_STRING, 2)
    if bit_stop != stop:
        raise _DerError("trailing data")
    if bit_start == bit_stop or data[bit_start] != 0:
        raise _DerError("bit string padding")
    key_start = bit_start + 1

    if oid == _OID_ED25519:
        return "ed25519", None
    if oid != _OID_RSA_ENCRYPTION or not params_null:
        return _oid_text(oid), None
    inner_start, inner_stop = _expect(data, key_start, bit_stop, _TAG_SEQUENCE, 3)
    if inner_stop != bit_stop:
        raise _DerError("trailing key data")
    return "rsa", ("spki", _rsa_modulus_bits(data, inner_start, inner_stop, 4))


def _rsa_modulus_bits(data: bytes, start: int, stop: int, depth: int) -> int:
    """``RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`` body."""
    n_start, n_stop = _expect(data, start, stop, _TAG_INTEGER, depth)
    e_start, e_stop = _expect(data, n_stop, stop, _TAG_INTEGER, depth)
    if e_stop != stop:
        raise _DerError("trailing data")
    modulus = _positive_integer(data[n_start:n_stop])
    exponent = _positive_integer(data[e_start:e_stop])
    if modulus < 3 or exponent < 3 or not modulus & 1:
        raise _DerError("implausible RSA key")
    return modulus.bit_length()


def _positive_integer(content: bytes) -> int:
    """Minimal two's-complement DER INTEGER that must be positive."""
    if not content or content[0] & 0x80:
        raise _DerError("empty or negative integer")
    if len(content) > 1 and content[0] == 0 and not content[1] & 0x80:
        raise _DerError("non-minimal integer")
    return int.from_bytes(content, "big")


def _oid_text(oid: bytes) -> str:
    """Dotted form of an OID for issue reporting (best effort, bounded)."""
    if not oid or oid[-1] & 0x80 or len(oid) > 32:
        return "unknown"
    arcs: list[int] = []
    value = 0
    for byte in oid:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first, *arcs[1:]])
