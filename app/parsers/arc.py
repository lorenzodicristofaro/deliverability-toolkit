"""ARC chain parser and structural validation (RFC 8617).

Pure and offline: no DNS, no network, no filesystem, no database. **No signature is
verified.** ARC-Seal and ARC-Message-Signature need the sealer's public key from DNS to be
checked, which this module never fetches. Every :class:`ArcChain` therefore has
``verified=None`` and ``crypto_checked=False``: ``structurally_valid`` only means the header
fields are well formed and numbered as RFC 8617 section 5.1.1 requires, NOT that the chain
is authentic. Anyone can write a structurally valid ARC chain.

``parse_arc_chain`` reads the ``ARC-Seal`` (AS), ``ARC-Message-Signature`` (AMS) and
``ARC-Authentication-Results`` (AAR) fields of a :class:`~app.parsers.message.HeaderBlock`;
``parse_arc_values`` takes ``(name, value)`` pairs in header order (topmost first).

Header parsing:

- AS and AMS use the DKIM tag-list grammar (RFC 6376 section 3.2, reused by RFC 8617
  sections 4.1.2 and 4.1.3): ``tag=value`` separated by ``;``, folding whitespace around
  names and values, tag names case-sensitive, unknown tags ignored, a duplicate tag is an
  error (the first one is kept). Parsed tags: ``i a b bh d s cv t h c``. The values of
  ``b=`` and ``bh=`` are never retained: only their presence and their length with
  whitespace removed (so folding inside them is tolerated). For the same reason no raw
  header text is kept.
- Required tags: AS ``i a b cv d s``; AMS ``i a b bh d h s`` (RFC 8617 4.1.2/4.1.3).
  ``h=`` on an AS is ``seal_h_tag`` (error) and makes the chain ``cv_fail`` (RFC 8617
  4.1.3: "MUST result in a cv status of 'fail'"). ``bh=`` on an AS and ``cv=`` on an AMS
  are ``unexpected_tag`` warnings.
- ``a=`` and ``cv=`` are compared case-insensitively and reported in lowercase. An ``a=``
  outside :data:`KNOWN_ALGORITHMS` is kept and flagged (``unknown_algorithm``, warning).
- ``t=`` must be 1-12 digits (RFC 6376 3.5); anything else, or a value datetime cannot
  hold, gives ``timestamp=None`` and an ``invalid_timestamp`` warning.
- The AAR is ``i=<n>; <authres-payload>`` (RFC 8617 4.1.1). The payload is parsed with
  :func:`app.parsers.authres.parse_authentication_results`; its issue positions are
  offsets inside the payload, which starts after the first ``;``.
- ``i=`` is ``1*2DIGIT`` with value 1..:data:`MAX_INSTANCES` (RFC 8617 3.9), so ``05`` is
  accepted; ``0``, ``-1``, ``abc`` or ``001`` give ``invalid_instance`` and values above 50
  ``instance_too_high``. Such a field
  is kept in :attr:`ArcChain.signatures` / :attr:`ArcChain.results` but is not grouped.
- A field over :data:`MAX_ARC_HEADER_LENGTH` (``header_too_large``) or with a NUL
  (``nul_byte``) is not parsed at all. Retained scalar tag values over
  :data:`MAX_TAG_VALUE` are dropped (``tag_too_long``).

Chain validation (RFC 8617 section 5.1.1, structure only): instances start at 1 and are
contiguous (``instance_gap``), each instance has exactly one AS, AMS and AAR
(``duplicate_instance``, ``missing_member``), at most 50 instances, ``cv=none`` at i=1
(``cv_not_none_at_first``) and ``cv=pass`` above it (``cv_none_after_first``). Status:

- ``none``: no ARC field at all;
- ``cv_fail``: an ARC-Seal with a valid instance says ``cv=fail`` (the chain was declared
  failed by a sealer) or carries ``h=``; this wins over ``invalid``. A seal whose ``i=`` is
  invalid is not counted, so it cannot mask an ``invalid`` chain;
- ``invalid``: any ``error`` issue on a field or on the chain;
- ``structurally_valid``: otherwise. Still not verified (see above).

Issues are :class:`~app.parsers.spf.ParseIssue` with a stable code and an empty or constant
``term`` (header content is never echoed). Field issue positions are character offsets in
the field value; chain issue positions are the field's ``position`` (byte offset in the
message, 0 for :func:`parse_arc_values`). Issues are capped at :data:`MAX_ISSUES` per list.
At most :data:`MAX_ARC_FIELDS` ARC fields are read (``truncated``). Every scan advances on
each step and is linear in the input size; no regular expression is used.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from app.parsers.authres import AuthResHeader, AuthResParseError, parse_authentication_results
from app.parsers.message import HeaderBlock
from app.parsers.spf import IssueSeverity, ParseIssue

AS_NAME = "ARC-Seal"
AMS_NAME = "ARC-Message-Signature"
AAR_NAME = "ARC-Authentication-Results"

MAX_INSTANCES = 50  # RFC 8617 section 4.2.1
MAX_ARC_HEADER_LENGTH = 8 * 1024
MAX_TAG_VALUE = 512
MAX_ARC_FIELDS = 3 * MAX_INSTANCES + 50
MAX_ISSUES = 200
MAX_TIMESTAMP_DIGITS = 12  # RFC 6376 section 3.5

# Field-level issue codes.
HEADER_TOO_LARGE = "header_too_large"
NUL_BYTE = "nul_byte"
INVALID_TAG = "invalid_tag"
INVALID_TAG_NAME = "invalid_tag_name"
INVALID_TAG_VALUE = "invalid_tag_value"
EMPTY_TAG = "empty_tag"
EMPTY_TAG_VALUE = "empty_tag_value"
DUPLICATE_TAG = "duplicate_tag"
MISSING_TAG = "missing_tag"
UNEXPECTED_TAG = "unexpected_tag"
TAG_TOO_LONG = "tag_too_long"
MISSING_INSTANCE = "missing_instance"
INVALID_INSTANCE = "invalid_instance"
INSTANCE_TOO_HIGH = "instance_too_high"
MISSING_CV = "missing_cv"
INVALID_CV = "invalid_cv"
UNKNOWN_ALGORITHM = "unknown_algorithm"
INVALID_TIMESTAMP = "invalid_timestamp"
INVALID_AAR = "invalid_aar"
INVALID_AUTHRES = "invalid_authres"
TOO_MANY_ISSUES = "too_many_issues"

# Chain-level issue codes.
DUPLICATE_INSTANCE = "duplicate_instance"
MISSING_MEMBER = "missing_member"
INSTANCE_GAP = "instance_gap"
UNGROUPED_FIELD = "ungrouped_field"
CV_FAIL = "cv_fail"
SEAL_H_TAG = "seal_h_tag"
CV_NOT_NONE_AT_FIRST = "cv_not_none_at_first"
CV_NONE_AFTER_FIRST = "cv_none_after_first"
TOO_MANY_FIELDS = "too_many_fields"

CV_VALUES: frozenset[str] = frozenset({"none", "pass", "fail"})  # RFC 8617 section 4.1.3
# RFC 8617 takes a= from RFC 6376 section 3.5 (rsa-sha256); RFC 8463 (Standards Track)
# adds ed25519-sha256 to DKIM. Sources: rfc-editor.org RFC 8617, 6376, 8463; verified
# 2026-11-07. An unlisted value is kept and only flagged.
KNOWN_ALGORITHMS: frozenset[str] = frozenset({"rsa-sha256", "ed25519-sha256"})

ArcStatus = Literal["none", "structurally_valid", "invalid", "cv_fail"]
SignatureKind = Literal["seal", "message_signature"]

_FWS = frozenset(" \t\r\n")
_DIGITS = frozenset("0123456789")
_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_NAME_CHARS = _ALPHA | _DIGITS | frozenset("_")
# RFC 6376 tval: %x21-3A / %x3C-7E (VCHAR without ";").
_TVAL = frozenset(chr(c) for c in range(0x21, 0x7F)) - {";"}

# AS tags are only i, a, b, d, s, t, cv (RFC 8617 section 4.1.3: h= is NOT allowed and
# MUST result in cv=fail; there is no bh). AMS is DKIM-Signature syntax with i= as the
# instance (section 4.1.2); cv is defined only for the AS. Sources: rfc-editor.org
# RFC 8617; verified 2026-11-07.
_REQUIRED: dict[SignatureKind, tuple[str, ...]] = {
    "seal": ("i", "a", "b", "cv", "d", "s"),
    "message_signature": ("i", "a", "b", "bh", "d", "h", "s"),
}
_UNEXPECTED: dict[SignatureKind, frozenset[str]] = {
    "seal": frozenset({"bh"}),
    "message_signature": frozenset({"cv"}),
}
_PARSED_TAGS = frozenset({"i", "a", "b", "bh", "d", "s", "cv", "t", "h", "c"})
_OPAQUE_TAGS = frozenset({"b", "bh", "h"})  # not subject to MAX_TAG_VALUE


@dataclass(frozen=True, slots=True)
class ArcSignature:
    """One parsed ARC-Seal (``kind="seal"``) or ARC-Message-Signature.

    Fields that do not apply to the kind, or whose tag is missing or invalid, are None (or
    empty). ``b=``/``bh=`` values are not retained, only presence and length. ``position``
    is the field's byte offset in the message and ``index`` its order among ARC fields.
    """

    kind: SignatureKind
    instance: int | None
    algorithm: str | None
    unknown_algorithm: bool
    domain: str | None
    selector: str | None
    cv: str | None
    timestamp: datetime | None
    canonicalization: str | None
    signed_headers: tuple[str, ...]
    has_signature: bool
    signature_length: int
    has_body_hash: bool
    body_hash_length: int
    position: int
    index: int
    issues: tuple[ParseIssue, ...]


@dataclass(frozen=True, slots=True)
class ArcAuthenticationResults:
    """One ARC-Authentication-Results field; ``results`` is the parsed authres payload."""

    instance: int | None
    results: AuthResHeader | None
    position: int
    index: int
    issues: tuple[ParseIssue, ...]


@dataclass(frozen=True, slots=True)
class ArcSet:
    """The AS, AMS and AAR of one instance (first of each when duplicated)."""

    instance: int
    seal: ArcSignature | None
    message_signature: ArcSignature | None
    authentication_results: ArcAuthenticationResults | None

    @property
    def domain(self) -> str | None:
        """Sealer domain: ``d=`` of the ARC-Seal."""
        return self.seal.domain if self.seal else None

    @property
    def selector(self) -> str | None:
        return self.seal.selector if self.seal else None

    @property
    def cv(self) -> str | None:
        return self.seal.cv if self.seal else None

    @property
    def timestamp(self) -> datetime | None:
        return self.seal.timestamp if self.seal else None

    @property
    def results(self) -> AuthResHeader | None:
        """Authentication state recorded by this hop (the AAR payload)."""
        aar = self.authentication_results
        return aar.results if aar else None


@dataclass(frozen=True, slots=True)
class ArcChain:
    """Structural view of an ARC chain. NOT cryptographically verified (module docstring).

    ``sets`` holds valid instances in ascending order. ``signatures`` and ``results`` hold
    every parsed field in header order, including duplicates and ungroupable ones.
    """

    status: ArcStatus
    sets: tuple[ArcSet, ...]
    signatures: tuple[ArcSignature, ...]
    results: tuple[ArcAuthenticationResults, ...]
    issues: tuple[ParseIssue, ...]
    field_count: int
    truncated: bool
    verified: bool | None = None
    crypto_checked: bool = False

    @property
    def instance_count(self) -> int:
        return len(self.sets)

    @property
    def highest(self) -> ArcSet | None:
        """The set with the highest instance number (the newest hop), or None."""
        return self.sets[-1] if self.sets else None


class _Issues:
    """Local capped issue list (authres keeps its own private equivalent)."""

    def __init__(self) -> None:
        self.items: list[ParseIssue] = []
        self._full = False

    def add(
        self, code: str, position: int, severity: IssueSeverity = "error", term: str = ""
    ) -> None:
        if self._full:
            return
        if len(self.items) >= MAX_ISSUES:
            self.items.append(ParseIssue(TOO_MANY_ISSUES, "", position, "warning"))
            self._full = True
            return
        self.items.append(ParseIssue(code, term, position, severity))

    @property
    def has_error(self) -> bool:
        return any(i.severity == "error" for i in self.items)


@dataclass(frozen=True, slots=True)
class _Tag:
    value: str
    position: int


def _strip_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """Shrink ``[start, end)`` past FWS on both sides. Each step moves a bound."""
    while start < end and text[start] in _FWS:
        start += 1
    while end > start and text[end - 1] in _FWS:
        end -= 1
    return start, end


def _parse_tag_list(value: str, issues: _Issues) -> dict[str, _Tag]:
    """RFC 6376 section 3.2 tag-list. Returns first occurrence of each well-formed tag."""
    tags: dict[str, _Tag] = {}
    n = len(value)
    start = 0
    while start <= n:
        semi = value.find(";", start)
        end = n if semi < 0 else semi
        s, e = _strip_bounds(value, start, end)
        if s == e:
            if semi >= 0:
                issues.add(EMPTY_TAG, start, "warning")
        else:
            _parse_tag_spec(value, s, e, tags, issues)
        if semi < 0:
            break
        start = semi + 1  # strictly greater than the previous start
    return tags


def _parse_tag_spec(value: str, s: int, e: int, tags: dict[str, _Tag], issues: _Issues) -> None:
    eq = value.find("=", s, e)
    if eq < 0:
        issues.add(INVALID_TAG, s)
        return
    ns, ne = _strip_bounds(value, s, eq)
    name = value[ns:ne]
    if not name or name[0] not in _ALPHA or any(c not in _NAME_CHARS for c in name):
        issues.add(INVALID_TAG_NAME, s)
        return
    vs, ve = _strip_bounds(value, eq + 1, e)
    if name not in _PARSED_TAGS:
        return  # unknown tags MUST be ignored (RFC 6376 section 3.2)
    if name in tags:
        issues.add(DUPLICATE_TAG, s, term=name)
        return
    if any(c not in _TVAL and c not in _FWS for c in value[vs:ve]):
        issues.add(INVALID_TAG_VALUE, vs, term=name)
        return
    if vs == ve:
        issues.add(EMPTY_TAG_VALUE, vs, term=name)
        return
    if name not in _OPAQUE_TAGS and ve - vs > MAX_TAG_VALUE:
        issues.add(TAG_TOO_LONG, vs, term=name)
        return
    tags[name] = _Tag(value[vs:ve], vs)


def _parse_instance(tag: _Tag | None, issues: _Issues) -> int | None:
    if tag is None:
        issues.add(MISSING_INSTANCE, 0)
        return None
    text = tag.value
    if not text or any(c not in _DIGITS for c in text):
        issues.add(INVALID_INSTANCE, tag.position)
        return None
    significant = text.lstrip("0")
    if not significant:
        issues.add(INVALID_INSTANCE, tag.position)
        return None
    if len(significant) > 2 or int(significant) > MAX_INSTANCES:
        issues.add(INSTANCE_TOO_HIGH, tag.position)
        return None
    if len(text) > 2:  # RFC 8617 section 3.9: position = 1*2DIGIT (e.g. "001")
        issues.add(INVALID_INSTANCE, tag.position)
        return None
    return int(significant)


def _parse_timestamp(tag: _Tag | None, issues: _Issues) -> datetime | None:
    if tag is None:
        return None
    text = tag.value
    if not text or len(text) > MAX_TIMESTAMP_DIGITS or any(c not in _DIGITS for c in text):
        issues.add(INVALID_TIMESTAMP, tag.position, "warning")
        return None
    try:
        return datetime.fromtimestamp(int(text), UTC)
    except (OverflowError, OSError, ValueError):
        issues.add(INVALID_TIMESTAMP, tag.position, "warning")
        return None


def _opaque_length(tag: _Tag | None) -> int:
    if tag is None:
        return 0
    return sum(1 for c in tag.value if c not in _FWS)


def _precheck(value: str, issues: _Issues) -> bool:
    if len(value) > MAX_ARC_HEADER_LENGTH:
        issues.add(HEADER_TOO_LARGE, 0)
        return False
    nul = value.find("\x00")
    if nul >= 0:
        issues.add(NUL_BYTE, nul)
        return False
    return True


def _empty_signature(
    kind: SignatureKind, position: int, index: int, issues: _Issues
) -> ArcSignature:
    return ArcSignature(
        kind=kind,
        instance=None,
        algorithm=None,
        unknown_algorithm=False,
        domain=None,
        selector=None,
        cv=None,
        timestamp=None,
        canonicalization=None,
        signed_headers=(),
        has_signature=False,
        signature_length=0,
        has_body_hash=False,
        body_hash_length=0,
        position=position,
        index=index,
        issues=tuple(issues.items),
    )


def _parse_signature(kind: SignatureKind, value: str, position: int, index: int) -> ArcSignature:
    issues = _Issues()
    if not _precheck(value, issues):
        return _empty_signature(kind, position, index, issues)
    tags = _parse_tag_list(value, issues)
    instance = _parse_instance(tags.get("i"), issues)
    for name in _REQUIRED[kind]:
        if name not in tags and name != "i":
            issues.add(MISSING_CV if name == "cv" else MISSING_TAG, len(value), term=name)
    for name in sorted(_UNEXPECTED[kind] & tags.keys()):
        issues.add(UNEXPECTED_TAG, tags[name].position, "warning", term=name)
    if kind == "seal" and "h" in tags:
        issues.add(SEAL_H_TAG, tags["h"].position, term="h")

    algorithm: str | None = None
    unknown_algorithm = False
    if "a" in tags:
        algorithm = tags["a"].value.lower()
        if algorithm not in KNOWN_ALGORITHMS:
            unknown_algorithm = True
            issues.add(UNKNOWN_ALGORITHM, tags["a"].position, "warning")

    cv: str | None = None
    if kind == "seal" and "cv" in tags:
        candidate = tags["cv"].value.lower()
        if candidate in CV_VALUES:
            cv = candidate
        else:
            issues.add(INVALID_CV, tags["cv"].position)

    signed: tuple[str, ...] = ()
    if kind == "message_signature" and "h" in tags:
        names: list[str] = []
        for part in tags["h"].value.split(":"):
            ps, pe = _strip_bounds(part, 0, len(part))
            if ps < pe:
                names.append(part[ps:pe].lower())
        signed = tuple(names)

    def scalar(name: str) -> str | None:
        tag = tags.get(name)
        return tag.value if tag else None

    return ArcSignature(
        kind=kind,
        instance=instance,
        algorithm=algorithm,
        unknown_algorithm=unknown_algorithm,
        domain=scalar("d"),
        selector=scalar("s"),
        cv=cv,
        timestamp=_parse_timestamp(tags.get("t"), issues),
        canonicalization=scalar("c") if kind == "message_signature" else None,
        signed_headers=signed,
        has_signature="b" in tags,
        signature_length=_opaque_length(tags.get("b")),
        has_body_hash="bh" in tags,
        body_hash_length=_opaque_length(tags.get("bh")),
        position=position,
        index=index,
        issues=tuple(issues.items),
    )


def _parse_aar(value: str, position: int, index: int) -> ArcAuthenticationResults:
    issues = _Issues()
    if not _precheck(value, issues):
        return ArcAuthenticationResults(None, None, position, index, tuple(issues.items))
    semi = value.find(";")
    if semi < 0:
        issues.add(INVALID_AAR, len(value))
        return ArcAuthenticationResults(None, None, position, index, tuple(issues.items))
    tags = _parse_tag_list(value[:semi], issues)
    if tags.keys() - {"i"}:
        issues.add(INVALID_AAR, 0)
    instance = _parse_instance(tags.get("i"), issues)
    results: AuthResHeader | None = None
    try:
        results = parse_authentication_results(value[semi + 1 :], position=position, index=index)
    except AuthResParseError:
        issues.add(INVALID_AUTHRES, semi + 1)
    return ArcAuthenticationResults(instance, results, position, index, tuple(issues.items))


def _build_chain(fields: Iterable[tuple[str, str, int]]) -> ArcChain:
    signatures: list[ArcSignature] = []
    aars: list[ArcAuthenticationResults] = []
    chain = _Issues()
    count = 0
    truncated = False
    for name, value, position in fields:
        lowered = name.lower()
        if lowered not in _LOWER_NAMES:
            continue
        if count >= MAX_ARC_FIELDS:
            truncated = True
            chain.add(TOO_MANY_FIELDS, position)
            break
        if lowered == _LOWER_NAMES[0]:
            signatures.append(_parse_signature("seal", value, position, count))
        elif lowered == _LOWER_NAMES[1]:
            signatures.append(_parse_signature("message_signature", value, position, count))
        else:
            aars.append(_parse_aar(value, position, count))
        count += 1

    if count == 0:
        return ArcChain("none", (), (), (), tuple(chain.items), 0, truncated)

    seals: dict[int, ArcSignature] = {}
    amss: dict[int, ArcSignature] = {}
    results: dict[int, ArcAuthenticationResults] = {}
    field_error = False
    cv_fail = False
    for sig in signatures:
        field_error = field_error or any(i.severity == "error" for i in sig.issues)
        # Only seals with a valid instance count, so an ungroupable seal cannot turn an
        # invalid chain into cv_fail.
        declares_fail = sig.cv == "fail" or any(i.code == SEAL_H_TAG for i in sig.issues)
        if sig.kind == "seal" and sig.instance is not None and declares_fail:
            cv_fail = True
        target = seals if sig.kind == "seal" else amss
        label = AS_NAME if sig.kind == "seal" else AMS_NAME
        _group(sig.instance, sig, target, label, chain, sig.position)
    for aar in aars:
        field_error = field_error or any(i.severity == "error" for i in aar.issues)
        _group(aar.instance, aar, results, AAR_NAME, chain, aar.position)

    instances = sorted(seals.keys() | amss.keys() | results.keys())
    highest = instances[-1] if instances else 0
    present = set(instances)
    for k in range(1, highest + 1):
        if k not in present:
            chain.add(INSTANCE_GAP, 0, term=str(k))

    sets: list[ArcSet] = []
    for k in instances:
        arc_set = ArcSet(k, seals.get(k), amss.get(k), results.get(k))
        for member, label in (
            (arc_set.seal, AS_NAME),
            (arc_set.message_signature, AMS_NAME),
            (arc_set.authentication_results, AAR_NAME),
        ):
            if member is None:
                chain.add(MISSING_MEMBER, 0, term=label)
        seal = arc_set.seal
        if seal is not None and seal.cv is not None:
            if k == 1 and seal.cv != "none":
                chain.add(CV_NOT_NONE_AT_FIRST, seal.position)
            elif k > 1 and seal.cv == "none":
                chain.add(CV_NONE_AFTER_FIRST, seal.position)
        sets.append(arc_set)

    if cv_fail:
        chain.add(CV_FAIL, 0)
        status: ArcStatus = "cv_fail"
    elif field_error or chain.has_error:
        status = "invalid"
    else:
        status = "structurally_valid"
    return ArcChain(
        status=status,
        sets=tuple(sets),
        signatures=tuple(signatures),
        results=tuple(aars),
        issues=tuple(chain.items),
        field_count=count,
        truncated=truncated,
    )


_LOWER_NAMES = (AS_NAME.lower(), AMS_NAME.lower(), AAR_NAME.lower())


def _group[T](
    instance: int | None,
    item: T,
    target: dict[int, T],
    label: str,
    chain: _Issues,
    position: int = 0,
) -> None:
    if instance is None:
        chain.add(UNGROUPED_FIELD, position, term=label)
    elif instance in target:
        chain.add(DUPLICATE_INSTANCE, position, term=label)
    else:
        target[instance] = item


def parse_arc_values(fields: Sequence[tuple[str, str]]) -> ArcChain:
    """Parse ``(name, value)`` pairs in header order (topmost first). Non-ARC names are
    ignored. Positions are 0. See the module docstring; nothing is verified."""
    if isinstance(fields, str):
        raise TypeError("fields must be a sequence of (name, value) pairs")
    return _build_chain((name, value, 0) for name, value in fields)


def parse_arc_chain(block: HeaderBlock) -> ArcChain:
    """Parse the ARC fields of ``block`` (unfolded raw values). Nothing is verified."""
    return _build_chain((f.name, f.raw_value, f.position) for f in block.fields)
