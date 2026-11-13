"""SPF recursive resolution engine (M3-07).

``resolve_spf(resolver, domain)`` fetches the SPF record of ``domain`` (via M3-03), follows
``include`` and ``redirect`` recursively and returns an :class:`SpfTree` with one
:class:`SpfNode` per visited record plus whole-tree counters. No findings, no i18n (M3-08).

Counting rules (RFC 7208 section 4.6.4):

- DNS-lookup-causing terms are ``include a mx ptr exists`` and the ``redirect`` modifier;
  ``all ip4 ip6`` and ``exp`` are not counted. The count spans the whole tree, so a domain
  included twice is counted twice (as a receiver evaluating the record would). Only
  syntactically valid terms are counted; a ``redirect`` is ignored (not counted, not followed)
  when the record has an ``all`` mechanism (section 6.1). Mechanisms after the first ``all``
  of a record are neither counted nor followed (section 5.1: ``all`` always matches, so they
  are never tested); they are still parsed, so a syntax error among them still makes the
  record a permerror (section 4.6). An ``all`` inside an included record stops only that
  record's terms. Terms before the first ``all`` follow the worst-case convention above.
- Void lookups are terms whose query is answered NXDOMAIN or NODATA: the TXT query of an
  ``include`` or ``redirect`` target, the MX query of ``mx``, the A query of ``exists`` and
  the A query of ``a``. For ``a`` this models the dominant IPv4 receiver (which asks A only);
  the AAAA state is queried and recorded on the term for diagnostics but does not decide
  voidness. A failure on either query is an error, never void. An ``include`` target that
  answers TXT records none of which is SPF is NOT void (RCODE 0 with answers) but is still
  recorded as ``no_record`` (section 5.2: permerror).
- Syntax errors (section 4.6: check_host() returns permerror as soon as the record has a
  syntax error anywhere): a record that is not ``is_valid`` is kept on the node with its
  issues and ``syntax_error=True``; none of its terms are counted or followed.
- ``mx``: the number of MX hosts is the number of address lookups the term needs; it is
  exposed per term and compared against :data:`MX_ADDRESS_LIMIT`. MX host addresses are not
  resolved. ``ptr`` and terms with macros cannot be resolved without a sender context: they
  are counted but not queried (``resolved=False``).

Failure handling: any query that ends in a failure state (servfail, timeout, blocked, ...)
marks the node/term with that :class:`ResultState` and the tree ``evaluated=False``. A
failure is never counted as void and never treated as "no record".

Bounds: depth (:data:`MAX_DEPTH`), nodes (:data:`MAX_NODES`) and distinct queries
(:data:`MAX_QUERIES`) are capped; hitting a cap stops descent and sets ``truncated``. Every
(name, type) is queried at most once per run (memo). A domain already on the current path is
not fetched again: the node is marked ``loop=True``.

Truncation keeps ``evaluated=True``: no cap can be reached with 10 lookups or fewer (depth 13
needs 13 include/redirect terms, 100 fetched nodes need 99, and each lookup term causes at most
two queries, so 250 queries need over 100 terms). A truncated tree has therefore already
exceeded :data:`LOOKUP_LIMIT` and its ``lookup_count`` is a lower bound.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from app.checks.dnsutil import classify
from app.core.domain_names import MAX_DOMAIN_LENGTH, MAX_LABEL_LENGTH, to_dns_name
from app.dns.types import DnsQuestion, Resolver, ResultState
from app.parsers.spf import SpfRecord, SpfTerm, is_spf_record, parse_spf

# RFC 7208 section 4.6.4 limits (the only place these numbers live).
LOOKUP_LIMIT = 10
VOID_LOOKUP_LIMIT = 2
MX_ADDRESS_LIMIT = 10

# Resource bounds against hostile records.
MAX_DEPTH = 12
MAX_NODES = 100
MAX_QUERIES = 250

LOOKUP_TERMS: frozenset[str] = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})

NodeVia = Literal["root", "include", "redirect"]


@dataclass(frozen=True, slots=True)
class TermLookup:
    """One DNS-lookup-causing term of a node, in record order.

    ``target`` is the normalised domain queried (None when unresolvable). ``states`` maps the
    queried rdtype to its outcome. ``resolved`` is False for ``ptr``, macro targets, invalid
    targets and terms skipped by a cap. ``error`` is the first failure state, if any.
    """

    term: SpfTerm
    target: str | None
    resolved: bool
    states: tuple[tuple[str, ResultState], ...] = ()
    void: bool = False
    error: ResultState | None = None
    invalid_target: bool = False
    mx_hosts: int | None = None  # mx only: address lookups this term needs
    child: SpfNode | None = None  # include / redirect only

    @property
    def mx_limit_exceeded(self) -> bool:
        return self.mx_hosts is not None and self.mx_hosts > MX_ADDRESS_LIMIT


@dataclass(frozen=True, slots=True)
class SpfNode:
    """One record in the tree. ``records`` holds every SPF record at the name (more than one
    means ``multiple_records``); ``record`` is the parsed record when there is exactly one."""

    domain: str
    via: NodeVia
    depth: int
    dns_state: ResultState | None = None  # None when not queried (loop / truncated)
    records: tuple[str, ...] = ()
    record: SpfRecord | None = None
    lookups: tuple[TermLookup, ...] = ()
    no_record: bool = False
    multiple_records: bool = False
    loop: bool = False
    truncated: bool = False
    syntax_error: bool = False  # record kept with its issues; terms not counted or followed

    @property
    def terms(self) -> tuple[SpfTerm, ...]:
        return self.record.terms if self.record is not None else ()

    @property
    def error(self) -> ResultState | None:
        """The DNS failure state of this node's TXT query, None when it completed."""
        if self.dns_state is not None and self.dns_state.is_failure:
            return self.dns_state
        return None

    @property
    def children(self) -> tuple[SpfNode, ...]:
        return tuple(lk.child for lk in self.lookups if lk.child is not None)

    @property
    def missing_target(self) -> bool:
        """An include/redirect target without an SPF record (RFC 7208 5.2 / 6.1: permerror).
        Distinct from a DNS failure, which sets ``error`` instead."""
        return self.via != "root" and self.no_record


@dataclass(frozen=True, slots=True)
class SpfTree:
    """Whole-tree result. ``truncated`` means a resource cap stopped resolution; that is only
    reachable after more than :data:`LOOKUP_LIMIT` lookup terms, so ``lookup_count`` is then a
    lower bound and the limit is already exceeded. ``evaluated`` stays True in that case."""

    domain: str
    root: SpfNode
    lookup_count: int
    void_count: int
    mx_address_lookups: tuple[tuple[str, int], ...]  # (mx term target, host count) per mx
    evaluated: bool
    truncated: bool
    errors: tuple[tuple[str, str, ResultState], ...]  # (name, rdtype, state)
    query_count: int

    @property
    def lookup_limit_exceeded(self) -> bool:
        return self.lookup_count > LOOKUP_LIMIT

    @property
    def void_limit_exceeded(self) -> bool:
        return self.void_count > VOID_LOOKUP_LIMIT

    @property
    def mx_limit_exceeded(self) -> bool:
        return any(n > MX_ADDRESS_LIMIT for _, n in self.mx_address_lookups)

    @property
    def has_loop(self) -> bool:
        return any(n.loop for n in self.nodes())

    def nodes(self) -> tuple[SpfNode, ...]:
        """All nodes, depth-first pre-order."""
        out: list[SpfNode] = []
        stack = [self.root]
        while stack:
            node = stack.pop()
            out.append(node)
            stack.extend(reversed(node.children))
        return tuple(out)


@dataclass(slots=True)
class _Txt:
    state: ResultState
    records: tuple[str, ...]


@dataclass(slots=True)
class _Run:
    resolver: Resolver
    memo_txt: dict[str, _Txt] = field(default_factory=dict)
    memo_other: dict[tuple[str, str], tuple[ResultState, tuple[str, ...]]] = field(
        default_factory=dict
    )
    queries: int = 0
    nodes: int = 0
    lookup_count: int = 0
    void_count: int = 0
    mx: list[tuple[str, int]] = field(default_factory=list)
    errors: list[tuple[str, str, ResultState]] = field(default_factory=list)
    truncated: bool = False

    def _budget(self) -> bool:
        if self.queries >= MAX_QUERIES:
            self.truncated = True
            return False
        self.queries += 1
        return True

    def _fail(self, name: str, rdtype: str, state: ResultState) -> None:
        if state.is_failure:
            self.errors.append((name, rdtype, state))

    async def txt(self, name: str) -> _Txt | None:
        hit = self.memo_txt.get(name)
        if hit is not None:
            if hit.state.is_failure:
                self._fail(name, "TXT", hit.state)
            return hit
        if not self._budget():
            return None
        # `name` is already normalised (root: to_dns_name; targets: _spf_target), so the
        # question is built directly: fetch_txt would re-apply the stricter host-name rule.
        result = await self.resolver.resolve(DnsQuestion(name, "TXT"))
        state, evaluated, texts, _ = classify(result, "TXT")
        state = state if evaluated else _failure(state)
        out = _Txt(state, tuple(texts) if evaluated else ())
        self.memo_txt[name] = out
        self._fail(name, "TXT", state)
        return out

    async def query(self, name: str, rdtype: str) -> tuple[ResultState, tuple[str, ...]] | None:
        key = (name, rdtype)
        hit = self.memo_other.get(key)
        if hit is None:
            if not self._budget():
                return None
            result = await self.resolver.resolve(DnsQuestion(name, rdtype))
            state = result.state
            texts = tuple(r.rdata_text for r in result.records if r.rdtype == rdtype)
            if state.is_ok and not texts:
                state = ResultState.error  # "ok" without the asked type is not an answer
            hit = (state, texts if state.is_ok else ())
            self.memo_other[key] = hit
        self._fail(name, rdtype, hit[0])
        return hit


def _failure(state: ResultState) -> ResultState:
    """dnsutil reports not-evaluated outcomes with their state; keep it a failure state."""
    return state if state.is_failure else ResultState.error


async def resolve_spf(resolver: Resolver, domain: str) -> SpfTree:
    """Resolve the SPF tree of ``domain``. Raises ``InvalidDomainName`` for an invalid root
    name (a caller bug); every DNS outcome is reported in the tree instead."""
    root_name = to_dns_name(domain)
    run = _Run(resolver)
    root = await _node(run, root_name, "root", 0, ())
    return SpfTree(
        domain=root_name,
        root=root,
        lookup_count=run.lookup_count,
        void_count=run.void_count,
        mx_address_lookups=tuple(run.mx),
        evaluated=not run.errors,
        truncated=run.truncated,
        errors=tuple(run.errors),
        query_count=run.queries,
    )


async def _node(run: _Run, name: str, via: NodeVia, depth: int, path: tuple[str, ...]) -> SpfNode:
    if name in path:
        return SpfNode(domain=name, via=via, depth=depth, loop=True)
    if depth > MAX_DEPTH or run.nodes >= MAX_NODES:
        run.truncated = True
        return SpfNode(domain=name, via=via, depth=depth, truncated=True)
    fetched = await run.txt(name)
    if fetched is None:
        return SpfNode(domain=name, via=via, depth=depth, truncated=True)
    run.nodes += 1
    if fetched.state.is_failure:
        return SpfNode(domain=name, via=via, depth=depth, dns_state=fetched.state)
    spf = tuple(r for r in fetched.records if is_spf_record(r))
    if not spf:
        return SpfNode(domain=name, via=via, depth=depth, dns_state=fetched.state, no_record=True)
    if len(spf) > 1:
        # RFC 7208 4.5: permerror; no single record to evaluate, so nothing is followed.
        return SpfNode(
            domain=name,
            via=via,
            depth=depth,
            dns_state=fetched.state,
            records=spf,
            multiple_records=True,
        )
    record = parse_spf(spf[0])
    if not record.is_valid:
        # RFC 7208 4.6: permerror at parse time; nothing in the record is evaluated.
        return SpfNode(
            domain=name,
            via=via,
            depth=depth,
            dns_state=fetched.state,
            records=spf,
            record=record,
            syntax_error=True,
        )
    lookups = await _lookups(run, name, record, depth, (*path, name))
    return SpfNode(
        domain=name,
        via=via,
        depth=depth,
        dns_state=fetched.state,
        records=spf,
        record=record,
        lookups=lookups,
    )


async def _lookups(
    run: _Run, name: str, record: SpfRecord, depth: int, path: tuple[str, ...]
) -> tuple[TermLookup, ...]:
    has_all = any(t.name == "all" for t in record.mechanisms)
    out: list[TermLookup] = []
    for term in record.terms:
        if _is_all(term):
            # RFC 7208 5.1: all always matches, so later mechanisms are never tested. The only
            # lookup modifier, redirect, is ignored anyway when an all is present (6.1).
            break
        if term.kind == "invalid" or not term.valid or term.name not in LOOKUP_TERMS:
            continue
        if term.kind == "modifier" and (term.name != "redirect" or has_all):
            continue
        run.lookup_count += 1
        out.append(await _term(run, name, term, depth, path))
    return tuple(out)


def _is_all(term: SpfTerm) -> bool:
    return term.kind == "mechanism" and term.name == "all" and term.valid


def mechanisms_after_all(record: SpfRecord) -> tuple[SpfTerm, ...]:
    """Mechanisms after the first valid ``all``: never tested by a receiver (RFC 7208 5.1)."""
    mechanisms = record.mechanisms
    first = next((i for i, t in enumerate(mechanisms) if _is_all(t)), None)
    return () if first is None else mechanisms[first + 1 :]


def _spf_label_ok(label: str) -> bool:
    return 0 < len(label) <= MAX_LABEL_LENGTH and all(
        "\x21" <= c <= "\x7e" and c != "\\" for c in label
    )


def _spf_target(raw: str) -> str | None:
    """Normalised query name of a macro-free SPF ``domain-spec``, or None if it cannot be queried.

    The parser has already checked the grammar (visible ASCII, a valid toplabel); this adds
    what DNS needs: lowercase, one trailing dot removed, at most 253 octets, labels of 1-63
    octets, and no backslash (``dns.name.from_text`` would treat it as an escape)."""
    if not raw.isascii():  # before lower(): e.g. U+212A KELVIN SIGN lowercases to ASCII "k"
        return None
    name = raw.lower()
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > MAX_DOMAIN_LENGTH:
        return None
    labels = name.split(".")
    if len(labels) < 2 or not all(_spf_label_ok(label) for label in labels):
        return None
    return name


async def _term(
    run: _Run, name: str, term: SpfTerm, depth: int, path: tuple[str, ...]
) -> TermLookup:
    if term.name == "ptr" or term.has_macro:
        return TermLookup(term=term, target=None, resolved=False)
    raw = term.value if term.value is not None else name
    target = _spf_target(raw)
    if target is None:
        return TermLookup(term=term, target=None, resolved=False, invalid_target=True)

    if term.name in ("include", "redirect"):
        via: NodeVia = "include" if term.name == "include" else "redirect"
        child = await _node(run, target, via, depth + 1, path)
        void = child.dns_state in _ABSENT
        if void:
            run.void_count += 1
        states: tuple[tuple[str, ResultState], ...] = (
            (("TXT", child.dns_state),) if child.dns_state is not None else ()
        )
        return TermLookup(
            term=term,
            target=target,
            resolved=child.dns_state is not None,
            states=states,
            void=void,
            error=child.error,
            child=child,
        )

    rdtypes = {"a": ("A", "AAAA"), "mx": ("MX",), "exists": ("A",)}[term.name]
    answers: list[tuple[str, ResultState, tuple[str, ...]]] = []
    for rdtype in rdtypes:
        got = await run.query(target, rdtype)
        if got is None:
            return TermLookup(term=term, target=target, resolved=False)
        answers.append((rdtype, got[0], got[1]))
    addr_states = tuple((rt, st) for rt, st, _ in answers)
    error = next((st for _, st, _ in answers if st.is_failure), None)
    # Voidness is decided by the first rdtype (A for ``a``/``exists``, MX for ``mx``).
    void = error is None and answers[0][1] in _ABSENT
    if void:
        run.void_count += 1
    mx_hosts: int | None = None
    if term.name == "mx" and error is None:
        mx_hosts = _mx_host_count(answers[0][2])
        run.mx.append((target, mx_hosts))
    return TermLookup(
        term=term,
        target=target,
        resolved=True,
        states=addr_states,
        void=void,
        error=error,
        mx_hosts=mx_hosts,
    )


_ABSENT = (ResultState.nxdomain, ResultState.nodata)


def _mx_host_count(rdata: tuple[str, ...]) -> int:
    """Distinct exchange names, excluding the null MX target "." (RFC 7505)."""
    hosts: set[str] = set()
    for text in rdata:
        parts = text.split()
        host = parts[-1].lower().rstrip(".") if parts else ""
        if host:
            hosts.add(host)
    return len(hosts)
