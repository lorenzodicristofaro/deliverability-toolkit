"""SPF check (M3-08): findings over the M3-07 resolution tree. RFC 7208 throughout.

Evaluation model:

- A DNS failure anywhere in the tree (``SpfTree.evaluated`` False) gives status ``error``
  (``evaluated=False``) with a single ``SPF_DNS_ERROR`` finding naming the first failed name
  and its :class:`ResultState`; never ``ok`` and never ``SPF_MISSING`` (section 4.4: a DNS
  error is temperror, not "none").
- "Policy" nodes are the root and the records reached from it via ``redirect`` (section 6.1:
  the redirect target's result becomes the result). The default result (``all`` mechanism,
  or its absence) is judged on them only, because an included record's ``-all``/``~all``/
  ``?all`` only makes the ``include`` not match (section 5.2 table).
- ``+all`` is reported on any node reached through ``redirect`` or ``+include`` terms only:
  a ``pass`` from such a record propagates as ``pass`` for every address (sections 5.1, 5.2).
- Permerror conditions (sections 4.5, 4.6, 4.6.4, 5.2, 6.1) are reported wherever they occur
  in the tree, because an included permerror propagates (section 5.2 table).

Flattening hints are advisory text only: no addresses are generated or claimed.
"""

from __future__ import annotations

import time
from typing import Any

from app.checks.models import CheckContext, CheckResult, Finding, Target, finding
from app.checks.spf_tree import (
    LOOKUP_LIMIT,
    VOID_LOOKUP_LIMIT,
    SpfNode,
    SpfTree,
    TermLookup,
    resolve_spf,
)
from app.core.domain_names import InvalidDomainName

CODES: tuple[str, ...] = (
    "SPF_MISSING",
    "SPF_MULTIPLE_RECORDS",
    "SPF_SYNTAX_ERROR",
    "SPF_TOO_MANY_LOOKUPS",
    "SPF_NEAR_LOOKUP_LIMIT",
    "SPF_TOO_MANY_VOID_LOOKUPS",
    "SPF_INCLUDE_LOOP",
    "SPF_INCLUDE_NOT_FOUND",
    "SPF_PLUS_ALL",
    "SPF_QUESTION_ALL",
    "SPF_NEUTRAL_ALL_SOFTFAIL",
    "SPF_NO_ALL",
    "SPF_REDIRECT_WITH_ALL",
    "SPF_PTR_DEPRECATED",
    "SPF_RECORD_TOO_LONG",
    "SPF_RESOLUTION_TRUNCATED",
    "SPF_FLATTENING_HINT",
    "SPF_DNS_ERROR",
)

# Lookup count from which SPF_NEAR_LOOKUP_LIMIT / SPF_FLATTENING_HINT are emitted (9 and 10
# are still within the RFC 7208 section 4.6.4 limit of LOOKUP_LIMIT).
NEAR_LOOKUP_THRESHOLD = 9
# RFC 1035 section 3.3 / RFC 7208 section 3.3: one TXT character-string holds at most 255
# octets; a longer record must be published as several strings.
TXT_STRING_MAX = 255
# RFC 7208 section 3.4: keep name + record text under 450 octets so the answer fits in a
# 512-octet UDP DNS message.
DNS_ANSWER_GUIDELINE = 450
UDP_MESSAGE_LIMIT = 512


class SpfCheck:
    id = "spf"

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        started = ctx.clock()
        t0 = time.monotonic()
        findings, evaluated, data = await self._evaluate(ctx, target)
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=findings,
            evaluated=evaluated,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
            data=data,
        )

    @staticmethod
    async def _evaluate(
        ctx: CheckContext, target: Target
    ) -> tuple[list[Finding], bool, dict[str, Any]]:
        try:
            tree = await resolve_spf(ctx.resolver, target.domain)
        except InvalidDomainName:
            params = {"name": target.domain, "rdtype": "TXT", "state": "invalid_name"}
            return [finding("SPF_DNS_ERROR", "medium", params)], False, {}
        data = _summary(tree)
        if not tree.evaluated:
            name, rdtype, state = tree.errors[0]
            evidence = [f"{n} {t}: {s}" for n, t, s in tree.errors]
            params = {"name": name, "rdtype": rdtype, "state": str(state)}
            return [finding("SPF_DNS_ERROR", "medium", params, evidence)], False, data
        return _findings(tree), True, data


def _findings(tree: SpfTree) -> list[Finding]:
    root = tree.root
    if root.no_record:
        return [finding("SPF_MISSING", "medium", {"domain": root.domain})]
    out: list[Finding] = []
    for node in tree.nodes():
        out.extend(_node_findings(node))
    out.extend(_all_findings(tree))
    out.extend(_limit_findings(tree))
    return out


def _node_findings(node: SpfNode) -> list[Finding]:
    """Per-record conditions, wherever the record sits in the tree."""
    out: list[Finding] = []
    name = {"name": node.domain}
    if node.multiple_records:
        out.append(
            finding(
                "SPF_MULTIPLE_RECORDS", "high", {**name, "count": len(node.records)}, node.records
            )
        )
    if node.loop:
        out.append(finding("SPF_INCLUDE_LOOP", "high", {**name, "via": node.via}))
    if node.missing_target:
        out.append(finding("SPF_INCLUDE_NOT_FOUND", "high", {**name, "via": node.via}))
    syntax: list[str] = []
    if node.syntax_error and node.record is not None:
        syntax = [
            f"{i.code}: {i.term}" if i.term else i.code
            for i in node.record.issues
            if i.severity == "error"
        ]
    syntax += [f"invalid_target: {lk.term.raw}" for lk in node.lookups if lk.invalid_target]
    if syntax:
        out.append(finding("SPF_SYNTAX_ERROR", "high", name, syntax))
    if node.record is not None and not node.syntax_error:
        ptr = [t.raw for t in node.record.mechanisms if t.name == "ptr" and t.valid]
        if ptr:
            out.append(finding("SPF_PTR_DEPRECATED", "low", name, ptr))
        if "redirect_with_all" in node.record.issue_codes():
            out.append(finding("SPF_REDIRECT_WITH_ALL", "low", name))
    out.extend(_length_findings(node))
    return out


def _length_findings(node: SpfNode) -> list[Finding]:
    if not node.records:
        return []
    longest = max(len(r.encode("utf-8", "surrogateescape")) for r in node.records)
    size = len(node.domain) + sum(len(r.encode("utf-8", "surrogateescape")) for r in node.records)
    if size > DNS_ANSWER_GUIDELINE:
        params = {"name": node.domain, "length": size, "limit": DNS_ANSWER_GUIDELINE}
        return [finding("SPF_RECORD_TOO_LONG", "medium", params)]
    if longest > TXT_STRING_MAX:
        params = {"name": node.domain, "length": longest, "limit": TXT_STRING_MAX}
        return [finding("SPF_RECORD_TOO_LONG", "info", params)]
    return []


def _first_all(node: SpfNode) -> str | None:
    """Qualifier of the first ``all`` mechanism (later mechanisms are never tested, 5.1)."""
    if node.record is None or node.syntax_error:
        return None
    for term in node.record.mechanisms:
        if term.name == "all" and term.valid:
            return term.qualifier or "+"
    return None


def _redirect_child(node: SpfNode) -> SpfNode | None:
    return next(
        (lk.child for lk in node.lookups if lk.term.name == "redirect" and lk.child is not None),
        None,
    )


def _all_findings(tree: SpfTree) -> list[Finding]:
    out: list[Finding] = []
    # +all on any record whose pass propagates to the root result.
    stack: list[SpfNode] = [tree.root]
    while stack:
        node = stack.pop()
        if _first_all(node) == "+":
            via = "root" if node is tree.root else node.via
            out.append(finding("SPF_PLUS_ALL", "critical", {"name": node.domain, "via": via}))
        for lk in node.lookups:
            if lk.child is not None and _propagates_pass(lk):
                stack.append(lk.child)
    # Default result of the policy chain (root, then redirect targets).
    policy: SpfNode | None = tree.root
    seen: set[int] = set()
    while policy is not None and id(policy) not in seen:
        seen.add(id(policy))
        if policy.record is None or policy.syntax_error:
            break
        qualifier = _first_all(policy)
        name = {"name": policy.domain}
        if qualifier == "?":
            out.append(finding("SPF_QUESTION_ALL", "medium", name))
        elif qualifier == "~":
            out.append(finding("SPF_NEUTRAL_ALL_SOFTFAIL", "info", name))
        if qualifier is not None:
            break
        if policy.record.redirect is None:
            # Section 4.7: no all and no redirect means an implicit ?all (neutral).
            out.append(finding("SPF_NO_ALL", "medium", name))
            break
        policy = _redirect_child(policy)  # None for a macro target: not judged
    return out


def _propagates_pass(lk: TermLookup) -> bool:
    if lk.term.name == "redirect":
        return True
    return lk.term.name == "include" and (lk.term.qualifier or "+") == "+"


def _limit_findings(tree: SpfTree) -> list[Finding]:
    out: list[Finding] = []
    count = tree.lookup_count
    params = {"count": count, "limit": LOOKUP_LIMIT}
    if tree.truncated or tree.lookup_limit_exceeded:
        out.append(finding("SPF_TOO_MANY_LOOKUPS", "high", params))
    elif count >= NEAR_LOOKUP_THRESHOLD:
        out.append(finding("SPF_NEAR_LOOKUP_LIMIT", "low", params))
    if tree.truncated:
        out.append(finding("SPF_RESOLUTION_TRUNCATED", "info", {"count": count}))
    if tree.void_limit_exceeded:
        voids = [lk.term.raw for n in tree.nodes() for lk in n.lookups if lk.void]
        out.append(
            finding(
                "SPF_TOO_MANY_VOID_LOOKUPS",
                "medium",
                {"count": tree.void_count, "limit": VOID_LOOKUP_LIMIT},
                voids,
            )
        )
    if tree.truncated or count >= NEAR_LOOKUP_THRESHOLD:
        ranked = _include_costs(tree.root)
        if ranked:
            evidence = [f"{raw}: {cost}" for raw, cost in ranked]
            out.append(finding("SPF_FLATTENING_HINT", "info", params, evidence))
    return out


def _subtree_lookups(node: SpfNode) -> int:
    """Lookup terms counted in ``node`` and below (iterative; trees can be deep)."""
    total = 0
    stack = [node]
    while stack:
        n = stack.pop()
        total += len(n.lookups)
        stack.extend(n.children)
    return total


def _include_costs(root: SpfNode) -> list[tuple[str, int]]:
    """include/redirect terms of the policy chain, ranked by the lookups they consume
    (the term itself plus everything below it). Ties keep record order."""
    costs: list[tuple[str, int]] = []
    node: SpfNode | None = root
    seen: set[int] = set()
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        for lk in node.lookups:
            if lk.term.name == "include":
                cost = 1 + (_subtree_lookups(lk.child) if lk.child is not None else 0)
                costs.append((lk.term.raw, cost))
        node = _redirect_child(node)
    return sorted(costs, key=lambda c: -c[1])


def _node_data(node: SpfNode) -> dict[str, Any]:
    return {
        "domain": node.domain,
        "via": node.via,
        "depth": node.depth,
        "state": str(node.dns_state) if node.dns_state is not None else None,
        "records": list(node.records),
        "lookups": [
            {
                "term": lk.term.raw,
                "target": lk.target,
                "void": lk.void,
                "error": str(lk.error) if lk.error is not None else None,
            }
            for lk in node.lookups
        ],
        "no_record": node.no_record,
        "multiple_records": node.multiple_records,
        "loop": node.loop,
        "truncated": node.truncated,
        "syntax_error": node.syntax_error,
    }


def _summary(tree: SpfTree) -> dict[str, Any]:
    root = tree.root
    return {
        "domain": tree.domain,
        "record": root.records[0] if len(root.records) == 1 else None,
        "lookup_count": tree.lookup_count,
        "lookup_limit": LOOKUP_LIMIT,
        "void_count": tree.void_count,
        "void_limit": VOID_LOOKUP_LIMIT,
        "truncated": tree.truncated,
        "errors": [{"name": n, "rdtype": t, "state": str(s)} for n, t, s in tree.errors],
        "nodes": [_node_data(n) for n in tree.nodes()],
    }
