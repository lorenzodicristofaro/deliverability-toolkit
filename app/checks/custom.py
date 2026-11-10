"""Declarative custom DNS checks (M5-22). Definitions are validated by
`app.core.custom_check_schema`; this module only evaluates them.

Nothing stored is trusted: `run` revalidates the kind, definition, severity and remediation and
recompiles any regex through `compile_checked`, on every run. An invalid stored definition is
`error`.

Status rules:
- `error` (could not evaluate; never `ok`, never a claim that the record is absent): any DNS state
  other than ok/nxdomain/nodata, an "ok" with no record of the asked type, a regex timeout or any
  incomplete regex result, the regex time budget running out, the run budget running out (below),
  a non-numeric value on a range, an invalid definition, a name that cannot be built (too long
  included), too many records to evaluate.
- Missing record (DNS answered definitively): `CUSTOM_CHECK_FAILED` with the configured severity
  on all three kinds, `reason` being `nxdomain` or `nodata`. For `dns_matches` and
  `dns_value_range` the requirement is unmet because there is no record to satisfy it; it is not
  `no_match`/`out_of_range`, and not `error` since the lookup succeeded.

Matched text: `DnsRecord.rdata_text`, one per record. For TXT that is the character-strings of one
record concatenated with no separator (`join_txt_strings`), never merged across records.

Multiple records:
- `dns_matches`: `ok` if at least one record matches; `CUSTOM_CHECK_FAILED` (`no_match`) if none
  does. Every record is searched and any incomplete search makes the result `error`, even when
  another record matched, so the verdict does not depend on record order. All the searches of one
  evaluation share MAX_REGEX_BUDGET_S (below the 15 s run deadline of `app.services.checks`);
  running out is `error` (`regex_budget_exceeded`), never a verdict from the records searched.
- `dns_value_range`: every value must be numeric, otherwise `error`; `ok` only if all are in
  [min, max], otherwise `CUSTOM_CHECK_FAILED` (`out_of_range`). The grammar is plain decimal
  notation (no exponent, NaN or Infinity, at most 30 digits on each side of the point) and the
  comparison is exact, in `Decimal`.

Remediation, on `CUSTOM_CHECK_FAILED` only: either the plain text of the definition, in
`params["remediation_text"]` ({en, it}), which renderers escape, with `Finding.remediation_key`
None; or, for a global row carrying only a `remediation_key`, that key in
`Finding.remediation_key`, rendered like any built-in remediation. The key must exist in every
catalogue (`validate_remediation_key`); a key that does not is an invalid definition (`error`), so
a failed finding never lacks its remediation.

Ids: `custom:<scope>:<check_key>`, so a global and a tenant check sharing a key never collide in
one run; an invalid key or scope reads `invalid`, never the stored value.

Run budget (M5-23): every custom check of one domain run shares one `RunBudget` of
RUN_BUDGET_S, started by the first custom check that runs and kept below the 15 s per-check
deadline of `app.services.checks`. A check that starts with no budget left is `error`
(`run_budget_exceeded`) without a DNS query; the DNS lookup is cut at the budget, an answer that
arrives past it gives no verdict, and the regex searches get at most what is left. So N custom
checks end within the budget plus scheduling overhead and their own `error`, instead of each one
racing the runner's deadline into `CHECK_TIMEOUT`; never `ok` once the budget is spent. A
`CustomDnsCheck` built without a budget (the admin dry run) gets its own.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Final

from app.checks.dnsutil import classify
from app.checks.models import CheckContext, CheckResult, Finding, Target, finding
from app.core.custom_check_schema import (
    DefinitionInvalid,
    KindUnavailable,
    NameRenderError,
    ParsedDefinition,
    parse_definition,
    render_name,
    validate_remediation_key,
    validate_remediation_text,
    validate_severity,
)
from app.core.safe_regex import MAX_MATCHES, CompiledRule, SearchFailure, search_many
from app.dns.types import DnsQuestion

CODES: tuple[str, ...] = (
    "CUSTOM_CHECK_FAILED",
    "CUSTOM_CHECK_ERROR",
    "CUSTOM_KIND_UNAVAILABLE",
)

MAX_RECORDS: Final = 64
MAX_EVIDENCE_ITEMS: Final = 5
MAX_EVIDENCE_CHARS: Final = 256
MATCH_TIMEOUT_S: Final = 1.0
MAX_REGEX_BUDGET_S: Final = 10.0  # all the regex searches of one evaluation
RUN_BUDGET_S: Final = 12.0  # every custom check of one domain run together
SCOPES: Final = ("global", "tenant")
_NUMBER: Final = re.compile(r"[+-]?[0-9]{1,30}(\.[0-9]{1,30})?")
_CHECK_KEY: Final = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_BUDGET_EXCEEDED: Final = "regex_budget_exceeded"
_RUN_BUDGET_EXCEEDED: Final = "run_budget_exceeded"
_regex_clock = time.monotonic


class RunBudget:
    """Time shared by the custom checks of one run. The clock starts at the first `remaining()`
    call, so building the checks (and any database work before the run) costs nothing."""

    def __init__(
        self, total_s: float = RUN_BUDGET_S, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._total = total_s
        self._clock = clock
        self._started: float | None = None

    def remaining(self) -> float:
        now = self._clock()
        if self._started is None:
            self._started = now
        return self._total - (now - self._started)


def _evidence(values: Iterable[str]) -> list[str]:
    """Bounded and printable: DNS text is decoded latin-1 and can hold anything."""
    out: list[str] = []
    for value in values:
        if len(out) == MAX_EVIDENCE_ITEMS:
            break
        out.append("".join(c if c.isprintable() else "?" for c in value[:MAX_EVIDENCE_CHARS]))
    return out


@dataclass(frozen=True, slots=True)
class _Outcome:
    findings: list[Finding]
    evaluated: bool
    data: dict[str, Any] = field(default_factory=dict)


class _CannotEvaluate(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class CustomDnsCheck:
    """One custom check. Built per run from a stored row or a dry-run definition."""

    def __init__(
        self,
        *,
        check_key: str,
        kind: object,
        definition: object,
        severity: object,
        remediation_text: object = None,
        remediation_key: object = None,
        scope: object = "tenant",
        budget: RunBudget | None = None,
        remediation_optional: bool = False,
    ) -> None:
        valid_key = isinstance(check_key, str) and _CHECK_KEY.fullmatch(check_key)
        self._key = check_key if valid_key else "invalid"
        self._scope = scope if isinstance(scope, str) and scope in SCOPES else "invalid"
        self.id = f"custom:{self._scope}:{self._key}"
        self._kind = kind
        self._definition = definition
        self._severity = severity
        self._remediation_text = remediation_text
        self._remediation_key = remediation_key
        self._budget = budget if budget is not None else RunBudget()
        # Dry run only: a definition being tried out needs no remediation yet.
        self._remediation_optional = remediation_optional

    def _error(self, reason: str, **data: Any) -> _Outcome:
        params = {"check_key": self._key, "reason": reason}
        found = finding("CUSTOM_CHECK_ERROR", "low", params, remediation=False)
        return _Outcome([found], False, {"reason": reason, **data})

    def _remediation(self) -> tuple[dict[str, str] | None, str | None]:
        """(text, key): exactly one is set, unless a dry run gave neither."""
        if self._remediation_key is not None:
            if self._scope != "global":
                raise DefinitionInvalid("remediation_key", "global_only")
            if self._remediation_text is not None:
                raise DefinitionInvalid("remediation", "both")
            return None, validate_remediation_key(self._remediation_key)
        text = self._remediation_text
        if text is None and self._remediation_optional:
            return None, None
        # A stored record carries a LocalizedText; checks do not import repositories.
        as_dict = getattr(text, "as_dict", None)
        return validate_remediation_text(as_dict() if callable(as_dict) else text), None

    async def _evaluate(self, ctx: CheckContext, target: Target) -> _Outcome:
        try:
            parsed = parse_definition(self._kind, self._definition)
            severity = validate_severity(self._severity)
            remediation, remediation_key = self._remediation()
        except KindUnavailable:
            params = {"check_key": self._key}
            found = finding("CUSTOM_KIND_UNAVAILABLE", "low", params, remediation=False)
            return _Outcome([found], False, {"reason": "kind_unavailable"})
        except DefinitionInvalid as exc:
            return self._error("invalid_definition", field=exc.field, detail=exc.reason)

        try:
            name = render_name(parsed.name_template, target.domain)
        except NameRenderError as exc:
            return self._error(exc.reason)

        remaining = self._budget.remaining()
        if remaining <= 0:
            return self._error(_RUN_BUDGET_EXCEEDED)
        try:
            async with asyncio.timeout(remaining):
                result = await ctx.resolver.resolve(DnsQuestion(name, parsed.rrtype))
        except TimeoutError:
            return self._error(_RUN_BUDGET_EXCEEDED, name=name, rrtype=parsed.rrtype)
        if self._budget.remaining() <= 0:  # an answer past the budget gives no verdict either
            return self._error(_RUN_BUDGET_EXCEEDED, name=name, rrtype=parsed.rrtype)
        state, evaluated, records, _ttl = classify(result, parsed.rrtype)
        data: dict[str, Any] = {
            "kind": parsed.kind,
            "name": name,
            "rrtype": parsed.rrtype,
            "state": str(state),
            "records": len(records),
        }

        def failed(reason: str, evidence: Iterable[str] = ()) -> _Outcome:
            params: dict[str, Any] = {
                "check_key": self._key,
                "name": name,
                "rrtype": parsed.rrtype,
                "reason": reason,
            }
            if remediation is not None:
                params["remediation_text"] = remediation
            found = finding(
                "CUSTOM_CHECK_FAILED", severity, params, _evidence(evidence), remediation=False
            )
            if remediation_key is not None:
                found = found.model_copy(update={"remediation_key": remediation_key})
            return _Outcome([found], True, {**data, "reason": reason})

        if not evaluated:
            return self._error(f"dns_{state}", **data)
        if state.is_definitive_absence:
            return failed(str(state))
        if parsed.kind == "dns_exists":
            return _Outcome([], True, data)
        if len(records) > MAX_RECORDS:
            return self._error("too_many_records", **data)
        try:
            if parsed.kind == "dns_matches":
                if not await _any_match(parsed, records, self._budget):
                    return failed("no_match", records)
            elif not _all_in_range(parsed, records):
                return failed("out_of_range", records)
        except _CannotEvaluate as exc:
            return self._error(exc.reason, **data)
        return _Outcome([], True, data)

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        started = ctx.clock()
        t0 = time.monotonic()
        try:
            outcome = await self._evaluate(ctx, target)
        except Exception:  # defensive: a custom check must never break the domain run
            outcome = self._error("internal_error")
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=outcome.findings,
            evaluated=outcome.evaluated,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
            data=outcome.data,
        )


async def _search(rule: CompiledRule, text: str, remaining: float) -> bool:
    # search_many blocks on a worker subprocess; keep the event loop free. Its total_timeout_s
    # bounds the slot wait, the worker start and the rule together.
    (result,) = await asyncio.to_thread(
        search_many,
        [rule],
        text,
        timeout_s=min(MATCH_TIMEOUT_S, remaining),
        max_matches=MAX_MATCHES,
        total_timeout_s=remaining,
    )
    if result.failure is SearchFailure.BATCH_DEADLINE:
        raise _CannotEvaluate(_BUDGET_EXCEEDED)
    if result.timed_out:
        raise _CannotEvaluate("regex_timeout")
    if not result.complete:
        raise _CannotEvaluate("regex_failed")
    return bool(result.matches)


async def _any_match(parsed: ParsedDefinition, records: Sequence[str], run: RunBudget) -> bool:
    assert parsed.rule is not None
    started = _regex_clock()

    def budget_left() -> float:
        run_left = run.remaining()
        if run_left <= 0:
            raise _CannotEvaluate(_RUN_BUDGET_EXCEEDED)
        remaining = MAX_REGEX_BUDGET_S - (_regex_clock() - started)
        if remaining <= 0:
            raise _CannotEvaluate(_BUDGET_EXCEEDED)
        return min(remaining, run_left)

    matched = False
    try:
        for text in records:  # no early exit: an incomplete search is `error` in any record order
            matched = await _search(parsed.rule, text, budget_left()) or matched
        budget_left()  # a last search that ended past the budget gives no verdict either
    except _CannotEvaluate as exc:
        # A search cut by the batch deadline: say which budget ran out.
        if exc.reason == _BUDGET_EXCEEDED and run.remaining() <= 0:
            raise _CannotEvaluate(_RUN_BUDGET_EXCEEDED) from None
        raise
    return matched


def _number_of(text: str) -> Decimal:
    candidate = text.strip(" \t")
    if not _NUMBER.fullmatch(candidate):
        raise _CannotEvaluate("non_numeric")
    return Decimal(candidate)  # exact: the context only applies to arithmetic


def _exact_bound(bound: int | float) -> Decimal:
    """The bound as written: `repr` of a float is its shortest round-trip text, so 0.1 is 0.1 and
    not its binary expansion."""
    return Decimal(bound) if isinstance(bound, int) else Decimal(repr(bound))


def _all_in_range(parsed: ParsedDefinition, records: Sequence[str]) -> bool:
    assert parsed.minimum is not None and parsed.maximum is not None
    # Parse every value first: a non-numeric one is `error` even if another is out of range.
    values = [_number_of(text) for text in records]
    minimum, maximum = _exact_bound(parsed.minimum), _exact_bound(parsed.maximum)
    return all(minimum <= v <= maximum for v in values)
