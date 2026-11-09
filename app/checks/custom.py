"""Declarative custom DNS checks (M5-22). Definitions are validated by
`app.core.custom_check_schema`; this module only evaluates them.

Nothing stored is trusted: `run` revalidates the kind, definition, severity and remediation and
recompiles any regex through `compile_checked`, on every run. An invalid stored definition is
`error`.

Status rules:
- `error` (could not evaluate; never `ok`, never a claim that the record is absent): any DNS state
  other than ok/nxdomain/nodata, an "ok" with no record of the asked type, a regex timeout or any
  incomplete regex result, a non-numeric value on a range, an invalid definition, a name that
  cannot be built (too long included), too many records to evaluate.
- Missing record (DNS answered definitively): `CUSTOM_CHECK_FAILED` with the configured severity
  on all three kinds, `reason` being `nxdomain` or `nodata`. For `dns_matches` and
  `dns_value_range` the requirement is unmet because there is no record to satisfy it; it is not
  `no_match`/`out_of_range`, and not `error` since the lookup succeeded.

Matched text: `DnsRecord.rdata_text`, one per record. For TXT that is the character-strings of one
record concatenated with no separator (`join_txt_strings`), never merged across records.

Multiple records:
- `dns_matches`: `ok` if at least one record matches; `CUSTOM_CHECK_FAILED` (`no_match`) if none
  does. Every record is searched and any incomplete search makes the result `error`, even when
  another record matched, so the verdict does not depend on record order.
- `dns_value_range`: every value must be numeric, otherwise `error`; `ok` only if all are in
  [min, max], otherwise `CUSTOM_CHECK_FAILED` (`out_of_range`).

`Finding.remediation_key` is always None: the remediation is the plain text of the definition, in
`params["remediation_text"]` ({en, it}), and renderers escape it. A global row carrying only a
`remediation_key` produces a finding without remediation text.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from app.checks.dnsutil import _classify
from app.checks.models import CheckContext, CheckResult, Finding, Target, finding
from app.core.custom_check_schema import (
    DefinitionInvalid,
    KindUnavailable,
    NameRenderError,
    ParsedDefinition,
    parse_definition,
    render_name,
    validate_remediation_text,
    validate_severity,
)
from app.core.safe_regex import MAX_MATCHES, CompiledRule, search_all
from app.dns.types import DnsQuestion

CODES: tuple[str, ...] = (
    "CUSTOM_CHECK_FAILED",
    "CUSTOM_CHECK_ERROR",
    "CUSTOM_KIND_UNAVAILABLE",
)

MAX_RECORDS: Final = 16
MAX_EVIDENCE_ITEMS: Final = 5
MAX_EVIDENCE_CHARS: Final = 256
MATCH_TIMEOUT_S: Final = 1.0
_NUMBER: Final = re.compile(r"[+-]?[0-9]{1,30}(\.[0-9]{1,30})?")
_CHECK_KEY: Final = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")


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
        scope: str = "tenant",
    ) -> None:
        valid_key = isinstance(check_key, str) and _CHECK_KEY.fullmatch(check_key)
        self._key = check_key if valid_key else "invalid"
        self.id = f"custom:{self._key}"
        self._kind = kind
        self._definition = definition
        self._severity = severity
        self._remediation_text = remediation_text
        self._remediation_key = remediation_key
        self._scope = scope

    def _error(self, reason: str, **data: Any) -> _Outcome:
        params = {"check_key": self._key, "reason": reason}
        found = finding("CUSTOM_CHECK_ERROR", "low", params, remediation=False)
        return _Outcome([found], False, {"reason": reason, **data})

    def _remediation(self) -> dict[str, str] | None:
        if self._remediation_key is not None:
            if self._scope != "global":
                raise DefinitionInvalid("remediation_key", "global_only")
            if self._remediation_text is not None:
                raise DefinitionInvalid("remediation", "both")
            return None
        return validate_remediation_text(self._remediation_text)

    async def _evaluate(self, ctx: CheckContext, target: Target) -> _Outcome:
        try:
            parsed = parse_definition(self._kind, self._definition)
            severity = validate_severity(self._severity)
            remediation = self._remediation()
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

        result = await ctx.resolver.resolve(DnsQuestion(name, parsed.rrtype))
        state, evaluated, records, _ttl = _classify(result, parsed.rrtype)
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
                if not await _any_match(parsed, records):
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


async def _search(rule: CompiledRule, text: str) -> bool:
    # search_all blocks on a worker subprocess; keep the event loop free.
    result = await asyncio.to_thread(
        search_all, rule, text, timeout_s=MATCH_TIMEOUT_S, max_matches=MAX_MATCHES
    )
    if result.timed_out:
        raise _CannotEvaluate("regex_timeout")
    if not result.complete:
        raise _CannotEvaluate("regex_failed")
    return bool(result.matches)


async def _any_match(parsed: ParsedDefinition, records: Sequence[str]) -> bool:
    assert parsed.rule is not None
    matched = False
    for text in records:  # no early exit: an incomplete search is `error` in any record order
        matched = await _search(parsed.rule, text) or matched
    return matched


def _number_of(text: str) -> float:
    candidate = text.strip(" \t")
    if not _NUMBER.fullmatch(candidate):
        raise _CannotEvaluate("non_numeric")
    return float(candidate)


def _all_in_range(parsed: ParsedDefinition, records: Sequence[str]) -> bool:
    assert parsed.minimum is not None and parsed.maximum is not None
    # Parse every value first: a non-numeric one is `error` even if another is out of range.
    values = [_number_of(text) for text in records]
    return all(parsed.minimum <= v <= parsed.maximum for v in values)
