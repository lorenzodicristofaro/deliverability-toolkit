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

Remediation, on `CUSTOM_CHECK_FAILED` and the http_fetch mismatches only: either the plain
text of the definition, in `params["remediation_text"]` ({en, it}), which renderers escape, with
`Finding.remediation_key` None; or, for a global row carrying only a `remediation_key`, that key in
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

HTTP fetch (`http_fetch`, M7-02). The URL is built from the definition (`render_url`: scheme,
host under the target domain, path, no port) and re-parsed with the guarded client's policy
(`app.net.policy.parse_url`) before any request; a parsed URL whose scheme, host or text differs
is `error` (`url_mismatch`). The only I/O is `fetcher`, by default `app.net.guarded_http.fetch`
(GET, body truncated at the definition's `max_body_bytes`), called once per hop with
`follow_redirects=False`: redirects are followed here, at most `max_redirects` of the limits, and
every redirect target must be the target domain or a host under it (no IP literal) BEFORE it is
requested; any other target is `CUSTOM_HTTP_BLOCKED` (`redirect_off_domain`, `error`) and nothing
of the redirect (host, status, body, headers) is reported. https -> http is `scheme_not_allowed`,
a revisited URL or too many hops `too_many_redirects`, a missing or bad `Location`
`protocol_error`; each hop's request still goes through the client's full egress policy.
Limits are the caller's `fetch_limits` (the operator settings,
`limits_from_settings`) with the total deadline capped at what is left of the run budget; no
limits is `error` (`fetch_unconfigured`), never a fetch with defaults. Status rules:
- every client error is `error`, never `ok` and never a finding about the site:
  `blocked`/`scheme_not_allowed`/`port_not_allowed` -> `CUSTOM_HTTP_BLOCKED`, `too_large` ->
  `CUSTOM_HTTP_TOO_LARGE`, any other kind -> `CUSTOM_HTTP_UNREACHABLE`, `reason` being the kind;
  no budget left, or the fetch cut by the budget -> `CUSTOM_CHECK_ERROR` (`run_budget_exceeded`);
- a status outside `expected_status` -> `CUSTOM_HTTP_STATUS_MISMATCH` (body and header are not
  evaluated);
- `body_pattern` runs on the (possibly truncated) body decoded as UTF-8 with replacement: no
  match -> `CUSTOM_HTTP_BODY_MISMATCH`, except on a truncated body, where the match may lie past
  the cap -> `CUSTOM_HTTP_TOO_LARGE` (`body_truncated`, `error`);
- `header`: absent -> `CUSTOM_HTTP_HEADER_MISMATCH` (`header_missing`); a value not matching its
  pattern -> the same code (`header_no_match`);
- regex timeouts and budgets as for `dns_matches` (`error`).
Mismatch findings carry the configured severity and remediation, like `CUSTOM_CHECK_FAILED`.

Ownership gate (M7-21a, SPEC section 3): an http_fetch check fetches only for the domain its
caller vouched for as verified, `verified_domain` (the stored name of a domain whose
`verification_status` is `verified`, read by the caller in the same transaction as the check's
rows). Any other case (None, the default, or a target that is not that domain) is
`CUSTOM_HTTP_DOMAIN_UNVERIFIED` (`reason: domain_unverified`, `error`), decided first in the
http_fetch evaluation: no URL is built and nothing is fetched. Every run path builds checks this
way: the API domain run (`run_checks_for(..., domain_id=...)`), the dry run (`prepare_test`) and
any future scheduled path (which must use `run_checks_for` with the target's domain id; built
without it, the check is `error`). DNS kinds ignore `verified_domain`.
The response is untrusted: params hold only the check key, the rendered host, the final host
(validated by the client), the status and the expected statuses; body and header values only
reach `evidence`, at most MAX_EVIDENCE_CHARS each with non-printable characters replaced, which
renderers escape. Nothing about the response is logged.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Any, Final, Protocol
from urllib.parse import urljoin, urlsplit

from app.checks.dnsutil import classify
from app.checks.models import CheckContext, CheckResult, Finding, Severity, Target, finding
from app.core.custom_check_schema import (
    DefinitionInvalid,
    HttpFetchDefinition,
    NameRenderError,
    ParsedDefinition,
    parse_definition,
    render_name,
    render_url,
    validate_remediation_key,
    validate_remediation_text,
    validate_severity,
)
from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.core.safe_regex import (
    MAX_MATCHES,
    MAX_TEXT_BYTES,
    CompiledRule,
    SearchFailure,
    search_many,
)
from app.dns.types import DnsQuestion, Resolver
from app.net import FetchError, FetchErrorKind, FetchLimits, FetchResult
from app.net import fetch as guarded_fetch
from app.net.policy import MAX_URL_LENGTH, parse_url

CODES: tuple[str, ...] = (
    "CUSTOM_CHECK_FAILED",
    "CUSTOM_CHECK_ERROR",
    "CUSTOM_HTTP_BLOCKED",
    "CUSTOM_HTTP_UNREACHABLE",
    "CUSTOM_HTTP_TOO_LARGE",
    "CUSTOM_HTTP_STATUS_MISMATCH",
    "CUSTOM_HTTP_BODY_MISMATCH",
    "CUSTOM_HTTP_HEADER_MISMATCH",
    "CUSTOM_HTTP_DOMAIN_UNVERIFIED",
)
_REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})  # as the guarded client
_BLOCKED_KINDS: Final = frozenset(
    {FetchErrorKind.blocked, FetchErrorKind.scheme_not_allowed, FetchErrorKind.port_not_allowed}
)


class Fetcher(Protocol):
    """The guarded client's `fetch` signature, as far as this module uses it (test seam)."""

    async def __call__(
        self,
        url: str,
        *,
        resolver: Resolver,
        limits: FetchLimits | None = None,
        follow_redirects: bool | None = None,
        allow_truncated: bool = False,
    ) -> FetchResult | FetchError: ...


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
DOMAIN_UNVERIFIED: Final = "domain_unverified"
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
        fetch_limits: FetchLimits | None = None,
        fetcher: Fetcher | None = None,
        verified_domain: str | None = None,
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
        # http_fetch only: the operator's limits (None: the check is `error`) and the I/O seam.
        self._fetch_limits = fetch_limits
        self._fetcher: Fetcher = fetcher if fetcher is not None else guarded_fetch
        # http_fetch only: the verified domain this check may fetch from (None: none).
        self._verified_domain = verified_domain if isinstance(verified_domain, str) else None

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

    @staticmethod
    def _mismatch(
        code: str,
        severity: Severity,
        params: dict[str, Any],
        evidence: Iterable[str],
        remediation: dict[str, str] | None,
        remediation_key: str | None,
    ) -> Finding:
        """A requirement not met: configured severity and the definition's remediation."""
        if remediation is not None:
            params = {**params, "remediation_text": remediation}
        found = finding(code, severity, params, _evidence(evidence), remediation=False)
        if remediation_key is not None:
            found = found.model_copy(update={"remediation_key": remediation_key})
        return found

    async def _evaluate(self, ctx: CheckContext, target: Target) -> _Outcome:
        try:
            parsed = parse_definition(self._kind, self._definition)
            severity = validate_severity(self._severity)
            remediation, remediation_key = self._remediation()
        except DefinitionInvalid as exc:
            return self._error("invalid_definition", field=exc.field, detail=exc.reason)
        if isinstance(parsed, HttpFetchDefinition):
            return await self._evaluate_http(
                ctx, target, parsed, severity, remediation, remediation_key
            )

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
            found = self._mismatch(
                "CUSTOM_CHECK_FAILED", severity, params, evidence, remediation, remediation_key
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
                if not await _any_match(parsed, records, self._budget):
                    return failed("no_match", records)
            elif not _all_in_range(parsed, records):
                return failed("out_of_range", records)
        except _CannotEvaluate as exc:
            return self._error(exc.reason, **data)
        return _Outcome([], True, data)

    def _fetch_error(self, error: FetchError, host: str, data: dict[str, Any]) -> _Outcome:
        """A client error: `error`, with a code by kind. `detail` is a stable client code."""
        if error.kind in _BLOCKED_KINDS:
            code = "CUSTOM_HTTP_BLOCKED"
        elif error.kind is FetchErrorKind.too_large:
            code = "CUSTOM_HTTP_TOO_LARGE"
        else:
            code = "CUSTOM_HTTP_UNREACHABLE"
        reason = str(error.kind)
        params = {"check_key": self._key, "host": host, "reason": reason}
        found = finding(code, "low", params, remediation=False)
        extra = {"reason": reason, "detail": error.detail, "hop": error.hop}
        return _Outcome([found], False, {**data, **extra})

    def _redirect_off_domain(self, host: str, data: dict[str, Any], hop: int) -> _Outcome:
        """A redirect leaving the target domain: refused before it is requested. Nothing about
        the redirect target (host, status, body, headers) is reported."""
        reason = "redirect_off_domain"
        params = {"check_key": self._key, "host": host, "reason": reason}
        found = finding("CUSTOM_HTTP_BLOCKED", "low", params, remediation=False)
        return _Outcome([found], False, {**data, "reason": reason, "hop": hop})

    def _may_fetch(self, target: Target) -> bool:
        """True only if `target` is the domain the caller vouched for as verified."""
        if self._verified_domain is None:
            return False
        try:
            return to_ascii_domain(target.domain) == to_ascii_domain(self._verified_domain)
        except InvalidDomainName:
            return False

    def _unverified(self) -> _Outcome:
        params = {"check_key": self._key, "reason": DOMAIN_UNVERIFIED}
        found = finding("CUSTOM_HTTP_DOMAIN_UNVERIFIED", "low", params, remediation=False)
        return _Outcome([found], False, {"kind": "http_fetch", "reason": DOMAIN_UNVERIFIED})

    async def _evaluate_http(
        self,
        ctx: CheckContext,
        target: Target,
        parsed: HttpFetchDefinition,
        severity: Severity,
        remediation: dict[str, str] | None,
        remediation_key: str | None,
    ) -> _Outcome:
        if not self._may_fetch(target):  # before any URL is built or fetched (M7-21a)
            return self._unverified()
        try:
            url, host = render_url(parsed, target.domain)
        except NameRenderError as exc:
            return self._error(exc.reason)
        data: dict[str, Any] = {"kind": parsed.kind, "url": url, "host": host}
        base = self._fetch_limits
        if base is None:
            return self._error("fetch_unconfigured", **data)
        # The client's own policy on the built URL: same scheme, host and text, no IP literal.
        checked = parse_url(url, base.allowed_ports)
        if isinstance(checked, FetchError):
            return self._fetch_error(checked, host, data)
        if (checked.scheme, checked.host, checked.ip, checked.url) != (
            parsed.scheme,
            host,
            None,
            url,
        ):
            return self._error("url_mismatch", **data)

        domain = to_ascii_domain(target.domain)  # render_url already accepted it
        # Redirects are followed here, one request per hop, never by the client: every target
        # must be the domain or a host under it BEFORE it is requested (a tenant must not turn
        # the check into a proxy to an arbitrary host with read-back).
        current, checked_scheme = url, checked.scheme
        visited = {checked.url}
        hops = 0
        while True:
            remaining = self._budget.remaining()
            if remaining <= 0:
                return self._error(_RUN_BUDGET_EXCEEDED, **data, hops=hops)
            limits = replace(
                base,
                total_timeout=min(base.total_timeout, remaining),
                max_body_bytes=parsed.max_body_bytes,
            )
            try:
                async with asyncio.timeout(remaining):
                    response = await self._fetcher(
                        current,
                        resolver=ctx.resolver,
                        limits=limits,
                        follow_redirects=False,
                        allow_truncated=True,
                    )
            except TimeoutError:
                return self._error(_RUN_BUDGET_EXCEEDED, **data, hops=hops)
            if self._budget.remaining() <= 0:  # an answer past the budget gives no verdict
                return self._error(_RUN_BUDGET_EXCEEDED, **data, hops=hops)
            if isinstance(response, FetchError):
                cut = limits.total_timeout < base.total_timeout and response.detail == "deadline"
                if response.kind is FetchErrorKind.timeout and cut:
                    return self._error(_RUN_BUDGET_EXCEEDED, **data, hops=hops)
                return self._fetch_error(replace(response, hop=hops), host, data)
            hops += 1
            if response.status not in _REDIRECT_STATUSES:
                break
            # A redirect: no body, header or status of it reaches the result.
            if hops > base.max_redirects:
                error = FetchError(FetchErrorKind.too_many_redirects, "cap", hops)
                return self._fetch_error(error, host, data)
            location = response.headers.get("location", "").strip()
            try:
                following = urljoin(current, location) if location else ""
            except ValueError:
                following = ""
            if not following or len(location) > MAX_URL_LENGTH:
                error = FetchError(FetchErrorKind.protocol_error, "bad_location", hops)
                return self._fetch_error(error, host, data)
            nxt = parse_url(following, base.allowed_ports, hop=hops)
            if isinstance(nxt, FetchError):
                return self._fetch_error(nxt, host, data)
            if nxt.ip is not None or not (nxt.host == domain or nxt.host.endswith("." + domain)):
                return self._redirect_off_domain(host, data, hops)
            if checked_scheme == "https" and nxt.scheme == "http":
                error = FetchError(FetchErrorKind.scheme_not_allowed, "https_downgrade", hops)
                return self._fetch_error(error, host, data)
            if nxt.url in visited:
                error = FetchError(FetchErrorKind.too_many_redirects, "loop", hops)
                return self._fetch_error(error, host, data)
            visited.add(nxt.url)
            current, checked_scheme = nxt.url, nxt.scheme

        final_host = urlsplit(response.url).hostname or ""
        data.update(
            status=response.status,
            final_host=final_host,
            hops=hops,
            body_bytes=len(response.body),
            truncated=response.truncated,
        )
        params: dict[str, Any] = {
            "check_key": self._key,
            "host": host,
            "final_host": final_host,
            "status": response.status,
        }
        body = response.body.decode("utf-8", "replace")
        snippet = (body,) if body else ()

        def mismatch(code: str, reason: str, evidence: Iterable[str], **extra: Any) -> Finding:
            values = {**params, "reason": reason, **extra}
            return self._mismatch(code, severity, values, evidence, remediation, remediation_key)

        if response.status not in parsed.expected_status:
            expected = ", ".join(str(s) for s in parsed.expected_status)
            found = mismatch("CUSTOM_HTTP_STATUS_MISMATCH", "status", snippet, expected=expected)
            return _Outcome([found], True, {**data, "reason": "status"})

        header = response.headers.get(parsed.header_name) if parsed.header_name else None
        budget = _SearchBudget(self._budget)
        try:
            body_ok = parsed.body_rule is None or await _matches(parsed.body_rule, [body], budget)
            header_ok = parsed.header_rule is None or (
                header is not None and await _matches(parsed.header_rule, [header], budget)
            )
        except _CannotEvaluate as exc:
            return self._error(exc.reason, **data)

        findings: list[Finding] = []
        if not body_ok:
            if response.truncated:  # the match may lie past the cap: no verdict
                params_tl = {"check_key": self._key, "host": host, "reason": "body_truncated"}
                found = finding("CUSTOM_HTTP_TOO_LARGE", "low", params_tl, remediation=False)
                return _Outcome([found], False, {**data, "reason": "body_truncated"})
            findings.append(mismatch("CUSTOM_HTTP_BODY_MISMATCH", "body_no_match", snippet))
        name = parsed.header_name  # one of HTTP_HEADER_NAMES, never response text
        code = "CUSTOM_HTTP_HEADER_MISMATCH"
        if name is not None and header is None:
            findings.append(mismatch(code, "header_missing", (), header=name))
        elif not header_ok:
            findings.append(mismatch(code, "header_no_match", [header or ""], header=name))
        if findings:
            data["reason"] = findings[0].params["reason"]
        return _Outcome(findings, True, data)

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
        max_text_bytes=MAX_TEXT_BYTES,  # a decoded HTTP body can exceed the default cap
        total_timeout_s=remaining,
    )
    if result.failure is SearchFailure.BATCH_DEADLINE:
        raise _CannotEvaluate(_BUDGET_EXCEEDED)
    if result.timed_out:
        raise _CannotEvaluate("regex_timeout")
    if not result.complete:
        raise _CannotEvaluate("regex_failed")
    return bool(result.matches)


class _SearchBudget:
    """MAX_REGEX_BUDGET_S for all the searches of one evaluation, never past the run budget."""

    def __init__(self, run: RunBudget) -> None:
        self.run = run
        self._started = _regex_clock()

    def left(self) -> float:
        run_left = self.run.remaining()
        if run_left <= 0:
            raise _CannotEvaluate(_RUN_BUDGET_EXCEEDED)
        remaining = MAX_REGEX_BUDGET_S - (_regex_clock() - self._started)
        if remaining <= 0:
            raise _CannotEvaluate(_BUDGET_EXCEEDED)
        return min(remaining, run_left)


async def _matches(rule: CompiledRule, texts: Sequence[str], budget: _SearchBudget) -> bool:
    """True if `rule` matches any text; every text is searched (no early exit), so an incomplete
    search is `error` in any order."""
    matched = False
    try:
        for text in texts:
            matched = await _search(rule, text, budget.left()) or matched
        budget.left()  # a last search that ended past the budget gives no verdict either
    except _CannotEvaluate as exc:
        # A search cut by the batch deadline: say which budget ran out.
        if exc.reason == _BUDGET_EXCEEDED and budget.run.remaining() <= 0:
            raise _CannotEvaluate(_RUN_BUDGET_EXCEEDED) from None
        raise
    return matched


async def _any_match(parsed: ParsedDefinition, records: Sequence[str], run: RunBudget) -> bool:
    assert parsed.rule is not None
    return await _matches(parsed.rule, records, _SearchBudget(run))


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
