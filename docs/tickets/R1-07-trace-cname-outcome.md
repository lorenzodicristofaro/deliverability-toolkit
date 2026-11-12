# R1-07 DNS trace: report an unfinished CNAME chain instead of nodata
Milestone: R1
Branch: feature/r1-07-trace-cname-outcome
Findings: DNS-03 (medium)
Files in scope: app/dns/backends.py (`interpret_response`, `_Interpreted`/`ServerReply`), app/dns/trace.py (`TraceOutcome`, authoritative-answer handling), the services/routers/templates that render trace reports (coder lists them: app/services/dns_tools.py, app/api/v1/dns_tools.py, app/web/dns_tools.py and its template), locales/en.json + locales/it.json, docs/DNS.md, tests/dns/test_backends.py, tests/dns/test_trace.py, tests/api and tests/web trace rendering tests
Out of scope (GM decision: REPORT, do not follow): restarting the trace from the root for the CNAME target is a follow-up, NOT in this ticket. `resolve()` against a recursive resolver is unaffected and unchanged. Egress policy unchanged.
Depends on: none
Parallel-safe: no with R1-19 (DNS-07, same files app/dns/backends.py, tests/dns/test_backends.py, docs/DNS.md); serialize R1-07 then R1-19. Locale files shared with other tickets that add keys.
Model: opus (crosses backends, trace, rendering, locales; SPEC-level resolver behaviour)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- `interpret_response` exposes the unfinished chain (the CNAME records and the last target) when the answer holds a CNAME chain but no record of the asked type. It no longer drops the CNAME and returns plain `nodata` in that case.
- The trace ends with a new distinct outcome (e.g. `cname`) that carries the CNAME chain and the final target, instead of `nodata`. Existing outcomes unchanged.
- The new outcome has en + it labels, is rendered by the API (documented field shape, additive) and the UI (escaped, no raw HTML), and is described in docs/DNS.md, including the sentence that following the target is not done.
- Not an error and not "no record": nothing may say "the name exists, no record of that type" for a CNAME name.
- Tests, tests/dns/test_backends.py: AA NOERROR response with only `www.example.com. 300 IN CNAME host.example.net.` for `www.example.com A` -> unfinished chain exposed, not `nodata`; in-zone chain plus final record -> records returned as before; NXDOMAIN with a CNAME in the answer -> NXDOMAIN handling unchanged and the CNAME still not mistaken for data; CNAME loop inside one response; chain length cap respected.
- Tests, tests/dns/test_trace.py: CNAME at the query name into another zone -> outcome `cname` with the chain; existing `ns_is_cname` cases unchanged; a truly empty NOERROR AA answer still gives `nodata`.
- API/UI test for the new outcome (translated label in it, hostile target text escaped).
- Hand-built dnspython messages, no network, no wall clock. ruff, mypy, relevant tests green.
New i18n keys: one label key for the new trace outcome (name follows the existing trace outcome key pattern; the coder states it), en + it.
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/dns/backends.py:242-265` (`_follow_chain` returns `None` with a non-empty CNAME chain), `app/dns/backends.py:325-335` (`interpret_response` -> `nodata`), `app/dns/trace.py:540-561` (authoritative `nodata` ends the trace as outcome `nodata`).
- Problem: an authoritative server answers `www.example.com A` with only `www.example.com CNAME host.example.net` when the target is in another zone (it does not hold the target's records). `interpret_response` follows the chain inside the response, finds no A record and returns `nodata`, dropping the CNAME. The trace accepts an authoritative `nodata` as final, so the tool states "the name exists, no record of that type" for a name that resolves through a CNAME. Common for `www`, tracking and DKIM-delegation names. `resolve()` against a recursive resolver is not affected.
- Evidence: `interpret_response` on an AA NOERROR response whose answer section is `www.example.com. 300 IN CNAME host.example.net.` for question `www.example.com A` returns `state=nodata, records=()` (reproduced). `tests/dns/test_trace.py` has CNAME cases only for NS names (`ns_is_cname`), none for a CNAME at the query name. The trace end-to-end path is by code reading (`trace.py:540-561`), not run.
- Suggested fix (review): let `interpret_response` report the unfinished chain, and have the trace either record a `cname` hop and restart from the root (budgets and restart cap) or end with a distinct outcome that shows the CNAME instead of `nodata`. GM decision: the second option only (report, do not follow).
- Tests to add: as listed above (the review also suggested CNAME loop across zones and budget exhaustion during a restart: only relevant to the follow-up, not here).
- Confidence: high for `interpret_response`; medium-high for the trace outcome (read, not run end to end).
