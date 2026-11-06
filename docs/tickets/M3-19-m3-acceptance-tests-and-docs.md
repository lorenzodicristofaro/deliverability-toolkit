# M3-19 M3 acceptance tests and docs
Milestone: M3
Branch: feature/m3-19-acceptance
Files in scope: tests/checks/test_acceptance_m3.py, docs/CHECKS.md, TODO.md (M3 acceptance line only, by PM)
Out of scope: new features; fixes found go back to the owning ticket
Depends on: M3-11, M3-15, M3-16, M3-17, M3-18
Parallel-safe: yes (new files)
Model: sonnet
Acceptance criteria:
- Identical results: for each recorded zone (healthy, SPF over limit, SPF loop, DMARC external unauthorized, DKIM mix, SERVFAIL everywhere), the JSON from the service, the REST endpoint (domain-bound and free) and the CLI `--format json` is equal after removing only `started_at` and `duration_ms` (asserted with a fake clock so even those are equal if feasible).
- SERVFAIL/timeout/REFUSED/blocked on any lookup in SPF, DKIM, DMARC (incl. `_report._dmarc`) yields `error`, never `ok` and never a "missing" code; table test over every ResultState and every check.
- i18n completeness: every code in every check module `CODES` has title/detail/remediation in en and it; no hardcoded user strings in templates/CLI for M3 (existing guard extended or new scan).
- Network guard: the whole M3 suite runs with sockets blocked (extends the M2-15 pattern, also covering tests/api, tests/web, tests/cli DNS tests, which closes the open TODO follow-up if cheap).
- SSE streamed selector states equal the REST `data["selectors"]`.
- Tenancy sweep: every M3 route appears in the route-coverage matrix.
- `docs/CHECKS.md`: Check interface, finding code list with severities, how to add a check, CLI exit codes, the free-vs-tenant permission split, what is unverified.
- For every registered check, a recorded zone that returns SERVFAIL and one that times out both yield `error` through the service, API and CLI.
New i18n keys: none
Status: todo
