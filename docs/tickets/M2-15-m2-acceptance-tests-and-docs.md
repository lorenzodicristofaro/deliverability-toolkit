# M2-15 M2 acceptance tests and DNS docs
Milestone: M2
Branch: feature/m2-15-acceptance-docs
Files in scope: tests/dns/test_acceptance_m2.py, docs/DNS.md (new: layers, states, egress rule as implemented, how to add a zone fixture, data-file verification rule), TODO.md (checkboxes via PM)
Out of scope: ARCHITECTURE.md / SPEC.md (the GM or maintainer records the DNS egress decision in ARCHITECTURE section 7; PM and coders do not edit it)
Depends on: M2-01 to M2-14
Parallel-safe: no (last ticket)
Model: sonnet
Acceptance criteria:
- Named acceptance tests, one per line of the M2 acceptance criterion: "tests pass against recorded zones" (healthy, nxdomain, nodata, disagreement, delegation chain from fixtures) and "SERVFAIL/timeout never reported as record missing" asserted at each layer: backend mapping, cache (not cached as absence), lookup service, propagation aggregation, trace, REST response, and rendered HTML (reusing the M2-04 fixtures).
- A guard test lists every `ResultState` member and fails if one lacks an i18n key in en and it, a UI rendering, and a classification (so adding a state forces updates).
- A guard test fails if any module under app/dns or app/services/dns_* imports `socket`/opens connections outside the backend module, and if any unit test run created a socket (global socket monkeypatch in tests/dns conftest, if not already present).
- docs/DNS.md written; lint, mypy and full suite green.
New i18n keys: none
Status: todo

GM note 2026-11-06 (carried from M2-14 QA; scope widened to app/web/dns_tools.py, app/web/templates/dns/trace.html, app/web/static/app.css, locales/en.json, locales/it.json):
- too_many_targets in the propagation UI shows the generic api.error.invalid_request: add key tools.dns.propagation.too_many_targets (en+it), map it in `_error_key`, test with MAX_TARGETS monkeypatched (422, error testid, no input echo).
- `dns-state-referral` (trace.html:38) needs a one-line CSS rule in app.css.
- app/web/dns_tools.py:212 `_MAX_RESOLVER_IDS = 8` duplicates the service's MAX_RESOLVERS: import it. Drop the `# type: ignore[arg-type]` at :320 with a typed signature.
