# M6-13b Bounded, fail-fast DKIM detection probes
Milestone: M6
Branch: feature/m6-13b-esp-detection-dkim-concurrency
Files in scope: app/checks/esp_detection.py, tests/checks/test_esp_detection.py
Out of scope: profile content, UI, locale files (no new codes), other checks, SPEC.md/ARCHITECTURE.md
Depends on: M6-13. Must merge BEFORE any of M6-08, M6-09, M6-10 (real profiles make the probe cost real).
Parallel-safe: no (serialized after M6-13; same files)
Model: opus
Acceptance criteria:
- app/checks/esp_detection.py:140-151 probes up to 32 selectors serially, each resolve up to 5 s (TOTAL_DEADLINE_S): a slow nameserver costs up to 160 s per `all` run. Run the probes with bounded concurrency, using the same pattern as the bounded workers in app/checks/dkim.py.
- Stop probing after the first timeout/SERVFAIL (any non-evaluated state) under `_domainkey.<domain>`: no new queries start after it, and the result is `error` (never `ok`) with ESP_DNS_ERROR as today. In-flight queries finish or are cancelled; either way no query result is swallowed.
- Keep the deterministic order (profile id, selector name) of findings and evidence, independent of completion order, and keep the 32 cap as the named constant MAX_DETECTION_DKIM_QUERIES (`dkim_queries` in data counts queries actually started).
- Test with a fake slow or timing-out resolver: after the first failure the total number of queries is bounded (assert the bound, no wall-clock assertion), the status is `error`, and the order of results is stable.
- Fold-in (M6-13 QA): `data.detection.spf` is "partial", not "ok", when the SPF tree had a DNS failure but every candidate already matched (esp_detection.py:117-121). Add a test. Check how the caller maps this state before choosing the value and keep the check status consistent.
- Fold-in (M6-13 QA): the detection cache is separate from the assigned part, so a selector shared with an assigned ESP is queried twice (esp_detection.py:135). Share the cache if cheap; if it needs a signature change beyond the two files in scope, drop it and record it as a follow-up instead.
- No network in tests; existing M6-13 tests stay green.
New i18n keys: none
Status: done (merged into local dev at 5ff9dcc after QA APPROVE round 2; GM gate full PostgreSQL suite on the combined merge)
