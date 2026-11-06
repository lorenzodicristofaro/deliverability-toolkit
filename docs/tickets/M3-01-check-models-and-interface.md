# M3-01 Check interface, CheckResult and Finding models
Milestone: M3
Branch: feature/m3-01-check-models
Files in scope: app/checks/__init__.py, app/checks/models.py, app/parsers/__init__.py, tests/checks/__init__.py, tests/checks/test_models.py
Out of scope: registry/runner (M3-02), any concrete check, DB persistence, i18n files
Depends on: none
Parallel-safe: yes (new directories only; creates both package inits so M3-04..06 do not)
Model: sonnet
Acceptance criteria:
- Pydantic models exactly as ARCHITECTURE section 3: `Target`, `CheckContext` (holds the `Resolver`, a clock, optional tenant/domain ids as plain values, no DB handle), `Finding`, `CheckResult`, `Check` Protocol (`id`, `async run(ctx, target)`).
- Finding code convention enforced by a validator: `^[A-Z][A-Z0-9_]+$`; i18n keys derived as `finding.<CODE>.title|detail|remediation` through a helper `finding(code, severity, params, evidence, remediation=True, docs_url=None)` so no check hand-writes keys.
- `CheckResult.status` helper `derive_status(findings, evaluated)`: not evaluated -> `error`; any critical/high -> `fail`; any medium/low -> `warn`; only info -> `info`; none -> `ok`. Findings sorted by severity (stable order) on construction.
- `CheckResult` JSON serialization is deterministic (sorted findings, datetimes ISO UTC, `duration_ms` int) and is the single wire format used by API/CLI/UI.
- A per-check `CODES` tuple convention is documented in the module docstring (used by the i18n completeness test in M3-19).
- Table-driven tests: status derivation, invalid codes, ordering, JSON round trip.
New i18n keys: none
Status: todo
