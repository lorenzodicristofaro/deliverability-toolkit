# M4-10 Message analysis service and result model
Milestone: M4
Branch: feature/m4-10-analysis-service
Files in scope: app/services/message_analysis.py, tests/services/test_message_analysis.py
Out of scope: HTTP, UI, CLI, registering in app/checks/registry.py (the Check protocol is domain-bound with a DNS CheckContext; the analyzer is not a domain check, so it is a separate service on purpose).
Depends on: M4-01..M4-05, M4-08, M4-09
Parallel-safe: yes (new files, after dependencies merged)
Model: sonnet
Acceptance criteria:
- `analyze_message(raw: bytes) -> MessageAnalysis`, synchronous, pure and deterministic (no clock: "now" never used; no DNS, no network, no filesystem, no DB, NOTHING persisted or logged with content). Exports `model_dump_json` as the single wire format for API/UI/CLI, with sorted keys like CheckResult.
- `MessageAnalysis`: summary (subject decoded and capped, from, to counts, date), received hops with delays, authentication results, arc, alignment, mime summary + size breakdown, findings (sorted via the CheckResult sorting rule: severity then code), overall status in the existing Status vocabulary (error if input could not be evaluated: oversize, NUL, no headers).
- Input errors (over cap, NUL, empty, no header block) return a `MessageAnalysis` with status `error`, a MSG_PARSER_LIMIT/invalid-input finding and no partial data; they never raise to the caller (the API maps them to 413/422 BEFORE calling, see M4-11).
- Each sub-parser exception is caught and turned into an error finding for that section; other sections still produced.
- Whole-run time/memory guard test: a 2 MiB hostile input (fold bomb, deep MIME, 500 headers) completes under a generous bounded time in test.
- Same bytes -> byte-identical JSON (determinism test).
New i18n keys: none
Status: todo
