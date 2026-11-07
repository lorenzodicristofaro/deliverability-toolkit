# M5-02 MIME cap consistency (any capped input is error-class)
Milestone: M5
Branch: feature/m5-02-mime-cap
Files in scope: app/parsers/mime.py, app/services/message_findings.py, app/services/message_analysis.py (only if status derivation lives there), docs/HEADERS.md, tests/parsers/test_mime.py, tests/services/test_message_findings.py
Out of scope: UI, API shape, other follow-ups (i18n scanner, CLI nits).
Depends on: none
Parallel-safe: yes (parsers/services of M4 only; disjoint from M5-01, M5-03)
Model: sonnet
Follow-up closed: TODO "MIME cap consistency (M4-14 QA)".
Decision (GM): any capped input yields the error class. Exceeding the MIME depth cap must behave like exceeding the part cap: MSG_PARSER_LIMIT, analysis status `error`, never a silent low/warn MSG_MIME_TRUNCATED alone.
Acceptance criteria:
- Table-driven tests: part cap exceeded, depth cap exceeded, both, neither; each capped case gives status error and MSG_PARSER_LIMIT; uncapped clean message unchanged.
- MSG_MIME_TRUNCATED either removed or kept only as additional detail; coder states which and updates en+it text accordingly (no key left unused, no key missing).
- message_findings.py:71 comment and docs/HEADERS.md describe the single rule; grep shows no remaining text claiming a different rule.
- Existing M4 acceptance tests still pass (byte-equal surfaces).
New i18n keys: none (existing MSG_* texts may be edited in en + it)
Status: todo
