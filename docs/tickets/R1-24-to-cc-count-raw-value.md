# R1-24 To/Cc counts from raw header values, not RFC 2047 decoded ones
Milestone: R1
Branch: feature/r1-24-to-cc-count-raw-value
Findings: PARSE-08 (low)
Files in scope: app/services/message_analysis.py (`_count_addresses`, lines ~541-543), tests/services/test_message_analysis.py
Out of scope: parsers, summary schema, From/Return-Path/Reply-To handling (already raw)
Depends on: none
Parallel-safe: yes
Model: sonnet (one-line change in a summary helper with a table test)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- `_count_addresses` passes `raw_value` (not `decoded_value`) to `getaddresses`, as `message_alignment.py` and `message_findings.py` do for From, Return-Path and Reply-To.
- Table rows: `To: =?utf-8?Q?Doe=2C_John?= <j@example.org>` -> `to_count == 1` (today 2); `Cc: "Doe, John" <j@example.org>` -> 1; an encoded display name containing `<` and `@` (`=?utf-8?Q?a=3Cb=40c?= <x@example.org>`) -> 1; two real mailboxes -> 2; empty header, header with only comments/groups, 10,000-address list under the existing cap (malformed input, no exception).
- No network. ruff, mypy, relevant tests green.
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/services/message_analysis.py:541-543` (`_count_addresses` passes `decoded_value` to `getaddresses`).
- Problem: address lists must be split before encoded-words are decoded. A display name whose encoded form contains a comma is decoded first and then split as if it were two mailboxes, so the summary over-counts recipients.
- Evidence: `To: =?utf-8?Q?Doe=2C_John?= <j@example.org>` -> `summary.to_count == 2`. The equivalent quoted form `Cc: "Doe, John" <j@example.org>` -> `cc_count == 1`.
- Suggested fix: use `raw_value` in `_count_addresses`.
- Tests to add: one row with an encoded display name containing `=2C`, one with an encoded `<` and `@` in the display name.
- Confidence: high.
