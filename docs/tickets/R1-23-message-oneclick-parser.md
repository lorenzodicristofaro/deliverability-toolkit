# R1-23 Message analyzer: use the List-Unsubscribe parser for the One-Click check
Milestone: R1
Branch: feature/r1-23-message-oneclick-parser
Findings: PARSE-07 (low)
Files in scope: app/services/message_findings.py (`_other_part`, lines ~468-475), tests/services/test_message_findings.py, locales/en.json + locales/it.json only if a not-evaluated reason needs text (check first)
Out of scope: app/parsers/list_unsubscribe.py, the content analyzer, DKIM coverage of the Post header (message analyzer does not verify signatures)
Depends on: none
Parallel-safe: no with R1-10 and R1-22 (same module and test file): serialize after them
Model: sonnet (reuses an existing parser in a findings function; no parser change)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- `_other_part` calls `analyze_list_unsubscribe(block)` and emits `MSG_LIST_UNSUBSCRIBE_NO_ONECLICK` when `one_click_eligible` is false. When `https_uri_present` is `None` (capped or unreadable field) the area is marked not evaluated (error-class, with an explaining finding as in R1-10 if that has merged; otherwise the existing explaining mechanism) instead of staying silent.
- Same raw message gives the same One-Click answer in the message and content analyzers. Rows (message analyzer must emit the finding): (1) `List-Unsubscribe: <mailto:u@example.com>` + valid `List-Unsubscribe-Post: List-Unsubscribe=One-Click`; (2) `List-Unsubscribe: <https://example.com/u>` + `List-Unsubscribe-Post: x List-Unsubscribe=One-Click y`; (3) `List-Unsubscribe: <http://example.com/u>` + valid Post. Plus: a valid https + exact Post -> no finding; duplicated `List-Unsubscribe` field; over-long field value (capped -> not evaluated); no unsubscribe header at all (unchanged).
- Compare with the content analyzer (`CONTENT_NO_ONE_CLICK`) in a cross-check test using the same raw messages.
- No network. ruff, mypy, relevant tests green.
New i18n keys: none expected
Status: in-progress (parked)

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/services/message_findings.py:468-475`.
- Problem: `MSG_LIST_UNSUBSCRIBE_NO_ONECLICK` is suppressed whenever any `List-Unsubscribe-Post` value contains `list-unsubscribe=one-click` as a substring. RFC 8058 section 3.1 also needs an HTTPS URI in `List-Unsubscribe` and the exact single pair in the Post field. The M5-10 parser (`app/parsers/list_unsubscribe.py`, `one_click_eligible`) implements this and the content analyzer uses it, so the two analyzers give different answers for the same message.
- Evidence (same raw message to both): `List-Unsubscribe: <mailto:u@example.com>` + valid Post -> message analyzer: no unsubscribe finding; content analyzer: `CONTENT_NO_ONE_CLICK` (`detail_no_https_uri`). `List-Unsubscribe: <https://example.com/u>` + `List-Unsubscribe-Post: x List-Unsubscribe=One-Click y` -> message: none; content: `CONTENT_NO_ONE_CLICK` (`detail_post_value`). `List-Unsubscribe: <http://example.com/u>` + valid Post -> message: none; content: `CONTENT_NO_ONE_CLICK` and `CONTENT_HTTP_ONLY_UNSUBSCRIBE`.
- Suggested fix: as in the criteria.
- Tests to add: the three rows plus a duplicated `List-Unsubscribe` field and an over-long field value.
- Confidence: high.
