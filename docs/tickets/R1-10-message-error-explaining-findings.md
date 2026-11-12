# R1-10 Message analysis: every error status carries a finding that says why
Milestone: R1
Branch: feature/r1-10-message-error-explaining-findings
Findings: PARSE-03 (medium)
Files in scope: app/services/message_findings.py, locales/en.json, locales/it.json, docs/HEADERS.md (findings table), tests/services/test_message_findings.py
Out of scope (maintainer decision pending): whether a field WITHOUT authserv-id whose resinfo list parsed cleanly should count as evaluated (leniency) is NOT in this ticket and goes to the maintainer; do not change `app/parsers/authres.py` or the `skip("authres")` condition. No vendor wording about Microsoft or any provider in texts or docs.
Depends on: R1-09 (removes the most common route to the alignment path)
Parallel-safe: no (same module as R1-09/R1-22; locale files shared)
Model: sonnet (adds findings and i18n keys in one service; no parser change)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- Two new error-class findings, one per silent path: `MSG_AUTHRES_UNPARSED` (path at message_findings.py:341, `acc.skip("authres")`; the issue codes go in as a parameter) and `MSG_ALIGNMENT_NOT_EVALUATED` (path at :397, `acc.skip("alignment")`; the pair reasons go in as a parameter). Names may follow the existing MSG_* pattern; the coder states the final names.
- Both set the analysis as not evaluated exactly as today (status stays `error`); they only add the explanation. Severity/class consistent with `MSG_PARSER_LIMIT` and `MSG_RECEIVED_UNPARSED`.
- Texts in en + it with title/detail/remediation; parameters rendered as data (escaped, no raw echo of header text; reason and issue codes only).
- Property-style test: every `MessageFindings` with `evaluated == False` contains at least one finding from an explicit "explains error" set (the set lists all existing explaining codes plus the two new ones). The test builds inputs from a table of hostile/malformed cases, including capped input, Received unparsed, bad Date.
- Rows: a clean message with an Authentication-Results field that has no authserv-id (first segment contains `=`, e.g. `spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com`) -> status error AND `MSG_AUTHRES_UNPARSED`; `computed_dmarc == not_evaluated` with a field present (e.g. `dkim=fail` without `header.d`, still reachable after R1-09) -> `MSG_ALIGNMENT_NOT_EVALUATED`.
- en/it completeness test green; docs/HEADERS.md findings table updated.
- No network. ruff, mypy, relevant tests green.
New i18n keys: `finding.MSG_AUTHRES_UNPARSED.title/detail/remediation` and `finding.MSG_ALIGNMENT_NOT_EVALUATED.title/detail/remediation` (en + it), following the existing MSG_* key pattern; the coder states exact names.
Status: done
Outcome: reproduced (15 tests); fixed in merge 247175e (MSG_AUTHRES_UNPARSED, MSG_ALIGNMENT_NOT_EVALUATED, medium, en+it); QA APPROVE (Opus); dev CI green.

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location:
  - `app/services/message_findings.py:341` (`acc.skip("authres")` when any Authentication-Results field has no authserv-id or an error-severity issue; no finding is added)
  - `app/services/message_findings.py:397` (`acc.skip("alignment")` when `computed_dmarc` is `not_evaluated`; no finding is added)
  - `app/parsers/authres.py:568-572` (a first segment containing `=` is read as a resinfo and flagged `missing_authserv_id`, severity `error`)
- Problem: two paths mark the analysis as not evaluated without adding a finding. The user sees status `error` (CLI exit 2) next to findings that are all `info`, or none, and nothing says which part could not be evaluated. Every other not-evaluated path in this module adds `MSG_PARSER_LIMIT`, `MSG_RECEIVED_UNPARSED` or a date finding. The header's parse issues are in the `authentication` view as raw codes only.
- Evidence: `Authentication-Results: spf=pass (sender IP is 203.0.113.5) smtp.mailfrom=example.com; dkim=pass (signature was verified) header.d=example.com;dmarc=pass action=none header.from=example.com;compauth=pass reason=100` on an otherwise clean message -> status `error`; findings: only `MSG_RECEIVED_PRIVATE_IP_ORIGIN` (info); `computed_dmarc: pass`, both pairs `aligned`. The reviewer remembers this header shape from a vendor's documentation but did NOT open it: unverified, so do not use vendor wording.
- Suggested fix: add one error-class finding for each silent path (e.g. `MSG_AUTHRES_UNPARSED` with the issue codes as a parameter, and `MSG_ALIGNMENT_NOT_EVALUATED` with the pair reasons), en and it. The leniency question is separate (maintainer).
- Tests to add: the property-style test and the two rows above.
- Confidence: high for the behaviour; medium for the provider claim (unverified).
- Related: TODO "Content findings (M5-14 QA)" mentions an `MSG_SECTION_FAILED` follow-up for a different path.
