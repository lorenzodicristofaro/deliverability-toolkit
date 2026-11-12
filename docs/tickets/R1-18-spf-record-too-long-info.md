# R1-18 Drop the unverifiable 255-octet SPF_RECORD_TOO_LONG info branch
Milestone: R1
Branch: feature/r1-18-spf-record-too-long-info
Findings: DNS-06 (low)
Files in scope: app/checks/spf.py (`_length_findings`), locales/en.json + locales/it.json (detail and remediation mention the 255 rule), docs/CHECKS.md, tests/checks/test_spf_check.py
Out of scope: the 450-octet guideline finding (kept), `join_txt_strings` and the backend (no per-string length plumbing), SPF evaluation logic
Depends on: none
Parallel-safe: no with other tickets editing app/checks/spf.py or locale files (R1-06, R1-17): serialize
Model: opus (SPF area, WORKFLOW section 3; GM 2026-11-12)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- The `longest > TXT_STRING_MAX` (255) branch is removed; a valid 256-450 octet SPF record gives no length finding and the check can be `ok`.
- The 450-octet guideline finding (medium) stays and is unchanged: a 451-octet record keeps it.
- Rows: 255, 256, 301, 450, 451 octets (valid records); malformed record unchanged.
- Locale texts: the 255-specific wording removed or reworded in en + it only where the finding that remains mentions it; no unused keys left (the catalogue test must stay green).
- docs/CHECKS.md updated. No network. ruff, mypy, relevant tests green.
New i18n keys: none (text edits to the remaining finding at most; en + it)
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/checks/spf.py:157-168` (`_length_findings`, `longest > TXT_STRING_MAX`), `app/dns/types.py:76-80` (`join_txt_strings` concatenates the character-strings, so string boundaries are lost).
- Problem: the info variant is meant to flag "a string over 255 octets", but the check only sees the joined record, and a character-string over 255 octets cannot exist in a DNS answer at all (one length octet). The condition is therefore "the joined record is 256-450 octets", true for every correctly published long record. Such domains never get status `ok` for SPF, and the remediation asks for something already the case.
- Evidence (reproduced): a 301-octet `v=spf1 ip4:... -all` record -> status `info`, `SPF_RECORD_TOO_LONG` with `limit: 255`.
- Suggested fix: drop the 255 branch (keep the 450-octet guideline finding), or carry per-record string lengths from the backend if the maintainer wants a real check of something observable. Decision here: drop.
- Tests to add: a 300-octet valid record expects no finding; a 451-octet one keeps the medium finding.
- Confidence: high.
