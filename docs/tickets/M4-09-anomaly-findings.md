# M4-09 Header anomaly findings and i18n texts
Milestone: M4
Branch: feature/m4-09-anomalies
Files in scope: app/services/message_findings.py, tests/services/test_message_findings.py, locales/en.json, locales/it.json
Out of scope: service orchestration (M4-10), API/UI/CLI, DNS.
Depends on: M4-01, M4-02, M4-03, M4-04, M4-05, M4-08
Parallel-safe: no (locale files; serialize with every other ticket touching locales/*.json)
Model: sonnet
Acceptance criteria:
- Pure functions turning parser outputs into `app.checks.models.Finding` via `finding(...)`. Module declares `CODES: tuple[str, ...]` (CODE_RE compliant) so the M3-19-style i18n completeness test can cover it. Offline: no DNS or network.
- Minimum codes (coder may add, each with a table-driven test for positive, negative and malformed input): MSG_MISSING_FROM, MSG_MULTIPLE_FROM, MSG_MISSING_DATE, MSG_DATE_INVALID, MSG_DATE_NO_TIMEZONE, MSG_DATE_FAR_FROM_RECEIVED (skew > 24 h vs first hop), MSG_MISSING_MESSAGE_ID, MSG_DUPLICATE_SINGLETON_HEADER (From/Subject/Date/Message-ID repeated), MSG_RECEIVED_NONE, MSG_RECEIVED_UNPARSED, MSG_RECEIVED_CLOCK_SKEW, MSG_HOP_DELAY_HIGH (threshold constant, documented), MSG_RECEIVED_PRIVATE_IP_ORIGIN (info), MSG_AUTHRES_MISSING, MSG_AUTHRES_AUTHSERV_MISMATCH, MSG_SPF_NOT_PASS, MSG_DKIM_NOT_PASS, MSG_DMARC_NOT_PASS, MSG_ALIGNMENT_FAIL, MSG_ALIGNMENT_STATED_MISMATCH, MSG_UNVERIFIED_DKIM_SIGNATURE, MSG_ARC_INVALID, MSG_ARC_CV_FAIL, MSG_RETURN_PATH_MISSING, MSG_REPLY_TO_DIFFERS (info), MSG_LIST_UNSUBSCRIBE_MISSING (info), MSG_LIST_UNSUBSCRIBE_NO_ONECLICK (info, only when List-Unsubscribe present without List-Unsubscribe-Post; RFC 8058), MSG_ENCODED_HEADER_BROKEN, MSG_MIME_TRUNCATED, MSG_NO_TEXT_PART, MSG_PARSER_LIMIT (input capped).
- A finding is `error`-class (status error, not ok) when a needed header cannot be evaluated because of malformed input; missing data is never reported as a pass.
- Severity per code documented in a table in the module docstring. No vendor-specific expectation (no "Gmail requires X" claims; those need a verified provider-requirements data file in a later milestone).
- Every code has `finding.<CODE>.title`, `.detail`, `.remediation` (where a remediation exists) in en AND it; details never embed raw header values beyond a bounded, escaped excerpt (<= 200 chars, control chars removed).
New i18n keys: finding.MSG_*.title/detail/remediation for each code above (en + it)
Open points:
- Decide whether the Received `for` address in `raw` must be redacted in output or UI.
- QA nit: any 4-word date is reported as `date_no_timezone` without checking its shape (received.py:256). Optionally tighten this.
- M4-08 output: each alignment pair carries `authserv_id`/`authres_index`, and the report carries `stated_dmarc_authserv_id`/`stated_dmarc_index`. Flag mixed authserv-ids and do not treat AR results as trusted (RFC 8601 §5). `state` includes `aligned_but_not_passed` and `unknown` (reason `no_stated_result`). `computed_dmarc` ∈ pass/fail/not_evaluated.
GM decisions (2026-11-07):
- Findings never include the Received `for` address. M4-10 redacts the `for` clause from any raw hop excerpt it returns.
- The 4-word date nit (received.py) is out of scope here; tracked in TODO.md Follow-ups.
Status: todo
