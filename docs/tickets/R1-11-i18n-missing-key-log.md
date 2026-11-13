# R1-11 The missing-i18n-key warning must show the key it reports
Milestone: R1
Branch: feature/r1-11-i18n-missing-key-log
Findings: AUTH-06 (low)
Files in scope: app/core/i18n.py OR app/core/logging.py (coder states which), tests/test_logging.py (and the i18n test file if the field is renamed)
Out of scope: changing which secret names are redacted beyond what is needed; other `extra=` call sites except to check them against the redaction list
Depends on: none
Parallel-safe: yes
Model: sonnet (logging field name). If the redaction rule itself is changed, QA on Opus because it protects secrets.
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- The formatted missing-key warning contains the missing key (`i18n_key="some.missing.key"` is no longer `[REDACTED]`), preferably by renaming the extra field (e.g. `message_id`); if instead the match rule is narrowed, secret-named fields stay redacted.
- Table test: `secret_key`, `api_key`, `token`, `password`, `encryption_key`, `authorization` and similar fields are still redacted.
- Every other `extra=` field in `app/` checked against the redaction list after the change; report any other innocent field redacted by the substring rule (fix only if trivial).
- ruff, mypy, relevant tests green.
New i18n keys: none
Status: done

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/core/i18n.py:57` (`extra={"i18n_key": key, ...}`), `app/core/logging.py:23-32` (`"key"` in `_SENSITIVE_KEYS`), `app/core/logging.py:41-43` (substring match).
- Problem: the JSON formatter redacts every extra field whose name contains `key`. The only field of the "i18n key missing" warning that says which key is missing is `i18n_key`, so production logs show `[REDACTED]`. In production strict mode is off, so a missing key renders as the raw key for the user and the operator cannot find which from the log.
- Evidence (run): formatting a record with `i18n_key="some.missing.key"` gives `{"level": "WARNING", "logger": "app.core.i18n", "message": "i18n key missing", "i18n_key": "[REDACTED]", "lang": "it"}`.
- Suggested fix: rename the extra field (for example `message_id`), or match sensitive names more precisely (whole word or suffix `_key` only for known secret names). Check the other `extra=` fields in the app against the same list. Files: `app/core/i18n.py` or `app/core/logging.py`, `tests/test_logging.py`.
- Tests to add: the formatted missing-key warning contains the key; secret-named fields (`secret_key`, `api_key`, `token`) are still redacted.
- Confidence: high.

Outcome: reproduced; fixed in merge b43dfa0 (log field i18n_msgid, redaction rule unchanged); QA APPROVE (Sonnet); dev CI green.
