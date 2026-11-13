# R1-08 DKIM probe: a TXT record that is not a DKIM key does not make a selector "found"
Milestone: R1
Branch: feature/r1-08-dkim-non-key-txt
Findings: DNS-04 (medium)
Files in scope: app/checks/dkim.py, app/checks/esp_profile.py (primary `txt` selector path only, lines ~494-501), locales/en.json + locales/it.json (new finding), docs/CHECKS.md, tests/checks/test_dkim_check.py, tests/checks/test_esp_profile.py
Out of scope: the DKIM record parser (app/parsers/dkim.py), strict validity rule for primary ESP selectors (the minimal candidate test only), the random-label wildcard probe (option b of the review is NOT adopted), seeds/dkim_selectors.yaml, app/checks/dkim_selectors.py
Depends on: none
Parallel-safe: no with other tickets editing locale files or app/checks/esp_profile.py (serialize); yes with the rest
Model: sonnet
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- GM decision, classification: a TXT record is a DKIM key candidate if it starts with `v=DKIM1` or carries a `p=` tag (tag-list parse, tolerant of spaces). Candidates keep today's behaviour: a malformed candidate is still `DKIM_KEY_SYNTAX_ERROR`; selector `found`.
- A selector whose TXT records are ALL non-candidates is NOT found (treated as not found for selector status and for `DKIM_NO_SELECTOR_FOUND` logic). No per-selector syntax error for it.
- ONE aggregated finding per run, e.g. `DKIM_NON_KEY_TXT` (severity info), carrying the count of selectors affected and capped evidence (selector names, cap stated in a constant, text truncated, control characters not echoed raw). Not one finding per selector.
- `esp_profile` primary `txt` selectors apply the same minimal candidate test: a non-candidate TXT is not `ok`. Alternatives keep their existing strict validation.
- Tests: wildcard zone answering every `*.example.com` TXT with `v=spf1 -all` and with `google-site-verification=abc` -> `DkimCheck(["default","google","s1"])` gives no per-selector syntax errors, no `found`, `DKIM_NO_SELECTOR_FOUND` emitted, one `DKIM_NON_KEY_TXT` with count 3; mixed zone with a real key at one selector and wildcard text at others; a real but malformed key (`v=DKIM1; p=` garbage, or `p=` with bad base64) still gives `DKIM_KEY_SYNTAX_ERROR`; `_domainkey` as empty non-terminal; evidence cap respected with 250 selectors; esp `txt` selector answered by non-DKIM TXT in tests/checks/test_esp_profile.py.
- DNS failures still `error`. No network, no wall clock. ruff, mypy, relevant tests green.
New i18n keys: `finding.DKIM_NON_KEY_TXT.title/detail/remediation` (en + it); follow the existing key pattern of dkim findings and state the exact names. Remediation must not claim vendor behaviour.
Status: done
Outcome: reproduced (wildcard TXT made every selector found with DKIM_KEY_SYNTAX_ERROR; esp primary txt ok without a key); Sonnet round 1 got QA CHANGES REQUESTED (DKIM_MULTIPLE_RECORDS lost for a key next to a non-key TXT), escalated to Opus, fixed in round 2; merged aa9888f; QA APPROVE round 2; dev CI green.

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/checks/dkim.py:114-127` (`if txt.records:` -> `found`), `app/checks/dkim.py:193-196` (one `DKIM_KEY_SYNTAX_ERROR` per record), `app/checks/esp_profile.py:494-501` (a primary `txt` selector is `ok` for any TXT record; `validate_key` is only set for alternatives).
- Problem: the probe never checks whether the TXT data is a DKIM key record before calling a selector `found`. A domain with a wildcard TXT record (`*.example.com TXT "v=spf1 -all"` or a verification string) and no real selector answers every probed name, so every selector (up to 250) is `found`, each with a medium `DKIM_KEY_SYNTAX_ERROR`, and `DKIM_NO_SELECTOR_FOUND` is never emitted. In the `esp` check the same wildcard makes a `txt` selector such as Google Workspace `google` or Emailchef `mailchef` `ok` although no key is published.
- Evidence (reproduced): resolver answering every `*.example.com` TXT query with `v=spf1 -all`; `DkimCheck(["default","google","s1"])` -> status `warn`, `found: 3`, three `DKIM_KEY_SYNTAX_ERROR`. Same with `google-site-verification=abc`.
- Suggested fix (review): classify the TXT data before deciding; (a) a record with no parsable DKIM tag is "TXT present but not a DKIM key", and/or (b) a random-label probe. GM chose (a) with the rule above, plus ONE aggregated finding; (b) not adopted. For `esp_profile`, apply a minimal "is a DKIM key record" test to primary `txt` selectors too.
- Tests to add: as listed above.
- Confidence: high for the behaviour; medium for the best classification rule (a real but malformed key must still be reported as a syntax error).
