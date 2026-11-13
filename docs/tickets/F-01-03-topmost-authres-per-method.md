# F-01-03 Per-method findings use only the topmost Authentication-Results field
Milestone: F-01 (backlog, child of docs/tickets/F-01-auth-per-hop-view.md)
Branch: feature/f-01-03-topmost-authres-per-method
Files in scope: app/services/message_findings.py (`_topmost_results` and its docstring only), tests/services/test_message_findings.py (replace TOPMOST_RESULTS_PIN and its test; GM 2026-11-13: R122_FINDINGS row 2 expects MSG_DKIM_NOT_PASS, a direct consequence of the decision), docs/HEADERS.md (the paragraph stating the old lower-field rule), tests/services/test_message_analysis.py (only if a golden changes)
Out of scope: app/services/message_alignment.py (computed_dmarc and pairs unchanged), app/services/message_hops.py, MSG_AUTH_BROKE_AFTER_HOP, parsers, locales (no new keys; reuse the existing MSG_*_NOT_PASS keys and the existing "not_stated" variant)
Depends on: F-01-01, F-01-02 (both done)
Parallel-safe: no
Model: opus
Description: maintainer decision 2026-11-13 (TODO.md, F-01-03). The message's authentication outcome is what the receiver stated, i.e. the topmost Authentication-Results field. A lower field never suppresses, adds or replaces a per-method finding. Where a lower hop passed and the top did not, the hop view and MSG_AUTH_BROKE_AFTER_HOP already show it was correct earlier; the message still counts as not authenticated.
Acceptance criteria:
1. MSG_SPF_NOT_PASS and MSG_DKIM_NOT_PASS (and any other per-method result read by `_topmost_results`) take results ONLY from the topmost Authentication-Results field (headers[0]). A lower field never suppresses, adds or replaces them.
2. Top field without the method: finding emitted with the existing not_stated variant, severity low, even when a lower field states pass for that method.
3. Top dkim=fail + lower dkim=pass gives MSG_DKIM_NOT_PASS high. Top spf=pass + lower dkim=fail gives MSG_DKIM_NOT_PASS low not_stated (no "fail" taken from below).
4. computed_dmarc, alignment pairs, MSG_ALIGNMENT_FAIL, the hop view and MSG_AUTH_BROKE_AFTER_HOP are unchanged: their existing tests pass unmodified (except the old pin test being replaced).
5. Table-driven test covering: top only; top+lower pass; top+lower fail; top not stating the method; top field unparsed or missing authserv-id (MSG_AUTHRES_UNPARSED still fires, per-method results come from the top field only). No network.
6. docs/HEADERS.md states the rule: per-method findings report what the receiver (topmost field) stated; earlier hop results appear only in the hop view.
7. ruff, mypy and the relevant tests green.
New i18n keys: none
Status: todo
