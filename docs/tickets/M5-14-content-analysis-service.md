# M5-14 Content analysis service and findings
Milestone: M5
Branch: feature/m5-14-content-service
Files in scope: app/services/content_analysis.py, app/services/content_findings.py, app/checks/content.py (Check-interface wrapper if the interface fits an input-based check; else coder documents why and skips), locales/en.json, locales/it.json, tests/services/test_content_analysis.py, tests/services/test_content_findings.py
Out of scope: API, UI, CLI (M5-15..M5-17), network of any kind.
Depends on: M5-02, M5-08, M5-09, M5-10, M5-11, M5-13
Parallel-safe: no (locale files)
Model: sonnet
Acceptance criteria:
- `analyze_content(ctx: TenantContext, input) -> ContentAnalysis` (JSON-serializable, stable field order). Input: html and/or text, optional subject, optional `.eml` (reuses the M4 parsers to extract parts, headers, From domain, DKIM d=; `.eml` decoding errors/caps -> error-class per M5-02). When headers exist, List-Unsubscribe/One-Click facts are included; when not, that section is `not_evaluated` (never `ok`).
- Findings = verdicts over parser facts: CONTENT_* codes with severity, evidence, remediation, one code per finding kind (missing plain text, low text/image ratio, images without alt, masked link, URL shortener, non-https link, IP-literal link, unaligned link domain, many distinct link domains, malformed HTML, hidden text, Gmail-clip risk (advisory, heuristic wording), excess CSS, subject issues, no List-Unsubscribe, no One-Click, http-only unsubscribe, unsigned unsubscribe header, rule match, rule error, CONTENT_INPUT_CAPPED). Thresholds heuristic wording must say "advisory".
- Any parser cap hit or rule error -> section/overall status `error` (CLAUDE.md: error, not ok).
- Nothing stored, no request content in logs (caplog test), zero DNS/sockets (test blocks both).
- Tenant rules loaded via repository with the given TenantContext only.
- Every code has title/detail/remediation en + it; a test enumerates codes against both locale files.
New i18n keys: CONTENT_* codes as listed above, each .title/.detail/.remediation (en + it); coder lists the final set in the summary
GM note (constraints from M5-13 QA):
- Use one loader for the rules: all global and tenant rows, no `enabled_only`, page until a short page. `list()` defaults to limit 100 ordered by id, so a disabled override past page 1 would be silently lost. Include a test placing a disabled override past page 1.
- Always call `merge_tenant_rules` before evaluating; never pass unmerged rows, because `evaluate_rules` does not filter by tenant.
- From async code use `evaluate_rules_async`.
- Rule evidence can be None on a match.
- A seeded rule has a NULL title and takes its text from CONTENT_RULE.<seed_key>; a tenant rule whose seed_key's global row was removed can also have a NULL title, so handle that without a crash.
- When `RuleResults.complete` is False, the result must show evaluation was incomplete, never `ok` by omission; `input_capped`, `no_input`, `busy` and `budget_exceeded` are `not_evaluated`.
- All seeded rules are disabled today, so a clean result with zero rule matches is expected and must not imply that rules ran.
Status: todo
