# M5-22 Declarative custom checks: schema and DNS evaluator
Milestone: M5
Branch: feature/m5-22-custom-checks-eval
Files in scope: app/checks/custom.py, app/checks/custom_schema.py, tests/checks/test_custom.py, tests/checks/test_custom_schema.py, ARCHITECTURE.md (scope section only, see below), TODO.md (move the HTTP item to M7)
Out of scope: persistence (M5-07), API/UI (M5-23/24), any HTTP fetch, new dependencies.
Depends on: M5-03, M5-07
Parallel-safe: yes (new check modules; ARCHITECTURE.md/TODO.md edits are tiny and limited to the lines named here)
Model: sonnet
Decision (GM): M5 supports DNS kinds only: `dns_exists` (record of a type exists), `dns_matches` (a record value matches a regex), `dns_value_range` (numeric value in [min,max]). The `http_fetch` kind (SPEC §5) is DEFERRED to M7 because it needs the guarded outbound client (CLAUDE.md non-negotiable: all outbound network goes through it). The schema reserves `http_fetch` as a known kind but validation rejects it with a typed error "not available yet", and the evaluator refuses it; no HTTP code is written.
Doc updates required in this ticket: ARCHITECTURE.md (custom checks: DNS kinds in M5, http_fetch in M7 with the guarded client) and TODO.md (M5 line "Declarative custom checks (DNS/HTTP)" reworded to DNS only; add an M7 line "Custom check kind http_fetch via guarded client"). SPEC.md is NOT edited by the coder; the GM raises the SPEC §5 wording with the maintainer.
Acceptance criteria:
- Definition schema (typed, strict, unknown keys rejected): kind, record name template (`{domain}` placeholder only, validated so it can only produce a name under the target domain), record type (allowlist), regex (via safe_regex) or numeric range, severity (low|medium|high), per-language remediation text (en and it required, length-capped). Schema size cap.
- Evaluator uses the existing DNS layer/guarded resolver only (no new resolver). Result statuses follow the Check contract: DNS failure/timeout/regex timeout -> `error` (never ok, never swallowed); NXDOMAIN on `dns_exists` -> finding with the configured severity; value parse failure on range -> `error` with reason.
- Finding evidence bounded; remediation text taken from the definition and escaped by renderers (not an i18n key).
- Tests table-driven with a fake DNS backend (no network): exists/missing/NXDOMAIN/timeout/SERVFAIL, regex hit/miss/catastrophic (cut off), range in/out/non-numeric, TXT multi-string, name template abuse (`{domain}` injection, trailing dots, uppercase, IDN), `http_fetch` rejected in schema and evaluator.
New i18n keys: CUSTOM_CHECK_FAILED, CUSTOM_CHECK_ERROR, CUSTOM_KIND_UNAVAILABLE (.title/.detail generic wrappers; remediation comes from the definition) (en + it) — locale files edited by this ticket only if the final set is not empty; then it becomes Parallel-safe: no
GM notes (from M5-07): the custom_checks repository stores `definition` without schema validation and compiles no regex. This ticket must validate the definition schema and run every `dns_matches` pattern through `safe_regex.compile_checked` on EVERY write path (tenant and global repositories), not only in the evaluator, and the evaluator must recompile via compile_checked at run time (never trust a stored CompiledRule). Tenant rows use remediation_text only; remediation_key is global-only.
Status: todo
