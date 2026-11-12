# R1-05 DMARC check applies sp when the policy is inherited from the organizational domain
Milestone: R1
Branch: feature/r1-05-dmarc-inherited-sp
Findings: DNS-01 (medium)
Files in scope: app/checks/dmarc.py, tests/checks/test_dmarc_check.py, docs/CHECKS.md, locales/en.json + locales/it.json (only if a finding text mentions `p=` literally and must change; `finding.DMARC_POLICY_NONE.detail` says "The policy is p=none")
Out of scope: the DMARC record parser (app/parsers/dmarc.py), app/checks/dmarc_external.py, the `error` vs `fail` rule at dmarc.py:121-122 (maintainer question, see TODO R1 block "Not ticketed")
Depends on: none
Parallel-safe: yes (locale files: serialize with other locale-touching tickets if a text changes)
Model: sonnet (DMARC check logic in one module; the parser is not touched)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- When `inherited` is true (record found at the organizational domain for a subdomain target), the applied policy is `sp` if present and valid, else `p`. `effective_policy`, `DMARC_POLICY_NONE`, the quarantine finding and `DMARC_PCT_PARTIAL` are derived from the applied policy.
- `DMARC_SUBDOMAIN_POLICY_WEAKER` is not emitted for an inherited record (it describes the parent; the applied policy already says it).
- `data["p"]` and `data["sp"]` stay as published.
- Table rows (target `mail.example.com`, record only at `_dmarc.example.com`): `p=none; sp=reject` -> no `DMARC_POLICY_NONE`, effective reject; `p=reject; sp=none` -> `DMARC_POLICY_NONE`, effective none, no WEAKER finding; no `sp` -> uses `p`; invalid `sp` (the step-6 path at dmarc.py:143) -> unchanged behaviour. Non-inherited behaviour unchanged (existing rows green).
- DNS failures still map to error as before. No network.
- docs/CHECKS.md describes the inherited rule. If the p=none detail text is wrong for the sp-derived case, adjust en + it.
- ruff, mypy, relevant tests green.
New i18n keys: none expected
Status: done
Outcome: reproduced (sp-strict, sp-weak, sp-pct rows); fixed in merge e12a9ca; Sonnet fixtures used non-reserved .org domains, escalated to Opus (fixtures moved to .test, sp-aware texts); QA APPROVE (Opus); dev CI green.

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/checks/dmarc.py:101-102` (`inherited`), `app/checks/dmarc.py:138-176` (`_analyse`: `effective_policy=p`, `DMARC_POLICY_NONE`, `DMARC_POLICY_QUARANTINE`, `DMARC_PCT_PARTIAL`, `DMARC_SUBDOMAIN_POLICY_WEAKER` all computed from `p`).
- Problem: for a subdomain with the record at the organizational domain, the policy that applies is `sp` (if present), not `p` (RFC 7489 section 6.3). `_analyse` receives `inherited` but uses it only to add `DMARC_INHERITED_FROM_ORG`; everything is derived from `p`. Wrong in both directions.
- Evidence (reproduced, target `mail.example.com`, record only at `_dmarc.example.com`): `v=DMARC1; p=none; sp=reject; rua=...` -> `DMARC_POLICY_NONE` (low), `effective_policy: "none"` (the subdomain is actually under reject). `v=DMARC1; p=reject; sp=none; rua=...` -> no `DMARC_POLICY_NONE`, `effective_policy: "reject"`, plus `DMARC_SUBDOMAIN_POLICY_WEAKER` (the subdomain is actually under none: unprotected subdomain shown as protected).
- Suggested fix: in `_analyse`, when `inherited` is true take the applied policy from `sp` falling back to `p`, base `effective_policy`, none/quarantine findings and `DMARC_PCT_PARTIAL` on it; do not emit `DMARC_SUBDOMAIN_POLICY_WEAKER` for an inherited record. Keep `data["p"]` and `data["sp"]` as published.
- Tests to add: rows in `tests/checks/test_dmarc_check.py` for an inherited record with `sp` stricter than `p`, `sp` weaker than `p`, no `sp`, invalid `sp`.
- Confidence: high.
