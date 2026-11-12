# R1-17 SPF tree: do not count or follow mechanisms after the first valid all
Milestone: R1
Branch: feature/r1-17-spf-terms-after-all
Findings: DNS-05 (low)
Files in scope: app/checks/spf_tree.py, app/checks/spf.py (only if needed), docs/CHECKS.md, tests/checks/test_spf_tree.py, tests/checks/test_spf_check.py, locales/en.json + locales/it.json only if the optional low finding for unreachable terms is added
Out of scope: the general worst-case counting convention (every term counted although evaluation stops at the first match is NOT disputed and stays), the target normaliser (R1-06), `redirect` semantics beyond what RFC 7208 5.1 says about modifiers
Depends on: none (functional); run after R1-06 because of the shared file
Parallel-safe: no (spf_tree.py shared with R1-06)
Model: opus (SPF logic)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- In one record, mechanisms after the first valid `all` are neither counted nor followed (RFC 7208 section 5.1: never tested). Modifiers (`redirect`, `exp`) keep their RFC handling: `redirect` is ignored when an `all` is present; state and test that.
- Test rows: `v=spf1 -all include:i0.example.net ... include:i10.example.net` -> lookup count 0, no `SPF_TOO_MANY_LOOKUPS` (reproduced today: fail with count 11); a SERVFAIL on an include placed after `all` does not make the check `error` and is not queried (query counter asserts it); terms BEFORE `all` still counted and followed; `all` appearing inside an included record stops only that record's terms; `+all`, `?all`, `~all` qualifiers behave the same; invalid `all`-like token is not treated as `all`.
- Optional: a low finding for unreachable terms (en + it); if added, aggregate once per record, capped evidence.
- No network. ruff, mypy, relevant tests green.
New i18n keys: none unless the optional low finding is added (then `finding.<CODE>.title/detail/remediation` en + it)
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/checks/spf_tree.py:313-325` (`_lookups` counts and follows every valid lookup term in record order).
- Problem: RFC 7208 section 5.1 says mechanisms after `all` are never tested, so they cause no DNS lookup at a receiver. The tree counts and resolves them, and the check can report `SPF_TOO_MANY_LOOKUPS` (high), `SPF_INCLUDE_NOT_FOUND`, void-lookup or DNS-error results for terms no receiver evaluates. `spf.py` already knows the rule (`_first_all`: "later mechanisms are never tested"). The general worst-case counting is the usual convention for such tools and is not disputed.
- Evidence (reproduced): `v=spf1 -all include:i0.example.net ... include:i10.example.net` -> status `fail`, `SPF_TOO_MANY_LOOKUPS` with `count: 11`. A receiver performs 0 lookups.
- Suggested fix: stop counting and following mechanisms after the first valid `all` in a record; optionally add a low finding for unreachable terms.
- Tests to add: tree and check cases with lookup terms after `all` (count 0, not followed, a servfail behind them does not make the check `error`).
- Confidence: high for the behaviour; such records are uncommon.
