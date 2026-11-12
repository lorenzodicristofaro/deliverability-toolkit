# R1-06 SPF tree: own domain-spec target normaliser (no false SPF_SYNTAX_ERROR for inner underscores)
Milestone: R1
Branch: feature/r1-06-spf-target-normaliser
Findings: DNS-02 (medium)
Files in scope: app/checks/spf_tree.py, app/checks/spf.py (only if `invalid_target` handling needs it), a new helper in app/core/domain_names.py OR a private helper in app/checks/spf_tree.py (coder states which), tests/checks/test_spf_tree.py, tests/checks/test_spf_check.py, docs/CHECKS.md (one sentence)
Out of scope (GM decision): DKIM and ESP CNAME-target strictness stays unchanged: app/checks/dkim.py:114,128 and app/checks/esp_profile.py:424 keep using `to_dns_name`. Do not change `to_dns_name`, `_LABEL_RE`, or tenant domain validation. SPF parser (app/parsers/spf.py) not changed.
Depends on: none
Parallel-safe: no with R1-17 (DNS-05, same file spf_tree.py); serialize R1-06 then R1-17
Model: opus (SPF logic; decides what a valid SPF target is)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- The SPF tree normalises include/redirect/a/mx/exists targets with its own function following the RFC 7208 `domain-spec` rules the SPF parser already applies: lowercase, exactly one trailing dot removed, 253-octet name and 63-octet label limits, labels of printable ASCII acceptable to `DnsQuestion`. `invalid_target` stays only for names that really cannot be queried.
- Table-driven targets, each asserting "queried" vs `invalid_target`, and that parser validity and tree validity agree: `spf_c.x.test`, `a__b.x.test`, `__x.x.test`, `x-.x.test`, `-x.x.test`, `_.x.test`, a 63-octet label (ok), a 64-octet label (invalid), a 253-octet name (ok), a 254-octet name (invalid), empty label, trailing double dot, non-ASCII, space/control characters.
- End-to-end check test: `example.com TXT "v=spf1 include:spf_c.example.net -all"` with a valid record at `spf_c.example.net` -> include is fetched, status not `fail`, no `SPF_SYNTAX_ERROR`.
- Names that really are invalid still yield `SPF_SYNTAX_ERROR` as before; DNS failure states still map to `error`.
- docs/CHECKS.md states which target rule the SPF tree uses and that DKIM/ESP CNAME targets are intentionally stricter.
- No network; no wall clock. ruff, mypy, relevant tests green.
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/checks/spf_tree.py:333-337` (`to_dns_name(raw)` -> `invalid_target=True`), `app/checks/spf.py:139-141` (`invalid_target` -> `SPF_SYNTAX_ERROR`, high), `app/core/domain_names.py:106-124` (`_LABEL_RE`: LDH with one optional leading underscore).
- Problem: the SPF tree normalises every include/redirect/a/mx/exists target with `to_dns_name`, whose label rule is stricter than both DNS and the RFC 7208 `domain-spec` grammar: `a_b`, `a__b`, `__x`, a trailing or leading hyphen are rejected. The SPF parser accepts these terms as valid, but the tree marks them `invalid_target`, never queries them, and the check reports a high-severity syntax error whose text says receivers return permerror. A receiver would resolve such a name normally.
- Evidence (reproduced): `example.com TXT "v=spf1 include:spf_c.example.net -all"` with a valid record at `spf_c.example.net` -> status `fail`, `SPF_SYNTAX_ERROR` (high), evidence `invalid_target: include:spf_c.example.net`, the include never fetched. `parse_spf("v=spf1 include:a__b.example.net include:_.example.net include:-x.example.net -all").is_valid` is `True`.
- Suggested fix: give the SPF tree its own target normaliser that follows the `domain-spec` rules the parser already applies, instead of the host-name rule; keep `invalid_target` for names that cannot be queried. (The review noted the same strict rule on CNAME targets in dkim.py/esp_profile.py yields `error`/`invalid_name`, not a wrong verdict; GM decision: leave those unchanged.)
- Tests to add: table-driven targets above in `tests/checks/test_spf_tree.py` and `tests/checks/test_spf_check.py`.
- Confidence: high for the behaviour; medium for how common such include targets are in production (not checked against live DNS).
