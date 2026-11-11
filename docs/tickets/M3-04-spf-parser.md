# M3-04 SPF record parser
Milestone: M3
Branch: feature/m3-04-spf-parser
Files in scope: app/parsers/spf.py, tests/parsers/__init__.py, tests/parsers/test_spf.py
Out of scope: DNS, recursion, lookup counting, findings (M3-07/08)
Depends on: M3-01 (package init only)
Parallel-safe: yes with M3-05, M3-06 (own files; tests/parsers/__init__.py is created only here, M3-05/06 depend on it being merged or add it identically: GM merges M3-04 first)
Model: opus (SPF logic, parses DNS-sourced text)
Acceptance criteria:
- `is_spf_record(text)` (case-insensitive `v=spf1` as a whole first term, followed by space or end) and `parse_spf(text) -> SpfRecord` that never raises on bad input: returns terms plus a list of `ParseIssue(code, term, position)`.
- Terms: mechanisms `all include a mx ptr ip4 ip6 exists`, modifiers `redirect exp` and unknown modifiers; qualifiers `+ - ~ ?`; `a`/`mx` with domain and dual CIDR (`/24//64`); IPv4/IPv6 validated with `ipaddress`, prefix ranges checked; macros recognised syntactically (`%{d}` etc.) and flagged `has_macro`, not expanded.
- Issues reported (stable lowercase codes): unknown mechanism, empty value, bad CIDR, bad IP, duplicate `redirect`/`exp`, term after `all`, `redirect` together with `all`, uppercase/mixed case accepted, tabs/double spaces, trailing garbage, non-ASCII, missing `v=`.
- Resource bounds: input over 4096 chars or more than 200 terms is truncated with an issue, no quadratic or backtracking regex (ReDoS: no nested quantifiers; tokenise by split).
- Table-driven tests with real-world records (example.com placeholders) and at least 30 malformed inputs, plus a fuzz-ish test of random bytes/long input finishing under a time bound.
New i18n keys: none
Status: done
