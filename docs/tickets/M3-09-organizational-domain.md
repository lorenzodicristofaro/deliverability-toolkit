# M3-09 Organizational domain helper (public suffix)
Milestone: M3
Branch: feature/m3-09-org-domain
Files in scope: app/core/org_domain.py, seeds/public_suffix_list.dat (or the chosen library's bundled data), tests/core/test_org_domain.py, pyproject.toml/uv.lock (only if a library is chosen)
Out of scope: DMARC checks (M3-10), any network fetch of the list at runtime
Depends on: none
Parallel-safe: no (pyproject/uv.lock if a dependency is added)
Model: sonnet
Acceptance criteria:
- `organizational_domain(name) -> str` and `is_subdomain_of_org(name)` for the DMARC fallback (RFC 7489 section 6.6.3 uses the Public Suffix List).
- UNVERIFIED EXTERNAL FACT: the coder must pick the data source (Mozilla Public Suffix List, MPL-2.0, vs a bundled-data library such as publicsuffixlist) after reading its current official documentation and licence, record `verified_on` + source URL in a header comment/README line, and report the choice to the GM. No runtime network access; the list is updated by a documented manual step.
- Handles IDN (A-label normalisation via the project domain helpers), trailing dot, uppercase, wildcard and exception rules (`*.ck`, `!www.ck`), private-section suffixes decision documented (default: ICANN section only; note effect on `blogspot.com`-style domains), names that are themselves a public suffix (returns none, no crash), single-label names, empty/oversized input.
- Table-driven tests including malformed input.
New i18n keys: none
Status: done
