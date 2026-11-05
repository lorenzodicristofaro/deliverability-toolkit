# M2-01 Trim whitespace in to_ascii_domain + DNS record-name validator
Milestone: M2
Branch: feature/m2-01-domain-trim-record-name
Files in scope: app/core/domain_names.py, tests/core/test_domain_names.py
Out of scope: DNS queries, tenant-domain rules other than the trim (single-label, numeric TLD, underscore stay rejected), UI, i18n
Depends on: none
Parallel-safe: yes (touches only the two files above)
Model: sonnet
Context: maintainer decision 2026-11-05 (TODO.md follow-ups, HANDOFF.md).
Acceptance criteria:
- `to_ascii_domain` strips leading/trailing whitespace (str.strip; includes tab, newline, NBSP and ideographic space at the ends only) before all other checks; whitespace in the middle is still rejected (`forbidden_character`); input that is only whitespace gives `empty`. The raw-length cap (`MAX_INPUT_LENGTH`) still applies to the raw input, before stripping.
- M1-18 tests updated: the "whitespace anywhere (no silent strip)" cases are split into "surrounding whitespace is trimmed" (accepted, normalised result) and "inner whitespace rejected". Docstring updated.
- New `to_dns_name(value, *, allow_underscore=True)` (name to choose is the coder's, document it): normalised ASCII name for DNS-tool record names. Same pipeline as `to_ascii_domain` (trim, control/surrogate rejection, IDNA 2008 + UTS #46 for non-ASCII labels, trailing dot removed, 253/63 limits) but: labels may contain `_` (e.g. `_dmarc.example.com`, `s1._domainkey.example.com`), a leading `_` is allowed, `*` is allowed only as an entire first label (wildcard owner name), a single-label name is allowed only if it is the root `.` (returned as `.`; decide and test), IP literals are rejected (reverse lookups use the separate IP path in M2-08), numeric-only TLD rejected. ASCII labels are validated with an LDH+underscore rule, not by IDNA (IDNA std3 rejects `_`); non-ASCII labels go through IDNA per label.
- `InvalidDomainName` reason codes reused or extended; the error never carries the input.
- `to_ascii_domain` behaviour for tenant domains is otherwise unchanged (underscore still rejected: explicit test).
- Table-driven tests for the new function incl. malformed input: NUL, control chars, empty label (`a..b`), label > 63, name > 253 (after IDNA), `_` only label, `a_.com`, `*.example.com` ok, `a.*.example.com` rejected, `*` alone, mixed `*x.example.com` rejected, IPv4/IPv6, unicode `bücher.example`, uppercase, trailing dot, double trailing dot.
New i18n keys: none
Status: todo

GM note 2026-11-05 (QA r1): scope widened to tests/api/test_domains.py (trimmed names now accepted). Trim set narrowed to ASCII space/\t/\r/\n; other end-of-string control chars stay rejected. Status: changes-requested.
