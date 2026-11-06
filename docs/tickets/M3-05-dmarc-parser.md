# M3-05 DMARC record parser
Milestone: M3
Branch: feature/m3-05-dmarc-parser
Files in scope: app/parsers/dmarc.py, tests/parsers/test_dmarc.py
Out of scope: DNS, org-domain fallback, external authorization, findings (M3-09/10/11)
Depends on: M3-04 (tests/parsers package init) 
Parallel-safe: yes with M3-06 (own files)
Model: opus (DMARC parsing of DNS-sourced text)
Acceptance criteria:
- `is_dmarc_record(text)` and `parse_dmarc(text) -> DmarcRecord` never raising; returns tags plus `ParseIssue` list (same issue shape as M3-04; import it from a shared tiny module only if already present, else define in this file and note it for the GM).
- Tags: `v` (must be first), `p`, `sp`, `pct` (0-100 int), `rua`, `ruf` (comma lists of `mailto:` URIs with optional `!size` suffix; other schemes flagged, not rejected), `adkim`, `aspf` (`r|s`), `fo`, `ri`, `rf`, unknown tags kept; tag names case-insensitive, values per RFC 7489 syntax; whitespace around `;` and `=` tolerated.
- Issues: missing/late `v`, missing `p`, invalid `p`/`sp` value, pct out of range or non-numeric, duplicate tag, invalid URI, empty tag, trailing `;;`, uppercase values, non-ASCII, `v=DMARC2` etc.
- Each rua/ruf URI exposes its destination domain (lowercased, IDNA-validated) for M3-11.
- Bounded input (4096 chars, 50 tags, 20 URIs) with an issue when truncated; no backtracking regexes.
- Table-driven tests: real-world records and at least 30 malformed ones.
New i18n keys: none
Status: done
