# M7-04 seeds/dnsbl.yaml (data ticket)
Milestone: M7
Branch: feature/m7-04-dnsbl-seed
Files in scope: seeds/dnsbl.yaml, tests/checks/test_shipped_dnsbl.py, docs/DNSBL.md (list table: zone, return codes, source URL, verified_on, status)
Out of scope: engine code (M7-03), registration (M7-05), inventing any value
Depends on: M7-03 (schema/loader)
Parallel-safe: yes (data file, docs, one test file)
Model: sonnet (data; escalate to opus only if sources conflict)
Acceptance criteria:
- Every entry carries `verified_on` and official `sources` (the list operator's own documentation pages, fetched by the coder on the day; record the date). The coder takes zone names, return codes, categories and usage policy (query volume limits, commercial-use terms, whether public resolvers are blocked) ONLY from those pages.
- Anything not confirmed on the operator's official page is `status: unverified` with `unverified_fields` naming it; return codes are never guessed or copied from third-party blog posts. The coder lists every unverified item in the PR description.
- Candidate set (names only, from SPEC wording DNSBL/URIBL/RBL; each must be confirmed to still exist and still serve the stated purpose): Spamhaus ZEN/DBL, SpamCop, Barracuda, SURBL, URIBL, others only if the coder can cite an official page. Do not ship a list whose operator documentation cannot be fetched; leave it out and report it.
- Policy facts the maintainer must confirm are written in the entry as `usage_policy` text copied from the source with its URL, plus `unverified` where only secondary sources exist (for example free-use limits for self-hosted resolvers).
- Test loads the shipped file with the M7-03 strict loader, asserts verified_on present and not in the future, sources non-empty and https, unverified entries carry `unverified_fields`, no duplicate zones, and warns (not fails) when older than 12 months (same pattern as tests/esp/test_shipped_profiles.py).
- No network in tests.
Open for the maintainer (to be listed in the PR): every `unverified` entry; any list whose terms forbid use through the shipped default resolvers; whether to ship lists that require registration or a paid data feed (default: no).
New i18n keys: none
Status: done
