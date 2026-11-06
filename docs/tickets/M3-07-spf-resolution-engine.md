# M3-07 SPF recursive resolution engine
Milestone: M3
Branch: feature/m3-07-spf-resolution
Files in scope: app/checks/spf_tree.py, tests/checks/test_spf_tree.py, tests/fixtures/zones/spf_*.yaml (new zone files only)
Out of scope: findings and i18n (M3-08), flattening hints, UI. No change to the M2-04 loader.
Depends on: M3-03, M3-04
Parallel-safe: yes (new files only)
Model: opus (SPF logic)
Acceptance criteria:
- `resolve_spf(resolver, domain) -> SpfTree`: fetches the SPF TXT via M3-03, follows `include` and `redirect` recursively, and records for every node: domain, record text, parsed terms, DNS state, depth, children.
- Counters per RFC 7208 section 4.6.4: DNS-lookup-causing terms (`include a mx ptr exists redirect`) counted across the whole tree (`ip4/ip6/all` not counted; `exp` not counted); `lookup_count`, `void_count` (queries answered NXDOMAIN/NODATA for `a mx exists include` targets), `mx_address_lookups` per MX capped at 10 (RFC 7208 section 4.6.4 limit), exposed as data; the 10 and 2 limits are constants in one place.
- Loop detection (domain revisited on the current path) stops descent, marks the node `loop=True`; depth and total node caps (e.g. depth 12, 100 nodes) stop resolution with a `truncated` marker so hostile records cannot cause unbounded queries.
- Multiple SPF records at a name: node keeps all, flagged `multiple_records`; no record: `no_record`. Failures (SERVFAIL, timeout, blocked, ...) mark the node `error` with the ResultState and `evaluated=False` at tree level; never treated as void or missing.
- Include of a domain with no SPF record is recorded (RFC permerror) distinct from DNS failure.
- All queries via the M2 Resolver protocol; same name fetched once per run (memo); zero real network (fake resolver + socket guard).
- Tests: table over new recorded zones: simple, nested includes at exactly 10 and 11 lookups, 2 and 3 voids, include loop A->B->A, self-include, redirect chain, MX with >10 hosts, SERVFAIL inside include, deep chain over the cap, malformed record inside include.
New i18n keys: none
Status: done
