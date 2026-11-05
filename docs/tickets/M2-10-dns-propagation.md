# M2-10 DNS propagation check across resolvers
Milestone: M2
Branch: feature/m2-10-dns-propagation
Files in scope: app/services/dns_propagation.py, tests/services/test_dns_propagation.py
Out of scope: HTTP/UI, scheduling/history (M7), free-form resolver IPs
Depends on: M2-04, M2-07, M2-08
Parallel-safe: yes with M2-09 (disjoint files)
Model: sonnet
Acceptance criteria:
- `check_propagation(name_input, rdtype, resolver_ids=None, *, ...) -> PropagationReport`: validates input with the M2-01 validator; queries the same question against the selected public resolvers from the M2-07 file (default: all with `status` verified; unverified ones only when explicitly selected, flagged in the report) plus the configured default resolver, concurrently with a concurrency cap and a per-resolver timeout; cache bypassed (live answers).
- Each resolver row keeps its own state and records. Aggregation: group resolvers by identical normalised record set (order-insensitive, TTL ignored in the comparison but shown); report `consistent` only when every evaluated resolver returned the same ok set or the same definitive absence; resolvers in a failure state (servfail, timeout, refused, blocked, ...) are listed as `not evaluated` and counted separately, never as "missing" and never as agreeing with an absence. If fewer than a configurable minimum evaluated, overall verdict is `inconclusive`. Table-driven tests of the aggregation, including: all agree, split answers, one SERVFAIL among agreeing, all timeout (inconclusive), nxdomain vs ok mix, CNAME vs A differences, TTL-only differences.
- Resolver selection limited to ids from the data file; unknown id rejected; maximum number of resolvers per request capped (constant, tested).
- Tests use the M2-04 fake server set (zone where two servers disagree); no network.
New i18n keys: none (codes only; UI keys in M2-14)
Status: todo

GM note 2026-11-05 (from M2-08 QA): public resolvers in M2-08 are built from the entry's first address only. Propagation must query every address of each selected entry (factory over entry.addresses) and report per-address results.
