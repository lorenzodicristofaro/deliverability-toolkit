# M2-06 TTL-respecting DNS cache
Milestone: M2
Branch: feature/m2-06-dns-cache
Files in scope: app/dns/cache.py, tests/dns/test_cache.py
Out of scope: settings/env vars (constants and constructor arguments only, so config.py stays untouched), persistence/DB, DNS snapshots (M7)
Depends on: M2-02
Parallel-safe: yes with M2-03, M2-04 (disjoint files)
Model: sonnet
Acceptance criteria:
- `CachingResolver(inner: Resolver, clock=..., min_ttl, max_ttl, negative_ttl, max_entries)` implements `Resolver`; injectable monotonic clock (no sleeping in tests).
- Key = (inner.identity, question). Never mixes results across resolvers.
- Positive results cached for min(record TTLs) clamped to [min_ttl, max_ttl]; TTL 0 is not cached (or cached for 0s, document); remaining TTL is reported on cache hits (records returned with decremented TTL).
- Negative results (nxdomain, nodata) cached with a bounded short TTL (SOA-minimum based negative caching per RFC 2308 only if the result type carries the SOA; otherwise `negative_ttl`; coder checks RFC 2308 and notes what was implemented).
- FAILURES ARE NEVER CACHED as success or absence: servfail, refused, timeout, truncated, malformed, network_error, blocked, error are not stored (or, if a short failure-cache is added to avoid hammering, it replays the same failure state, is separately bounded, and is tested to never produce nxdomain/nodata). Explicit tests for each failure state.
- Bounded size with eviction (LRU or oldest-first); concurrent identical queries are coalesced (single-flight) and a cancelled waiter does not poison the others; tested with asyncio.
- A `bypass_cache` / fresh flag on the call path for the DNS tool "no cache" option and for propagation (propagation must see each resolver's live answer): test.
- Table-driven tests: expiry boundary, clamp edges, eviction, mixed identities, TTL decrement.
New i18n keys: none
Status: done
