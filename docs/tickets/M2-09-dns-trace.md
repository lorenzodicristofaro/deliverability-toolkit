# M2-09 DNS trace (dig +trace style)
Milestone: M2
Branch: feature/m2-09-dns-trace
Files in scope: app/dns/trace.py, tests/dns/test_trace.py
Out of scope: HTTP/UI, DNSSEC validation (AD/DS shown only if the response carries them), propagation
Depends on: M2-03, M2-04, M2-05, M2-07, M2-08
Parallel-safe: yes with M2-10 (disjoint files); no with anything touching app/dns/ shared modules
Model: opus (follows referrals from untrusted DNS data, so it can be steered to internal addresses: SSRF-class risk)
Acceptance criteria:
- `trace(question, *, query_server, root_hints, policy, limits) -> TraceReport`: starts from the M2-07 root hints, queries a root server for the name, follows NS referrals (glue from the additional section, otherwise resolves the NS name through the configured resolver) down to the authoritative answer. Each hop records: zone, server name+address queried, question, state, rcode, referral NS set, elapsed, and the final answer or failure.
- EGRESS: every referral/glue/NS-derived address is untrusted. Each is checked with the M2-03 `is_allowed_untrusted_target` before a packet is sent; blocked addresses are recorded as a hop with `ResultState.blocked` and are skipped; if no allowed server remains the trace ends `error` with a detail code, never "not found". Test with the M2-04 zone that delegates to 10.x, 127.0.0.1, 169.254.169.254, ::1 and an IPv4-mapped private address: no query is sent to any of them (assert on the fake's query log).
- Limits (named constants, tested): max referral depth, max total queries, max servers tried per zone (try the next on timeout/servfail/refused, record each failure), total deadline, per-hop response size cap, loop detection (same zone/server pair, or a referral that does not move closer to the name), refusal of referrals to a zone that is not an ancestor of the query name (bailiwick check; coder documents the rule applied).
- Outcomes distinguished: final ok, nxdomain, nodata (authoritative), lame delegation (referral server answers non-authoritatively/refuses), all servers timed out/servfail (state failure, not absence), loop, depth exceeded. SERVFAIL/timeout at any hop never becomes "name does not exist".
- Both IPv4 and IPv6 server addresses supported; TCP fallback on truncation via the M2-05 primitive.
- Tests use only the fake server set: normal chain, glueless delegation, lame server then good server, all-fail, loop, deep chain, referral to private/loopback/metadata (as above), malformed referral (NS pointing at non-address data, CNAME at NS name), underscore name.
New i18n keys: none (hop/detail codes only; UI keys in M2-14)
Status: done

GM note 2026-11-05: add a test that a referral never reaches the user as "missing", and use FakeResolver.server_queries to prove no packet was sent to a blocked (e.g. 10.0.0.53) referral address.

Outcome (GM 2026-11-05): limits depth 16, 64 queries, 4 servers/zone, 15 s total, 16 NS + 32 glue per referral, 3 glueless NS/zone. ServerReply.authoritative added (scope widened to backends); nxdomain/nodata final only when AA. Endpoint must be rate-limited per user (TODO follow-up).
