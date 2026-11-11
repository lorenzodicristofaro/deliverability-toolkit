# M2-08 DNS lookup and reverse-lookup service
Milestone: M2
Branch: feature/m2-08-dns-lookup-service
Files in scope: app/services/dns_tools.py (lookup, reverse), tests/services/test_dns_tools.py
Out of scope: trace (M2-09), propagation (M2-10), HTTP/UI, permissions (M2-11), cache wiring beyond accepting a Resolver
Depends on: M2-01, M2-02, M2-04, M2-07
Parallel-safe: no (first user of new services module with M2-09/M2-10; run alone, then 09 and 10 can run in parallel)
Model: sonnet
Acceptance criteria:
- `lookup(name_input, rdtype, resolver_selector, *, resolvers, bypass_cache=False) -> LookupReport`: validates `name_input` with the M2-01 DNS record-name validator (underscores accepted), rdtype from the M2-02 allow-list incl. an "all common types" mode that queries A, AAAA, MX, TXT, NS, SOA, CAA, CNAME, SRV? (coder fixes the list; ANY is not used because it is unreliable and often refused), concurrently with a cap; per-type result keeps its own `ResultState`.
- `resolver_selector`: `default` (configured resolver from settings), or `public:<id>` from the M2-07 data file. No free-form IP (see M2-03 open question); unknown id is a validation error. Public selectors go through the untrusted-target policy.
- `reverse(ip_input, ...)`: accepts IPv4/IPv6 text (rejects hostnames, ranges, zone ids, malformed), builds the in-addr.arpa / ip6.arpa name (nibble form), queries PTR; optional forward-confirmation (FCrDNS: each PTR name resolved back to A/AAAA, report match / mismatch / could-not-evaluate). Private/reserved IPs are allowed as INPUT to reverse (it is a query name, not a connection target) but a test documents that nothing connects to them.
- Output model is presentation-neutral: states, records (type, ttl, rdata_text), resolver identity, elapsed, AD flag, detail codes. A failure state is never rendered as "no record": `LookupReport.summary` exposes `evaluated: bool` so a caller can tell "nothing found" (nxdomain/nodata) from "could not evaluate" (servfail, timeout, ...). Tests prove SERVFAIL and timeout on one type do not turn into "missing" for that type and do not hide the other types.
- Tests use the M2-04 fake resolver only; table-driven incl. malformed names (NUL, too long, bad labels), IPv6 forms (compressed, mapped, uppercase), `_dmarc.example.com`, trailing dot, unicode names.
New i18n keys: none (codes only; UI keys in M2-13)
Status: done
