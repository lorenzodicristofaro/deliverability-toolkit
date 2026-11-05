# M2-04 Recorded-zone fixture format and replay/fake resolver
Milestone: M2
Branch: feature/m2-04-recorded-zones-fake-resolver
Files in scope: tests/support/__init__.py, tests/support/dns_zones.py (loader + FakeResolver), tests/fixtures/zones/*.yaml (a few sample zones), tests/conftest.py (fixture `fake_dns` only, check the existing file first), tests/dns/test_fake_resolver.py, docs/DNS_FIXTURES.md (short format description)
Out of scope: the real backends, any socket use, recording from the live network (fixtures are hand-written with example.com / RFC 5737 / RFC 3849 / reserved names only, WORKFLOW section 5)
Depends on: M2-02
Parallel-safe: yes with M2-03, M2-06 (disjoint dirs; tests/conftest.py touched only here in this wave)
Model: sonnet
Acceptance criteria:
- YAML fixture format (document in docs/DNS_FIXTURES.md): top-level `zones:` keyed by server id (`default` or an IP, so propagation and trace can give different answers per resolver/authoritative server); per server a list of entries `{name, type, ttl, rdata: [..]}` plus explicit failure entries `{name, type, state: servfail|refused|timeout|nxdomain|nodata|truncated|malformed|network_error, rcode?}`; delegation entries for trace (`referral: {zone, ns: [{name, addr}]}`); optional `ad: true`. Unknown name and type with no entry returns `nxdomain` if the name has no records of any type, else `nodata` (RFC semantics: empty non-terminal handling documented). Schema validated on load with clear errors (pydantic or manual; pyyaml is a dev dependency today, that is fine for tests).
- `FakeResolver(zones, server=...)` implements the M2-02 `Resolver` protocol; records every question asked (for "no extra queries" assertions); simulated latency optional (virtual clock, no real sleeping); `timeout` state returns immediately without sleeping.
- A `FakeServerSet` can serve a mapping server id -> FakeResolver for propagation and a `query_server(addr, question)` primitive matching the one M2-05 will expose (agree the signature in M2-02/M2-05 review; if not yet defined, expose the minimal shape and note it for the GM).
- Safety: loading a fixture with a real-looking public name outside example.* / *.test / *.invalid / reserved is a test failure (guard test scanning tests/fixtures/zones).
- Tests table-driven including malformed fixtures (missing keys, unknown state, bad ttl, duplicate entries, non-string rdata), and proof that no socket is created (monkeypatch socket.socket to raise).
- Sample zones: healthy domain (A, AAAA, MX, TXT multi-string, NS, SOA, CAA), NXDOMAIN, NODATA (name exists, type does not), SERVFAIL, REFUSED, timeout, a zone where two servers disagree, a delegation chain root -> tld -> example.com for trace, one referral pointing to a private address (for M2-09), underscore names (_dmarc, _domainkey).
New i18n keys: none
Status: done
