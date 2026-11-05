# M2-02 DNS result states and Resolver protocol
Milestone: M2
Branch: feature/m2-02-dns-result-types
Files in scope: app/dns/__init__.py (creates the package), app/dns/types.py, tests/dns/__init__.py, tests/dns/test_types.py
Out of scope: any query code, dnspython (not imported here), cache, settings, UI
Depends on: none
Parallel-safe: yes with M2-01 (disjoint); M2-03 onward depend on the package created here
Model: sonnet
Context: ARCHITECTURE section 7 ("distinguish NXDOMAIN, NODATA, SERVFAIL, timeout, REFUSED explicitly"). dnspython is NOT in pyproject yet; this ticket must stay dependency-free so the types do not leak library objects.
Acceptance criteria:
- `ResultState` StrEnum: `ok`, `nxdomain`, `nodata`, `servfail`, `refused`, `timeout`, `truncated` (response too large / TC not resolvable), `malformed` (unparseable or oversized response), `network_error` (unreachable, connection refused), `blocked` (target rejected by the egress policy, M2-03), `error` (anything else). Document each in a docstring with its meaning for callers.
- Helper properties: `is_definitive_absence` is True ONLY for `nxdomain` and `nodata`; `is_failure` True for servfail/refused/timeout/truncated/malformed/network_error/blocked/error. A test enumerates every member and asserts that exactly one of (ok, definitive absence, failure) holds, so a new state cannot be added without classification. SERVFAIL and timeout are never definitive absence (explicit test; this is the M2 acceptance line).
- Frozen dataclasses: `DnsQuestion(name, rdtype)` (name lowercase ASCII without trailing dot, rdtype as string from an allow-list incl. A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV, CAA, DS, DNSKEY, TLSA, NAPTR, SPF, ANY is NOT allowed), `DnsRecord(name, rdtype, ttl, rdata_text)`, `DnsResult(question, state, records, ttl_min, authenticated_data: bool, rcode: int | None, server: str | None, elapsed_ms, detail_code: str | None)`. `records` is non-empty only for `ok`. Constructor/factory rejects inconsistent combinations (records with a non-ok state; ok with no records).
- `Resolver` Protocol (async): `resolve(question: DnsQuestion) -> DnsResult` never raises for network/DNS conditions (returns a state); `identity: str` (stable id used as cache key and in reports). Documented: callers must handle every state.
- `rdata_text` is the canonical presentation text; TXT multi-string joining rule documented (concatenate strings, keep raw bytes decoded as latin-1 or escaped; coder decides, test it).
- Tests table-driven: state classification, record/state consistency, rdtype allow-list rejects unknown and ANY, immutability.
New i18n keys: none (state codes are stable identifiers; UI keys come in M2-13)
Status: todo
