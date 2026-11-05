# M2-05 DNS backends: system / custom / Unbound (dnspython)
Milestone: M2
Branch: feature/m2-05-dns-backends
Files in scope: pyproject.toml, uv.lock (add runtime dependency `dnspython`), app/dns/backends.py, app/dns/factory.py (build_resolver from Settings), tests/dns/test_backends.py
Out of scope: cache (M2-06), trace (M2-09), propagation (M2-10), DoH, DNSSEC validation (we only surface the AD flag; DNSSEC view is M9), HTTP/SMTP
Depends on: M2-02, M2-03
Parallel-safe: no (pyproject.toml / uv.lock)
Model: opus (resolver egress enforcement; parsing untrusted network responses)
Dependency: dnspython is NOT currently in pyproject.toml (ARCHITECTURE section 1 names it). Add it as a runtime dependency; the coder records the pinned version and licence (dnspython is ISC per its repository; coder must confirm against the package metadata and mark `unverified` otherwise).
Acceptance criteria:
- One `DnsPythonResolver` class (async, `dns.asyncquery`) parameterised by a nameserver list and a trust flag; `factory.build_resolver(settings)` returns: `system` (nameservers read from resolv.conf via dnspython; trusted, documented that this is not policy-checkable), `custom` (RESOLVER_ADDRS, trusted), `unbound` (RESOLVER_ADDRS, expected 172.28.53.2:5353; trusted; sets the EDNS DO bit and reports the AD flag). Also `build_resolver_for_target(addr, policy)` for untrusted public-list/trace targets, which calls the M2-03 policy BEFORE any packet and returns `blocked` if rejected.
- Per-query timeout and total deadline, bounded retries (retry only on timeout/network error, never on NXDOMAIN/NODATA/REFUSED), UDP with TCP fallback on TC, EDNS buffer size set, response size cap (reject > cap as `malformed`), max answers cap, one query in flight per nameserver bounded by a semaphore. Defaults as named module constants (coder proposes values; record them in the ticket outcome).
- Rcode and exception mapping to M2-02 states, table-driven: NOERROR with answers -> ok; NOERROR no answers -> nodata; NXDOMAIN -> nxdomain; SERVFAIL -> servfail; REFUSED -> refused; other rcodes (FORMERR, NOTIMP...) -> error with `rcode`; dns.exception.Timeout -> timeout; connection errors -> network_error; malformed wire data / dns.exception.FormError -> malformed; CNAME chains followed server-side only (do not loop client-side); a CNAME to nothing is reported as the final state not as ok. SERVFAIL/timeout/refused are NEVER mapped to nxdomain/nodata (explicit tests, this is the M2 acceptance line).
- Name and type come from the M2-02 `DnsQuestion` (already validated); no hostnames as nameservers.
- Tests: NO network, NO sockets. The query transport is injected (a callable returning `dns.message.Message` or raising) so tests feed canned wire messages, including truncated, oversized, garbage bytes, ID mismatch, wrong question section, and a response from an unexpected source if the transport exposes it.
- `uv sync` and `uv run pytest -q` pass; mypy clean (dnspython ships typing information: coder verifies, else adds a narrow override).
New i18n keys: none
Status: todo

GM note 2026-11-05 (from M2-03/M2-04 QA):
- Backends implement `query_server(addr, question) -> ServerReply(result, referral)` as in tests/support/dns_zones.py. Callers MUST check `reply.referral` before `result.state`; a referral is never surfaced as "missing". `resolve()` is for recursive servers only.
- Wire `Settings.log_resolver_config()` (M2-03) into the app lifespan after `configure_logging` if this ticket touches startup; otherwise M2-12 does it.
