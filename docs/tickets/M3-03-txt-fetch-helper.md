# M3-03 TXT/CNAME fetch helper for checks
Milestone: M3
Branch: feature/m3-03-txt-fetch-helper
Files in scope: app/checks/dnsutil.py, tests/checks/test_dnsutil.py
Out of scope: parsing SPF/DKIM/DMARC content, caching (M2-06 cache is inside the resolver), new DNS backends
Depends on: M3-01
Parallel-safe: yes
Model: sonnet
Acceptance criteria:
- `fetch_txt(resolver, name) -> TxtFetch(state, records: tuple[str, ...], evaluated: bool, ttl)`: joins each record's strings with `join_txt_strings` (latin-1, lossless), keeps record order from the resolver, never merges separate records.
- `fetch_cname(resolver, name)` returns the target or none, with state.
- State mapping is explicit: NXDOMAIN and NODATA -> `evaluated=True, records=()`; SERVFAIL, timeout, REFUSED, blocked (M2-03 egress), truncated, malformed, network_error -> `evaluated=False` with the original `ResultState`. A caller can never mistake a failure for "no record" (non-negotiable).
- Underscore names (`_dmarc.`, `_domainkey.`, `_report._dmarc.`) accepted via the M2-01 record-name validator.
- Tests against M2-04 recorded zones (healthy, failures) as a table over every ResultState; multi-string TXT; non-ASCII bytes; no network.
New i18n keys: none
Status: todo
