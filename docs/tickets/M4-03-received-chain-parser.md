# M4-03 Received chain parser and hop delays
Milestone: M4
Branch: feature/m4-03-received-parser
Files in scope: app/parsers/received.py, tests/parsers/test_received.py
Out of scope: anomaly findings (M4-09), reverse DNS or any lookup of the hop hosts/IPs, API/UI/CLI.
Depends on: M4-01
Parallel-safe: yes (new files)
Model: opus
Acceptance criteria:
- Pure offline: IPs and hostnames are extracted as text only. NO DNS, no whois, no geoip, no network. Stated in the module docstring.
- Input: the ordered Received values from `HeaderBlock`. Output: hops ordered oldest-to-newest (the header order is newest-first, RFC 5321 section 4.4), each with from-host, from-ip (bracketed IPv4/IPv6 literal, validated with `ipaddress`, plus a flag for private/reserved), by-host, with-protocol, id (not interpreted), for (presence only, address NOT retained), timestamp (UTC-aware or None), raw.
- Extraction is best effort per RFC 5321 grammar (from/by/via/with/id/for clauses after the `;` date). It must not assume any vendor layout; a hop that does not fit the grammar keeps `parsed=False` plus raw text and a warning code, and never aborts the chain.
- Date handling: RFC 5322 dates, obsolete zone names (RFC 5322 4.3), numeric offsets, comments in dates. A date with no timezone, an invalid date (Feb 30, hour 25), or a missing `;` yields `timestamp=None` with a warning code `date_no_timezone` / `date_invalid` / `date_missing`; the timezone-less value is NEVER assumed UTC.
- Hop delay (seconds) is computed between consecutive hops only when both timestamps are present; negative delays are kept and flagged (`clock_skew`), never clamped. Total transit time = last minus first when both exist.
- Caps: at most 100 hops parsed (more -> `truncated` flag), max 8 KiB per hop value, tests at boundary.
- Hostile input table: NUL (rejected upstream, still no crash if passed), huge IPv6, bracket garbage, `from` repeated, 1 MB single token, nested parentheses 10k deep (regex must be linear: include a timing guard test with a bounded input, no ReDoS-prone patterns), non-ASCII host, empty Received.
- Test fixtures inline and synthetic: example.com, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32. RFC 5321 section 4.4 / appendix D examples may be used and cited.
New i18n keys: none
Status: done
