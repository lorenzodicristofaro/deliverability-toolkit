# DNS zone fixtures

Hand-written YAML under `tests/fixtures/zones/`, loaded by `tests/support/dns_zones.py`
(`load_zones`, `parse_zones`). Never recorded from the live network. Only `example.com`,
`example.net`, `example.org`, `*.test`, `*.invalid`, RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) and RFC 3849 (`2001:db8::/32`) are allowed; a guard test enforces it. The one
exception is the private referral address `10.0.0.53` (for the M2-09 egress test).

```yaml
zones:
  default:                      # server id: `default` or an IP (per-server answers)
    - {name: example.com, type: A, ttl: 300, rdata: [192.0.2.10], ad: true}   # ad optional
    - {name: example.com, type: TXT, ttl: 300, rdata: [["part1 ", "part2"]]}   # multi-string TXT
    - {name: x.example.com, type: A, state: servfail, rcode: 2}               # explicit failure
    - {name: y.example.com, type: A, state: nxdomain, aa: false}              # non-authoritative
    - referral: {zone: example.com, ns: [{name: ns1.example.net, addr: 192.0.2.3}]}
```

- Names are lowercase, no trailing dot; types come from `ALLOWED_RDTYPES`. `rdata` is a non-empty
  list of strings (canonical presentation text); a TXT item may be a list of strings, joined as
  `join_txt_strings` does. A and AAAA rdata must be IP addresses.
- `state`: `servfail|refused|timeout|nxdomain|nodata|truncated|malformed|network_error`,
  optional `rcode` (0..15, must agree with the state). An entry has `rdata` xor `state`.
- Unlisted (name, type): `nodata` if the name has any record or is an empty non-terminal (it has
  descendants with records), else `nxdomain`. A name under a `referral` zone with no own data
  returns a `ServerReply` carrying the referral (result state `nodata`).
- Loading fails with `ZoneFixtureError` (source, entry index, reason) on missing keys, unknown
  state, bad ttl, duplicate (name, type), non-string rdata, bad server id.
- `FakeResolver` records `questions`, advances a virtual clock by `latency_ms` and never sleeps.
  `FakeServerSet.query_server(addr, question)` is a provisional shape for the M2-05 primitive;
  an address without fixture answers `network_error`.
- `query_server` callers must check `reply.referral` before `reply.result.state` (a referral
  reply carries the placeholder state `nodata`). `resolve()` models a recursive server only.
  `FakeServerSet.server_queries` lists every `query_server` call, unknown addresses included.
- `aa` (optional boolean, default `true`) is the AA flag reported as `ServerReply.authoritative`.
  Data a server serves (listed entries and the derived `nodata`/`nxdomain`) is authoritative by
  default; set `aa: false` on an entry to model a non-authoritative/lame answer. Referral replies
  and unreachable addresses are always `authoritative=False`. Trace (M2-09) accepts
  `nxdomain`/`nodata` as final only from an authoritative reply. A non-boolean `aa` fails loading.
- `rcode` agreement follows `DnsResult`: `nxdomain` = 3, `nodata` = 0, any other failure state
  must not use 0 or 3. TXT strings must be latin-1 encodable.
