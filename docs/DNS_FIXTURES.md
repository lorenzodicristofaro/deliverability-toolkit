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
