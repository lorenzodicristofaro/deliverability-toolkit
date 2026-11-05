# DNS layer (M2)

How the DNS engine and the raw DNS tools work, as implemented. Design rules live in
`ARCHITECTURE.md` section 7; this file does not replace them. Test fixtures: `docs/DNS_FIXTURES.md`.

## Layers

| Layer | Module | Job |
|---|---|---|
| Types | `app/dns/types.py` | `ResultState`, `DnsQuestion`, `DnsRecord`, `DnsResult`, `Resolver` protocol |
| Egress policy | `app/dns/egress.py` | which addresses may be contacted (see below) |
| Backends | `app/dns/backends.py` | dnspython-based UDP/TCP resolver, the only module that touches the network |
| Factory | `app/dns/factory.py` | builds a resolver from `Settings`; untrusted targets go through the policy |
| Cache | `app/dns/cache.py` | TTL-respecting cache wrapper |
| Knowledge | `app/dns/knowledge.py` + `seeds/` | public-resolver list and root hints |
| Trace | `app/dns/trace.py` | root-down delegation walk |
| Services | `app/services/dns_tools.py`, `dns_propagation.py` | lookup, reverse/FCrDNS, propagation |
| API / UI | `app/api/v1/dns_tools.py`, `app/web/dns_tools.py` | REST and server-rendered pages |

## Resolver modes

`RESOLVER_MODE` (default `system`):

- `system`: nameservers read from `resolv.conf`. Trusted; they cannot be policy-checked. If
  `resolv.conf` is unusable every query answers `error` (`no_nameservers`), never "missing".
- `custom`: the nameservers in `RESOLVER_ADDRS` (`ip` or `ip:port`, comma separated). Required.
  Trusted, may be private.
- `unbound`: `RESOLVER_ADDRS` pointing at the bundled Unbound (`172.28.53.2:5353` in the compose
  profile, see `docs/UNBOUND.md`). Sets the EDNS DO bit and reports the AD flag.

## Egress policy (ARCHITECTURE section 7)

- Operator-configured resolvers are trusted.
- Every target derived from request input or DNS data (public-resolver entries, trace
  referral/glue/NS addresses) must be a globally routable unicast IP literal on port 53. A rejected
  target answers `blocked` and no packet is sent. Reasons (`BlockReason`) include private,
  loopback, link-local, documentation, ipv4-mapped and unspecified.
- The tools select resolvers by id only (`default`, `public:<id>`); there are no free-form
  resolver IPs until the guarded client (M7) absorbs this policy.
- Known gap: an operator NAT64 prefix inside `2000::/3` that embeds a private IPv4 is not detected
  (TODO, M7).

## Result states

Every query ends in exactly one `ResultState`. Callers must handle all of them.

| State | Class | Meaning |
|---|---|---|
| `ok` | ok | answer with records |
| `nxdomain` | definitive absence | the name does not exist |
| `nodata` | definitive absence | the name exists, no record of that type |
| `servfail`, `refused`, `timeout`, `truncated`, `malformed`, `network_error`, `blocked`, `error` | failure | could not be evaluated |

Rule: a failure is never reported as absence, anywhere. Results carry `evaluated: false` (API) and
are drawn as "could not be evaluated" with a reason code (UI, `data-kind="failure"`). Aggregates
follow the same rule: a lookup summary lists failed types apart from absent ones; FCrDNS is
`could_not_verify` (never `mismatch`) if any step failed; a trace outcome other than
`ok`/`nxdomain`/`nodata` has state `error`; nxdomain/nodata in a trace count only from an
authoritative (AA) reply, otherwise the outcome is `lame_delegation`; propagation rows that failed
are listed as "not evaluated", belong to no answer group and are not counted. The cache never
stores a failure. If the whole request deadline expires the API still answers 200 with
`state: "timeout"`, `evaluated: false`, `detail_code: "request_deadline"`.

The acceptance tests (`tests/dns/test_acceptance_m2.py`) assert this at each layer.

## Limits and defaults

Backend (M2-05): 2 s per attempt (wire time), 5 s total, 3 attempts (timeout/network only,
rotating nameservers), EDNS 1232, response cap 16384 bytes, 100 records per section, CNAME chain
16, 32 in-flight queries per nameserver. Unparseable UDP datagrams are ignored until timeout;
oversized or malformed TCP responses are `malformed`.

Cache (M2-06): positive TTL = minimum record TTL clamped to 0..3600 s (TTL 0 is not cached),
negative TTL 60 s, 1024 entries (LRU), hits report decremented TTLs, concurrent identical queries
share one lookup. "No cache" bypasses it. Propagation always bypasses it.

Lookup/reverse (M2-08): `ALL` queries A, AAAA, MX, TXT, NS, SOA, CAA, CNAME; concurrency 4;
FCrDNS checks at most 8 PTR names.

Trace (M2-09): depth 16, 64 queries, 4 servers per zone, 15 s total, 16 NS and 32 glue per
referral, 3 glueless NS lookups per zone.

Propagation (M2-10): at most 8 resolvers and 16 addresses per request (every address of an entry
is queried), concurrency 8, 5 s per query, 10 s total, at least 2 evaluated rows for a verdict
(`consistent`, `inconsistent`, else `inconclusive`). No selection means every verified entry.

API/UI: request body at most 64 KiB, per-request deadline 20 s. No per-user rate limiting yet
(TODO).

## Seed data and its verification rule

`seeds/dns_resolvers.yaml` (public resolvers) and `seeds/root_hints.yaml` (root servers) carry
`verified_on` and `sources` (https only). The loader rejects a `verified` entry without both, any
address that fails the untrusted-target policy and any schema deviation. An entry whose
configuration was not confirmed against official documentation must be `status: unverified`: it
is only used when selected explicitly and is marked "unverified" in the API and UI. Never invent
vendor addresses; confirm them against the operator's page and re-verify before release. Root
hints are copied from the IANA/InterNIC `named.root` and diffed against it.

## Routes

REST (JSON body, POST, session cookie + CSRF header), tenant-scoped, permission `dns.tools`
(owner, admin, analyst; never client viewer): `/api/v1/dns/lookup`, `/reverse`, `/trace`,
`/propagation`. Status: 401 anonymous, 404 no active tenant, 403 without permission, 413/415 body,
422 invalid input (codes only, never the input), 200 whenever the query ran.

UI (server-rendered, no JavaScript): `GET /tools/dns` (lookup and reverse forms),
`POST /tools/dns/lookup`, `POST /tools/dns/reverse`, `GET|POST /tools/dns/trace`,
`GET|POST /tools/dns/propagation`. Anonymous GET redirects to `/login`; the nav link appears only
with the permission. Labels exist in en and it for every state and trace outcome.

## Tests and fixtures

Unit tests never open a connection: `tests/dns/conftest.py` makes `connect`, `sendto` and name
resolution fail, and a guard test fails if any module under `app/dns` or `app/services/dns_*.py`
other than `backends.py` imports `socket` or similar. To add a zone, write a hand-made YAML under
`tests/fixtures/zones/` (reserved names and RFC 5737/3849 addresses only) or an inline dict as in
`tests/dns/test_acceptance_m2.py`, and load it with `tests/support/dns_zones.py`; see
`docs/DNS_FIXTURES.md`. A new `ResultState` must be added to the locales (`tools.dns.state.*`, en
and it), the `dns/_result.html` macro and the classification properties; a guard test fails
otherwise.
