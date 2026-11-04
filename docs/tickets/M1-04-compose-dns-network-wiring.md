# M1-04 Compose: app on dns network, resolver env, IPAM gateway pin
Milestone: M1
Branch: feature/m1-04-compose-dns-wiring
Files in scope: compose.yaml, .env.example, docs/UNBOUND.md, tests/test_compose_config.py
Out of scope: the guarded outbound client / SSRF protection (M7), the Resolver abstraction and any DNS query code (M2), changes to docker/unbound/, CI (M1-08)
Depends on: M1-01
Parallel-safe: yes (files disjoint from M1-02, M1-03, M1-05)
Model: sonnet
Acceptance criteria:
- Carry-over "attach app to dns network" (GM decision Q5: always): `app` joins `default` and `dns` (keeps internet access via default). `RESOLVER_MODE` and `RESOLVER_ADDRS` pass through with defaults `system` and empty. `.env.example` and docs/UNBOUND.md document the unbound values `RESOLVER_MODE=unbound`, `RESOLVER_ADDRS=172.28.53.2:5353`.
- In scope for "guarded client target": ONLY the configuration wiring above (env values accepted by M1-01 settings). Explicitly OUT: any code that sends queries, IP-range blocking, pinning, size/time limits (M2 resolver, M7 guarded client).
- Carry-over nit (a): `ipam.config` gets `gateway: 172.28.53.1`, with a comment tying it to the `access-control 172.28.53.1/32 refuse` rule in docker/unbound/unbound.conf (read it and cite the real line; if it differs, report to GM).
- Static pytest (yaml parse, no docker): app is on `dns`; gateway equals 172.28.53.1; unbound ip is 172.28.53.2 and appears in unbound.conf; `dns` is `internal: true`; no `ports:` on unbound.
- `docker compose config` stays valid with no .env and default profile still starts app only (default `docker compose up` unchanged).
- Unverified: whether Docker honours `gateway` with `internal: true` networks on all engines. Mark `unverified`, check locally with `docker network inspect`, report result.
New i18n keys: none
Status: todo
