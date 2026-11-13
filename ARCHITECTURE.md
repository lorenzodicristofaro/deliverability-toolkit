# ARCHITECTURE

## 1. Stack

| Layer | Choice | Reason |
|---|---|---|
| Language | Python 3.12+ | dnspython, stdlib email parser, mature email libs |
| Web/API | FastAPI | one process serves UI and REST API, OpenAPI for free |
| UI | Jinja2 + HTMX + Alpine.js, SSE for streaming | no build step, fast first paint, easy for contributors |
| CSS | Plain CSS with variables (or Pico/Tailwind via CLI), dark mode | no Node toolchain in the image |
| DB | SQLite (default), PostgreSQL (optional) | SQLAlchemy 2.x + Alembic |
| Jobs | APScheduler in the same process; separate worker mode via env flag | simple by default, scalable later |
| DNS | dnspython, async, pluggable resolver | local Unbound recommended |
| Auth | argon2-cffi, signed session cookies, TOTP (pyotp) | |
| Packaging | One multi-arch image; `compose.yaml` with optional `unbound` and `postgres` profiles | |
| Tooling | uv, ruff, mypy, pytest, pre-commit | |

## 2. Repository layout

```
/app
  /core            config, logging, security, tenancy, i18n, http_guard
  /dns             resolver abstraction, cache, trace, dnssec helpers
  /checks          one module per check, each implements the Check interface
    spf.py dkim.py dmarc.py bimi.py mta_sts.py tls_rpt.py dane.py
    blacklist.py smtp.py content.py headers.py esp_profile.py custom.py
  /parsers         spf, dmarc, dkim record, eml/original, dmarc_xml
  /integrations    postmaster.py snds.py imap_reports.py notifiers/
  /models          SQLAlchemy models
  /repositories    tenant-scoped data access (the ONLY place that queries tenant data)
  /services        orchestration: run_check, schedule, alerts, reports
  /api             REST routers (v1), API keys, OpenAPI
  /web             UI routers, templates, static, SSE endpoints
  /cli             Typer-based CLI
/profiles/esp      YAML ESP profiles (schema validated)
/seeds             seed data (versioned): dkim_selectors.yaml, content_rules.yaml, dnsbl.yaml,
                   provider_requirements.yaml, dns_resolvers.yaml, root_hints.yaml;
                   shipped in the image at /app/seeds
/migrations        Alembic
/tests             unit, integration, tenancy, e2e
/docs
```

## 3. The Check interface

Every check is a pure-ish async function with a stable result schema, so UI,
API, CLI, scheduler and alerts all consume the same thing.

```python
class Check(Protocol):
    id: str                       # "spf", "dkim", "dmarc", ...
    async def run(self, ctx: CheckContext, target: Target) -> CheckResult: ...

class CheckResult(BaseModel):
    check_id: str
    target: str
    status: Literal["ok", "warn", "fail", "info", "error"]  # error = could not evaluate
    findings: list[Finding]       # ordered by severity
    data: dict                    # structured raw data (parsed record, lookups, ...)
    started_at: datetime
    duration_ms: int

class Finding(BaseModel):
    code: str                     # stable, e.g. "SPF_TOO_MANY_LOOKUPS"
    severity: Literal["critical", "high", "medium", "low", "info"]
    title_key: str                # i18n keys, never hardcoded strings
    detail_key: str
    remediation_key: str | None
    params: dict                  # values interpolated into the translations
    evidence: list[str]           # record text, hostnames, etc.
    docs_url: str | None
```

Rules:
- "Could not evaluate" (timeout, SERVFAIL, refused) is `error`, never `ok`.
- Finding codes are stable public identifiers (used by alerts, API, tests).
- Checks never touch the DB directly; the service layer stores results.
- Custom checks are DNS kinds only in M5 (`dns_exists`, `dns_matches`, `dns_value_range`);
  `http_fetch` is a reserved kind refused by schema and evaluator until M7, where it goes through
  the guarded client. The definition schema is `app/core/custom_check_schema.py`, so repositories
  validate every write without depending on `/checks`; the evaluator is `app/checks/custom.py`.
  An `all` domain run (built in `app/api/v1/checks.py`) runs the built-ins first, then the enabled
  global and own-tenant custom checks, read through the tenant repository; ids are
  `custom:<scope>:<key>`. All custom checks of one run share a 12 s budget (under the 15 s API
  deadline); a check with no budget left, or past the 50th, is `error`, never `ok`.

## 4. Multi-tenancy

Model:
```
Tenant 1—N Membership N—1 User
Tenant 1—N Domain
Membership has role; DomainAccess(membership, domain) restricts client viewers
Tenant 1—N CustomRule / CustomSelector / CustomCheck / ESPProfileOverride
Tenant 1—N ApiKey, ShareLink, Integration, AlertChannel
Global rows (tenant_id NULL): selectors, rules, DNSBL list, ESP profiles
```
ESP profiles: `ESPProfileOverride` is deferred beyond M6; M6 reads profiles from YAML only.

Isolation strategy (defense in depth):
1. Every tenant-owned table has a non-null `tenant_id`.
2. All access goes through `/repositories`, constructed with a `TenantContext`
   that injects `tenant_id` into every query. Routers and services never receive
   a raw session for tenant data.
3. A permission layer (`can(user, action, resource)`) evaluates role, domain
   access and per-user feature toggles; used by web, API and CLI alike. CLI commands
   that use tenant data go through `app/cli/tenant_scope.py` (`--tenant-id`, `--user-id`):
   these options select who the command acts as and are not authentication, so the CLI's
   trust boundary remains shell access. `check` and `analyze` stay tenant-less and offline.
4. PostgreSQL deployments may additionally enable row-level security.
5. Mandatory automated tests: for each endpoint, a user from tenant A must get
   404 on tenant B resources; a client viewer must not see unassigned domains.
6. The instance admin manages tenants and instance settings but has NO access to
   tenant data (domains, results, reports) through the admin flag alone. With a
   membership in a tenant they see that tenant's data exactly as their membership
   role and domain access allow, like any other member; the admin flag neither
   adds nor removes anything there (maintainer decision 2026-11-04). Audited impersonation may be
   evaluated later; it is not planned.
7. Deletes: deleting a tenant cascades to its memberships, domains and domain access
   (deliberate admin action). Users are never hard-deleted while they hold memberships
   (FK RESTRICT); they are deactivated with `is_active = false`. Cross-tenant
   `domain_access` rows are impossible by composite FKs on (id, tenant_id) (M1-10).

## 5. Data model (core tables)

`users`, `tenants`, `memberships`, `domain_access`, `domains`, `domain_esps`,
`ips`, `check_runs`, `check_results` (domain/ip, check_id, status, findings JSON,
data JSON, timestamps), `dns_snapshots` (for diffing), `dkim_selectors`
(scope global/tenant), `content_rules`, `custom_checks`, `esp_profiles`
(cached from YAML + overrides), `dmarc_reports`, `dmarc_report_rows`,
`integrations` (encrypted credentials), `alert_channels`, `alert_rules`,
`alerts`, `api_keys`, `share_links`, `audit_log`, `settings`.
The `esp_profiles` table is deferred beyond M6: M6 stores only `domain_esps`, profiles come
from `profiles/esp/*.yaml`.
`domain_esps` (M6-02): one row per (domain, ESP), composite FK (domain_id, tenant_id) to
`domains` like `domain_access`, cascade from domain and tenant, at most 10 per domain
(soft cap, checked by count). `esp_id` is a slug with no FK; the service checks it names a
loaded profile. Optional `return_path_host` / `tracking_host` must be the domain or a
subdomain of it. `DomainEspRepository.add` is idempotent and never changes stored hosts
(use `update_hosts`).

Retention: raw `check_results` are pruned by configurable policy; aggregates
and DNS snapshots are kept longer.

## 6. Execution model

- Interactive checks: request starts the check, the UI subscribes to an SSE
  stream; each sub-check (SPF, then DKIM selectors in parallel, then DNSBLs)
  emits an HTML fragment as soon as it is ready.
- Scheduled checks: APScheduler enqueues per-domain jobs with jitter, a global
  concurrency semaphore and per-target rate limits (DNSBLs punish bursts).
- DKIM probing: bounded concurrency, negative-result caching, early stop not
  allowed (all selectors are probed) but results stream.
- Optional worker mode: `ROLE=web|worker|all`, all state in the DB, so scaling
  later means pointing several workers at PostgreSQL.
- Migrations are safe to run from several containers started together: on
  PostgreSQL, `migrations/env.py` holds a session-level advisory lock
  (`MIGRATION_LOCK_KEY`) for the whole upgrade, so the first replica migrates and
  the others wait (no lock timeout) and then find the schema already at head.
  SQLite takes no lock (single container).
- Startup ordering (PostgreSQL profile): before taking the migration advisory lock,
  `migrations/env.py` waits for the database for at most 60 s (backoff 0.5 s doubling
  to a 4 s cap). It retries only connection refused and the server's starting-up
  rejection (57P03, matched on the libpq message because psycopg reports connect
  errors without a SQLSTATE). Authentication, unknown-database and DNS errors fail at
  once; after the bound the original error ends the process and
  `restart: unless-stopped` applies. SQLite and injected connections skip the wait.

## 7. DNS layer

- Interface `Resolver` with implementations: system, custom nameservers,
  DoH (optional). Unbound is bundled as an optional compose profile (`unbound`):
  our own Debian-slim image, recursive from the root with DNSSEC, reachable only on
  the compose network (see docs/UNBOUND.md for the maintenance rule).
- Per-query timeout, retry policy, TTL-aware cache, response size caps.
- Distinguish NXDOMAIN, NODATA, SERVFAIL, timeout, REFUSED explicitly in the
  result type; checks must handle each.
- DNS egress before the M7 guarded client (GM decision 2026-11-05, `app/dns/egress.py`):
  operator-configured resolvers (`RESOLVER_ADDRS`; resolv.conf nameservers in `system` mode,
  which cannot be policy-checked) are trusted and may be private. Every target derived from
  request input or DNS data (public-resolver list entries, trace referral/glue/NS addresses)
  must be a globally routable unicast IP literal on port 53; a blocked target yields
  `ResultState.blocked`, never "missing". The DNS tool selects resolvers by id only
  (configured + `seeds/dns_resolvers.yaml`); free-form resolver IPs are deferred to M7.
  For HTTP the guarded client (section 9, M7-01) now applies the same classification,
  `address_reason`, to every resolved or literal address; the DNS tool itself is unchanged.
- Raw DNS tools require the `dns.tools` permission: owner, admin, analyst; never client
  viewer (not grantable by toggle); no anonymous access.
- Running checks on a tenant domain requires `check.run` (GM decision 2026-11-06, M3-14):
  owner, admin, analyst on all domains; client viewer on assigned domains only; deniable
  per user by toggle. Tenant-less free checks (API/SSE) reuse `dns.tools`; the CLI `check`
  is tenant-less with no DB access (trust boundary: shell access). M3 stores no results.
- Offline message/header analysis requires `message.analyze` (GM decision 2026-11-07, M4-06):
  tenant-level, owner, admin, analyst; never client viewer; deniable per user by toggle and
  independent of `dns.tools`/`check.run`. The analyzer does no DNS/network and M4 stores nothing.
- DNSBL lookups must detect "refused/blocked" return codes (e.g. 127.255.255.x
  conventions) and report them as `error`, not `listed`.

## 8. ESP profiles

One YAML file per ESP in `profiles/esp/<id>.yaml`, loaded by `app/esp/profile.py` (M6-01).
The hand-written strict loader IS the schema (no JSON Schema): unknown keys, duplicate YAML
keys, anchors/aliases and merge keys are rejected, each file is size-capped, and the directory
load is all-or-nothing. Shape (fake example):

```yaml
id: example-esp                  # slug [a-z0-9][a-z0-9-]{0,39}, equal to the file name
name: Example ESP
homepage: https://esp.example.com
spf:
  includes: ["spf.esp.example.com"]
  only_if_record: false          # optional (M6-17): true = includes expected only if an SPF record exists
dkim:
  selectors:
    - { name: s1, type: cname, target_pattern: "s1.dkim.*.esp.example.com" }
    - { name: k1, type: txt }
  alternatives:                  # optional (M6-23): DKIM ok if `selectors` OR one set is fully present
    - [{ name: k0, type: txt }]  # never used for detection; alternative txt must be a valid key
return_path: { type: cname, optional: false, notes_key: esp.example_esp.return_path }
tracking_domain: { type: cname, optional: true }
pitfalls:                        # static advisory entries; no `when:` conditions
  - { code: ESP_EXAMPLE_ESP_LINK_BRANDING_MISSING, notes_key: esp.example_esp.link, severity: low }
verified_on: 2026-11-02
sources: ["<official doc URL>"]
status: verified                 # unverified requires unverified_fields
# unverified_fields: [return_path, dkim.selectors.s1]   # skipped by checks
```

`target_pattern` is a restricted glob (a `*` label matches exactly one DNS label, last two
labels literal), never a regex and never evaluated as code. Pitfalls carry no condition (GM
decision 2026-11-10: no expression evaluation of data).

Every profile carries `verified_on` and official `sources`. CI validation is
`tests/esp/test_shipped_profiles.py` in the normal pytest jobs: it loads the shipped profiles
with the strict loader, checks their notes keys exist in en and it, and warns (does not fail)
when a profile is older than 12 months.

## 9. Security

- Guarded outbound HTTP client (M7-01, decision record). `app/net/guarded_http.py` `fetch()` is
  the only way `app/` makes HTTP requests; only `app/net/` may import an HTTP library (`httpx2`),
  enforced by a test that parses every module under `app/` (no exceptions today). It returns a
  `FetchResult` (final URL, status, allowlisted response headers, capped body, `truncated`,
  hop list) or a `FetchError` with a closed kind: `blocked`, `dns_error`, `timeout`,
  `too_large`, `too_many_redirects`, `scheme_not_allowed`, `port_not_allowed`, `tls_error`,
  `connect_error`, `protocol_error`, plus a stable `detail` code and the hop number. Callers map
  every kind to Check `error`; there is no "not found means ok" path. Caller bugs (unknown
  method, request header outside the allowlist, body on GET/HEAD) raise `ValueError`.
  - The client absorbs the DNS egress policy for HTTP: addresses are classified by
    `app.dns.egress.address_reason` (IANA special-purpose registries, retrieved 2026-11-05), not
    a second list. Blocked: unspecified, "this network", loopback, private (RFC 1918, ULA
    `fc00::/7`), CGNAT, link-local (incl.
    `169.254.169.254`), protocol assignments, documentation, benchmarking, reserved, broadcast,
    multicast, IPv4-mapped, 6to4/NAT64 embedding a blocked IPv4, local-use NAT64, Teredo, and
    anything outside `2000::/3`.
  - Per hop (first request and every redirect): scheme `http`/`https`; port in
    `OUTBOUND_HTTP_ALLOWED_PORTS`; no userinfo (`@`), whitespace, control characters or
    backslash; host normalised by `app/core/domain_names.py` `to_ascii_domain` (IDNA 2008, 253/63
    limits, trailing dot removed, all-numeric last label refused, so decimal/octal/hex/short IPv4
    spellings never reach a resolver); IP literals (strict dotted quad, bracketed IPv6, no zone
    id) are classified directly. Names are resolved through the project resolver (A then AAAA,
    once each), never the OS resolver. ANY blocked answer refuses the request (no "pick the good
    one"); any resolution failure other than NXDOMAIN/NODATA, or no address at all, is
    `dns_error`.
  - Pinning: the request URL carries the first validated address (IPv4 first; no fallback to the
    others), the `Host` header carries the original host, and httpx2's documented
    `sni_hostname` request extension makes TLS SNI and certificate hostname verification use the
    original host (httpcore2 passes it as `server_hostname` to the TLS handshake). No custom
    transport is needed. No second lookup happens between check and connect (rebinding test).
    Each hop uses a fresh transport with one connection and no keep-alive, so a TLS connection
    opened for one name is never reused for another.
  - No ambient configuration: the transport is used directly (no `httpx2.Client`), built with
    `trust_env=False` and no proxy, so `HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`, netrc,
    `SSL_CERT_FILE`/`SSL_CERT_DIR` and cookie jars are never used. TLS verification is always on.
  - Redirects (301, 302, 303, 307, 308) are followed manually for GET/HEAD; POST (alert webhooks)
    does not follow unless asked (then 307/308 keep POST and the body, 301/302/303 become GET).
    Relative `Location` is resolved against the current URL; a missing, oversize or unparsable
    `Location` is `protocol_error`; https -> http is refused (`scheme_not_allowed`,
    `https_downgrade`); a revisited URL is `too_many_redirects` (`loop`). `Authorization` is
    dropped when scheme, host or port changes; `Cookie`, `Host`, `Proxy-*` and `Accept-Encoding`
    can never be set by callers.
  - Decompression bombs: `Accept-Encoding: identity` is sent and any other `Content-Encoding` is
    refused (`protocol_error`); the raw stream is read, nothing is decoded.

  | Limit | Default | Where |
  |---|---|---|
  | Allowed ports | 80, 443 | `OUTBOUND_HTTP_ALLOWED_PORTS` |
  | Redirects | 3 (hard max 5) | `OUTBOUND_HTTP_MAX_REDIRECTS` |
  | Connect timeout | 5 s | `FetchLimits.connect_timeout` |
  | Read/write timeout | 10 s per read | `FetchLimits.read_timeout` |
  | Total deadline | 20 s, DNS and all hops | `FetchLimits.total_timeout` |
  | Response body | 1 MiB, counted while streaming; over it: `too_large` or, if asked, truncated | `FetchLimits.max_body_bytes` |
  | POST body | 64 KiB | `FetchLimits.max_request_body_bytes` |
  | Response headers | 100 fields, 16 KiB names + values (httpcore2 also caps the raw header block at 100 KiB) | `FetchLimits.max_header_count`, `max_header_bytes` |
  | URL length | 2048 characters | `policy.MAX_URL_LENGTH` |

  All defaults are project choices, not vendor facts.
  - Test seam: `guarded_http._fetch` takes a transport factory and an address classifier;
    `fetch()` always passes the real transport and `address_reason`, and no setting reaches
    them. Unit tests (`tests/net`) use a scripted resolver and `httpx2.MockTransport`; the
    end-to-end tests use a server bound to 127.0.0.1 inside the test with the loopback block
    bypassed through the seam. Sockets to anything but loopback fail those tests.
  - SMTP: separate ticket, same policy.
- Input validation of domains/IPs (IDNA, length, label rules) at the edge.
- Regex rules run through `app/core/safe_regex.py` (M5-03): `search_many` runs all
  rules for one text in one worker subprocess with a per-rule deadline; a rule that
  times out gets its worker killed (SIGKILL) and a fresh worker runs the rest. Caps on
  pattern length, text size, matches, per-rule timeout, rules per call, overall call
  time, and live workers per process (bounded wait, then `busy`, never an unbounded queue). Not a thread (cannot be stopped) and not the
  `regex` module timeout (its docs do not say when the deadline is checked).
- Uploaded `.eml` files and DMARC XML: size caps, zip-bomb protection, defusedxml.
- Secrets encrypted with a key from env/file (Fernet or libsodium), rotation path documented.
- CSRF protection for the UI, strict security headers (CSP without inline scripts),
  secure cookies, login throttling, TOTP, session revocation.
- HTML from user content (email bodies) is always rendered escaped or in a
  sandboxed iframe with no scripts.
- Audit log is append-only from the app's perspective.

## 10. i18n

Message keys only in findings and templates; `locales/en.json`, `locales/it.json`;
missing-key test in CI; user and tenant language preference.

## 11. Configuration (env)

`DATABASE_URL` (default `sqlite:////data/app.db`), `SECRET_KEY`,
`ENCRYPTION_KEY`, `RESOLVER_MODE` (`system|custom|unbound`), `RESOLVER_ADDRS` (comma-separated `host:port`,
IP literals, IPv6 as `[::1]:5353`, default port 53),
`ROLE`, `ALLOW_SMTP_CHECKS` (default false), `ALLOW_REGISTRATION` (default false),
`BASE_URL`, `SMTP_*` for notifications, `LOG_LEVEL`,
`SESSION_IDLE_TIMEOUT_MINUTES` (default 30) and `SESSION_ABSOLUTE_TIMEOUT_MINUTES`
(default 720 = 12 h): both must be > 0 and idle <= absolute, otherwise startup fails.
`TRUSTED_PROXIES` (R1-30; comma-separated IPv4/IPv6 addresses or CIDR networks, default empty):
only a direct peer inside it may set the client IP via `X-Forwarded-For` (rightmost hop that is
not a trusted proxy; `Forwarded` is not read); empty means the direct peer is the client IP.
An invalid entry fails startup. uvicorn's own proxy-header rewriting is off in the image
(`--no-proxy-headers`). Deployment details: docs/SETUP.md section 7.

## 12. Observability

Structured JSON logs, `/healthz` and `/readyz`, optional Prometheus `/metrics`
(off by default, guarded), per-check duration metrics.

## 13. Testing strategy

- Parsers: table-driven tests with real-world and malformed records.
- Checks: a fake resolver fixture with recorded DNS zones; no network in unit tests.
- Tenancy and permissions: generated test matrix over endpoints and roles.
- E2E: Playwright smoke tests on the main flows.
- CI: ruff, mypy, pytest on SQLite and PostgreSQL, image build for amd64/arm64.
