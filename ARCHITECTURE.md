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
  (configured + `seeds/dns_resolvers.yaml`); free-form resolver IPs are deferred to M7,
  which will absorb this policy into the guarded client.
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

- Guarded outbound client (HTTP and SMTP): resolve first, reject loopback,
  private, link-local, CGNAT and cloud metadata ranges, pin the resolved IP
  to avoid DNS rebinding, enforce size/time limits, restrict redirects.
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

## 12. Observability

Structured JSON logs, `/healthz` and `/readyz`, optional Prometheus `/metrics`
(off by default, guarded), per-check duration metrics.

## 13. Testing strategy

- Parsers: table-driven tests with real-world and malformed records.
- Checks: a fake resolver fixture with recorded DNS zones; no network in unit tests.
- Tenancy and permissions: generated test matrix over endpoints and roles.
- E2E: Playwright smoke tests on the main flows.
- CI: ruff, mypy, pytest on SQLite and PostgreSQL, image build for amd64/arm64.
