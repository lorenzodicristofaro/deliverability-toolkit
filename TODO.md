# TODO / Roadmap

Rule: finish one milestone (code + tests + docs + commit) before starting the next.
Mark items `[x]` when done. Acceptance criteria are the definition of done.

## M0 — Project setup
- [x] Repo, AGPL-3.0 LICENSE, README stub, CONTRIBUTING (DCO), CODE_OF_CONDUCT
- [x] uv project, ruff, mypy, pytest, pre-commit, GitHub Actions CI
- [x] Dockerfile (multi-arch) + compose.yaml with optional `unbound` / `postgres` profiles
- [x] M0-07 own Unbound image — REWORK round 2 (maintainer 2026-11-04): KSK-2024 anchor test + persistent root.key volume, AD healthcheck, port 5353 + RESOLVER_ADDRS host:port, config audit, integration tests, arm64, hardening (round 1 merged into dev, QA APPROVE)
- [x] M0-09 Unbound hardening nits — superseded, folded into M0-07 round 2
- Accept: `docker compose up` serves a health page; CI green.
  Status: **accepted 2026-11-04** — `/healthz` 200 via compose (local), CI green on GitHub at 3f2db2b (incl. integration-unbound, unbound-arm64-smoke). Report: docs/reports/M0.md

## M1 — Core platform (auth + multi-tenancy skeleton)
Carried over from M0-07 QA:
- [x] Attach app to the `dns` network and point the guarded client at 172.28.53.2 (M1-04: config wiring; query code is M2, SSRF client M7)
- [x] CI runtime check of the `unbound` profile (M1-08: coverage mapped in docs/tickets/M1-08, app→unbound test added) (up, healthy, AD flag, port 5353 unpublished) — largely covered by M0-07 r2 CI jobs; reconcile
- [x] M0-07 QA nits (small) (M1-04 gateway + ip_range, M1-05 mDNS probe): (a) pin `gateway: 172.28.53.1` in compose.yaml IPAM so the `access-control 172.28.53.1/32 refuse` rule is explicitly tied; (b) host-side test probe on 127.0.0.1:5353 may false-fail on hosts with an mDNS responder (avahi): use another probe or skip/handle
- [x] Config, logging, DB, Alembic migrations (SQLite + PostgreSQL) (M1-01..03, M1-06, M1-07; PG in CI)
- [x] Users, tenants, memberships, roles, permission layer `can()`
- [x] Login (argon2), sessions, CSRF, first-run setup wizard (creates instance admin)
- [x] Tenant-scoped repositories + tenancy test matrix
- [x] Domain CRUD, tenant landing page, i18n (en/it) scaffolding, dark mode
- Accept: user from tenant A cannot read tenant B data (tests prove it); client viewer limited to assigned domains.
  Status: **accepted 2026-11-05** — tenancy matrix + named acceptance tests (tests/tenancy/test_acceptance_m1.py). CI green at d2e5e4a incl. PostgreSQL (4393 passed). Report: docs/reports/M1.md

## M2 — DNS engine
- [x] Resolver abstraction (system / custom / Unbound), cache, timeouts, explicit result states
- [x] Free DNS tool: all record types, trace, reverse, propagation across resolvers
- Tickets (docs/tickets/):
  - [x] M2-01 trim whitespace in `to_ascii_domain` + DNS record-name validator (underscores) — also closes the post-M1 follow-up
  - [x] M2-02 result states + Resolver protocol
  - [x] M2-03 DNS egress policy (opus; decided by GM 2026-11-05, ARCHITECTURE section 7)
  - [x] M2-04 recorded-zone fixtures + fake resolver
  - [x] M2-05 backends system/custom/Unbound (dnspython dependency, opus)
  - [x] M2-06 TTL cache
  - [x] M2-07 public resolver list + root hints data files (unverified entries flagged)
  - [x] M2-08 lookup + reverse service
  - [x] M2-09 trace (opus)
  - [x] M2-10 propagation
  - [x] M2-11 `dns.tools` permission (opus)
  - [x] M2-12 REST endpoints
  - [x] M2-13 UI lookup/reverse
  - [x] M2-14 UI trace/propagation
  - [x] M2-15 acceptance tests + docs/DNS.md
- Accept: tests pass against recorded zones; SERVFAIL/timeout never reported as "record missing".
  Status: **accepted 2026-11-06** — tests/dns/test_acceptance_m2.py; CI green at 8083cc5 incl. PostgreSQL (6577 passed). Report: docs/reports/M2.md

## M3 — SPF, DKIM, DMARC
- [x] Parsers + checks with Finding codes, remediation texts (en/it)
- [x] SPF recursive resolution, lookup/void counts, flattening hints
- [x] DKIM selector probe with seeded selector list, streaming results via SSE
- [x] DMARC incl. external report authorization
- [x] Domain page "Authentication" tab, CLI `check` command, REST endpoints
- Tickets (docs/tickets/):
  - [x] M3-01 Check interface + CheckResult/Finding models
  - [x] M3-02 check registry + runner service
  - [x] M3-03 TXT/CNAME fetch helper
  - [x] M3-04 SPF parser (opus)
  - [x] M3-05 DMARC parser (opus)
  - [x] M3-06 DKIM key record parser (opus)
  - [x] M3-07 SPF recursive resolution engine (opus)
  - [x] M3-08 SPF check: findings, flattening hints (opus)
  - [x] M3-09 organizational domain helper (public suffix source unverified)
  - [x] M3-10 DMARC check + org-domain fallback
  - [x] M3-11 DMARC external report authorization (opus)
  - [x] M3-12 DKIM selector seed + loader (unverified entries flagged)
  - [x] M3-13 DKIM probe engine + check
  - [x] M3-14 `check.run` permission (opus)
  - [x] M3-15 checks REST endpoints
  - [x] M3-16 DKIM SSE stream
  - [x] M3-17 Authentication tab UI
  - [x] M3-18 CLI `check` command (tenant-less free check)
  - [x] M3-19 acceptance tests + docs/CHECKS.md
  - [x] M3-20 DKIM seed: provider selectors and selector→provider mapping (post-acceptance follow-up, requested by maintainer 2026-11-06)
- Accept: results identical across UI, API and CLI; table-driven tests with malformed records.
  Status: **accepted 2026-11-06** — tests/checks/test_acceptance_m3.py (service = API = CLI byte-equal, UI status/codes equal, DNS failure → error on all surfaces, zero DNS on denial); CI green at 0e3511a incl. PostgreSQL (9434 passed). Report: docs/reports/M3.md

## M4 — Original (headers) analyzer
- [ ] Upload/paste `.eml` or headers; Received chain with delays; Authentication-Results; ARC
- [ ] Alignment analysis (From / Return-Path / DKIM d=), anomaly findings, MIME summary
- Accept: sample corpus (Gmail, Outlook, SES, SendGrid, MailUp...) parsed correctly.

## M5 — Content analyzer + admin rules
- [ ] Structural HTML/text checks, link analysis, size, List-Unsubscribe/One-Click
- [ ] `content_rules` in DB with seed, weights, categories, language
- [ ] Admin UI: global vs tenant rules, DKIM selectors, "test on sample" with ReDoS guard
- [ ] Declarative custom checks (DNS/HTTP) with severity and remediation text
- Accept: rules editable without redeploy; regex timeout enforced by test.

## M6 — ESP profiles
- [ ] YAML schema + CI validation, loader, per-domain ESP assignment
- [ ] Profile checks (SPF include, DKIM CNAMEs, return-path, tracking domain)
- [ ] Initial profiles verified against official docs, incl. MailUp/TeamSystem and other Italian ESPs
- [ ] Contributor guide for adding a profile
- Accept: each profile has `verified_on` + sources; sample domains produce expected findings.

## M7 — Monitoring
- [ ] Guarded outbound client (SSRF protection) + tests
- [ ] DNSBL/URIBL engine with refusal detection, `dnsbl.yaml` seed
- [ ] Scheduler, history, DNS snapshots + diff, trend charts
- [ ] Alerts: email, webhook, Slack/Teams
- Accept: scheduled runs respect rate limits; changes produce alerts exactly once.

## M8 — DMARC aggregate reports
- [ ] IMAP ingestion + HTTP endpoint, safe XML/zip/gz parsing
- [ ] Dashboard by source / disposition / alignment, unknown sender detection
- Accept: real-world report samples parsed; zip-bomb and XXE tests pass.

## M9 — Integrations and extra records
- [ ] Google Postmaster Tools (OAuth, per domain) — verify current API first
- [ ] Microsoft SNDS — verify current access method first
- [ ] BIMI (SVG Tiny-PS + VMC/CMC), MTA-STS, TLS-RPT, DANE, DNSSEC view
- [ ] Provider requirements checklist (Gmail/Yahoo/Microsoft) as dated data
- [ ] Optional SMTP module (off by default)

## M10 — Multi-tenant polish and release
- [ ] Share links, tenant branding, PDF/CSV/JSON export, audit log UI, TOTP, API keys
- [ ] Docs site, OpenAPI, install guides (Docker, Unraid/Synology/Proxmox notes), screenshots
- [ ] Security review checklist, dependency/license audit, v0.1.0 release

## Follow-ups (post-M1)
- [ ] Extend the tests/dns network guard (loopback-only) to the DNS tests in tests/api and tests/web (M2-15 QA)
- [ ] Import guard: forbid network calls via dns.resolver in app/dns/factory.py (it may only read resolv.conf) (M2-15 QA nit)
- [ ] Use a translated label for the FCrDNS no_ptr case instead of omitting the line (M2-13 QA nit)
- [ ] Global cap on concurrent DNS tool requests (per-request caps only in M2-12); pair with the per-user rate limit
- [ ] M7: DNS egress cannot detect an operator NAT64 prefix inside 2000::/3 embedding a private IPv4 (app/dns/egress.py); handle in the guarded client
- [ ] Per-user rate limiting for free tools (DNS trace/propagation); M2 has per-request caps only
- [ ] Seed staleness: a host clock behind a seed `verified_on` makes the knowledge loader raise at runtime; consider a tolerance (M2-07 QA nit)
- [ ] Shared result-list serializer in app/services/checks.py, used by API and CLI (now duplicated one-liners) (M3-18).
- [ ] CLI catches private typer._click UsageError (no public equivalent in typer 0.28); pin typer<0.29 or add a guard test (M3-18 QA).
- [ ] Tenancy matrix filler sends a literal {check_id}; substitute `spf` (M3-15 QA nit).
- [ ] DKIM_TEST_MODE text 'Some receivers treat such signatures differently' is unsourced; cite RFC 6376 3.6.1 t=y or soften (M3-13 QA nit).
- [ ] DMARC external: an unparseable record next to a valid one also emits a low AUTH_RECORD_INVALID (M3-11 QA nit, acceptable).
- [x] (M2-01) Domain names: trim surrounding whitespace in `to_ascii_domain` instead of rejecting it (maintainer decision 2026-11-05); update the M1-18 tests. Underscores stay rejected for tenant domains, but the M2 DNS tool must accept them in record names.
- [ ] Public `security.mac(label, msg, key)` helper, to replace csrf.py's import of private helpers
- [ ] CSRF exemption for future bearer-token API routes
- [ ] Throttle the `last_seen_at` write in resolve_session
- [ ] DB-backed login throttle for multi-process deployments
- [ ] Per-IP cap on throttle keys, plus a warning log when the table is full (a single IP can fill the table with locked keys and block new logins)
- [ ] Trusted-proxy setting for the client IP (needed before any reverse-proxy deployment)
- [ ] `services.auth.rotate_session` helper (`_switch` reads the sessions row directly)
- [ ] Dispose of the DB engine at shutdown via the lifespan
- [ ] A breached-password corpus check, offline
- [ ] MAINTAINER TO CONFIRM before the public release: the terms of the original xato.net dataset behind the SecLists password list are unverified
- [ ] A TenantMembershipRepository.create() helper (setup uses memberships.add(model(...)))
- [ ] NFC normalisation of email and password (login and setup together)
- [ ] A dedicated permission action for domain access management, replacing the USER_MANAGE+DOMAIN_UPDATE combination on PUT /domains/{id}/access
- [ ] Landing pagination (the landing caps at 1000 domains)
- [ ] Mixed-script heuristic false positives (U+00B7 Catalan middle dot, U+02BC, ZWJ) and possible false negatives for scripts sharing a first word in the unicodedata name: use Script_Extensions data
- [ ] Move `mixed_script` to app/core/domain_names.py
- [ ] app/services/domains.py hardcodes MembershipRole.CLIENT_VIEWER in list and set_access; use is_domain_restricted
- [ ] The matrix guard's create_app() uses env settings, not world.settings (QA nit)
- [ ] app/checks/dkim_selectors.py imports private validation helpers from app/dns/knowledge.py and app/dns/types.py; expose a public seed-validation helper (M3-12 QA)
- [x] (M3-20) DKIM seed selectors: provider selectors verified on raw official pages (Microsoft 365, Google Workspace, SendGrid, Mandrill, Klaviyo, MailUp, ActiveCampaign); per-customer (SES, Mailgun, SparkPost, Zoho, Brevo) not seeded; still unverified generic: default, dkim, mail, k1
- [ ] DKIM seed: per-entry `verified_on` (file-level date only; M3-20b entries verified 2026-11-07 noted in a comment)
- [ ] DKIM seed: Mailchimp campaigns, Postmark, HubSpot selectors not found in official docs; add if the maintainer supplies an official source
- [ ] Optional: add an explicit `evaluated` field to CheckResult if the runner-only convention proves insufficient (M3-01 QA)
- [ ] MAINTAINER TO CONFIRM: Public Suffix List data licence (MPL-2.0 per the PyPI publicsuffixlist page only); check github.com/publicsuffix/list LICENSE; recorded as unverified in seeds/public_suffix_source.yaml (M3-09)
- [ ] SPF parser nits (M3-04 QA): at the 4096-char cut, drop the partial last term so it does not add a second misleading issue; add a comment on Unicode-whitespace term splitting
- [ ] DMARC parser: reject a `!size` whose value after the unit (number*unit) exceeds 64 bits (M3-05 QA).
- [ ] Move the no-network socket guard from tests/dns/conftest.py to tests/conftest.py so tests/checks need no cross-package import (M3-07 QA).
- [ ] spf_tree.py:319 per-term `valid` filter is dead code; remove or assert (M3-07 QA nit).
- [ ] DKIM parser: optionally reject base64 with non-zero padding bits (M3-06 QA nit).
- [ ] HTMX under CSP `script-src 'self'` is unverified, maintainer to confirm against https://htmx.org/docs/ (set includeIndicatorStyles=false and allowEval=false when vendored)
- [ ] Authentication tab: catch InvalidTarget from run_checks and render the error page instead of a 500 (M3-17 QA nit)
- [ ] _result.html uses class dns-state-absent for warn/fail/info; use a neutral per-status class (M3-17 QA nit)
