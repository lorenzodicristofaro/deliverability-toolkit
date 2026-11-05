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
- [ ] Resolver abstraction (system / custom / Unbound), cache, timeouts, explicit result states
- [ ] Free DNS tool: all record types, trace, reverse, propagation across resolvers
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
  - [ ] M2-12 REST endpoints
  - [ ] M2-13 UI lookup/reverse
  - [ ] M2-14 UI trace/propagation
  - [ ] M2-15 acceptance tests + docs/DNS.md
- Accept: tests pass against recorded zones; SERVFAIL/timeout never reported as "record missing".

## M3 — SPF, DKIM, DMARC
- [ ] Parsers + checks with Finding codes, remediation texts (en/it)
- [ ] SPF recursive resolution, lookup/void counts, flattening hints
- [ ] DKIM selector probe with seeded selector list, streaming results via SSE
- [ ] DMARC incl. external report authorization
- [ ] Domain page "Authentication" tab, CLI `check` command, REST endpoints
- Accept: results identical across UI, API and CLI; table-driven tests with malformed records.

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
- [ ] M7: DNS egress cannot detect an operator NAT64 prefix inside 2000::/3 embedding a private IPv4 (app/dns/egress.py); handle in the guarded client
- [ ] Per-user rate limiting for free tools (DNS trace/propagation); M2 has per-request caps only
- [ ] Seed staleness: a host clock behind a seed `verified_on` makes the knowledge loader raise at runtime; consider a tolerance (M2-07 QA nit)
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
- [ ] HTMX under CSP `script-src 'self'` is unverified, maintainer to confirm against https://htmx.org/docs/ (set includeIndicatorStyles=false and allowEval=false when vendored)
