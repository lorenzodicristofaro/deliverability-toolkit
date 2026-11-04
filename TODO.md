# TODO / Roadmap

Rule: finish one milestone (code + tests + docs + commit) before starting the next.
Mark items `[x]` when done. Acceptance criteria are the definition of done.

## M0 — Project setup
- [x] Repo, AGPL-3.0 LICENSE, README stub, CONTRIBUTING (DCO), CODE_OF_CONDUCT
- [x] uv project, ruff, mypy, pytest, pre-commit, GitHub Actions CI
- [x] Dockerfile (multi-arch) + compose.yaml with optional `unbound` / `postgres` profiles
- Accept: `docker compose up` serves a health page; CI green.
  Status: pending — CI not yet run on GitHub (needs push of dev); local Docker daemon unavailable.

## M1 — Core platform (auth + multi-tenancy skeleton)
- [ ] Config, logging, DB, Alembic migrations (SQLite + PostgreSQL)
- [ ] Users, tenants, memberships, roles, permission layer `can()`
- [ ] Login (argon2), sessions, CSRF, first-run setup wizard (creates instance admin)
- [ ] Tenant-scoped repositories + tenancy test matrix
- [ ] Domain CRUD, tenant landing page, i18n (en/it) scaffolding, dark mode
- Accept: user from tenant A cannot read tenant B data (tests prove it); client viewer limited to assigned domains.

## M2 — DNS engine
- [ ] Resolver abstraction (system / custom / Unbound), cache, timeouts, explicit result states
- [ ] Free DNS tool: all record types, trace, reverse, propagation across resolvers
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
