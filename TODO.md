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
- [x] Upload/paste `.eml` or headers; Received chain with delays; Authentication-Results; ARC
- [x] Alignment analysis (From / Return-Path / DKIM d=), anomaly findings, MIME summary
- Accept: sample corpus (Gmail, Outlook, SES, SendGrid, MailUp...) parsed correctly. **Status 2026-11-07: parser verified against RFC corpus; provider samples pending** (maintainer to supply sanitized real .eml, see tests/fixtures/messages/README.md).
- Tickets (docs/tickets/):
  - [x] M4-01 raw message limits + header block parser (opus)
  - [x] M4-02 MIME structure + size (opus)
  - [x] M4-03 Received chain + hop delays (opus)
  - [x] M4-04 Authentication-Results parser (opus)
  - [x] M4-05 ARC chain parser (opus)
  - [x] M4-06 `message.analyze` permission (opus)
  - [x] M4-07 sample corpus + MANIFEST (provider samples unverified until maintainer supplies them)
  - [x] M4-08 alignment analysis
  - [x] M4-09 anomaly findings + MSG_* texts
  - [x] M4-10 analysis service
  - [x] M4-11 REST endpoint
  - [x] M4-12 web UI
  - [x] M4-13 CLI `analyze`
  - [x] M4-14 acceptance tests + docs/HEADERS.md

## M5 — Content analyzer + admin rules
- [x] Structural HTML/text checks, link analysis, size, List-Unsubscribe/One-Click
- [x] `content_rules` in DB with seed, weights, categories, language
- [x] Admin UI: global vs tenant rules, DKIM selectors, "test on sample" with ReDoS guard
- [x] Declarative custom checks (DNS only) with severity and remediation text
- Accept: rules editable without redeploy; regex timeout enforced by test.
  Status: **accepted 2026-11-10** — tests/content/test_acceptance_m5.py; full suite green on PostgreSQL locally and in dev CI. Report: docs/reports/M5.md
- Scope note (GM): custom checks cover DNS kinds only in M5; the HTTP-fetch kind moves to M7 (needs the guarded client). M5-22 updates this block and ARCHITECTURE.md.
- Tickets (docs/tickets/):
  - [x] M5-01 CSRF form cap vs localized 413 (opus)
  - [x] M5-02 MIME cap consistency, any capped input is error-class
  - [x] M5-03 ReDoS-safe regex runner with enforced timeout (opus)
  - [x] M5-04 permissions content.analyze, rules.manage global/tenant (opus)
  - [x] M5-05 content_rules model + migration + repository (opus)
  - [x] M5-05b content_rules index rework, SQLite planner error (opus)
  - [x] M5-06 dkim_selectors model + migration + repository + seed sync (opus)
  - [x] M5-07 custom_checks model + migration + repository (opus)
  - [x] M5-08 HTML/text structural parser
  - [x] M5-09 static link analysis + url_shorteners seed (no network)
  - [x] M5-10 List-Unsubscribe / One-Click analysis (RFC 2369, RFC 8058)
  - [x] M5-11 subject analysis
  - [x] M5-12 content_rules seed + sync
  - [x] M5-13 content rules engine (opus)
  - [x] M5-14 content analysis service + CONTENT_* findings
  - [x] M5-15 REST POST /api/v1/content/analyze
  - [x] M5-15b test DB fixtures: migrate once per session (opus)
  - [x] M5-15c test suite speed: seed sync, parallel CI jobs, docs-only pushes (opus)
  - [x] M5-15d PostgreSQL on tmpfs in CI (measured, no gain, reverted)
  - [x] M5-16 web UI content analyzer
  - [x] M5-17a CLI operator tenant and user selection (opus)
  - [x] M5-17 CLI `content`
  - [x] M5-17b ids above 32 bits give a 500 on PostgreSQL (opus)
  - [x] M5-18 content rules admin service + REST + test on sample (opus)
  - [x] M5-19 content rules admin UI
  - [x] M5-20 DKIM selectors admin service + REST + check wiring (opus)
  - [x] M5-21 DKIM selectors admin UI
  - [x] M5-22 custom checks schema + DNS evaluator (http_fetch rejected, deferred to M7)
  - [x] M5-23 custom checks admin service + REST + run wiring (opus)
  - [x] M5-23b DKIM provider visible to client viewers (opus)
  - [x] M5-24 custom checks admin UI
  - [x] M5-25 acceptance tests + docs/CONTENT.md

## M6 — ESP profiles
- [x] YAML schema + CI validation, loader, per-domain ESP assignment
- [x] Profile checks (SPF include, DKIM CNAMEs, return-path, tracking domain)
- [x] Initial profiles verified against official docs, incl. MailUp/TeamSystem and other Italian ESPs
- [x] Contributor guide for adding a profile
- Accept: each profile has `verified_on` + sources; sample domains produce expected findings.
- Tickets (docs/tickets/):
  - [x] M6-00 CI: fewer billed Actions minutes (no CI on qa, path-filtered infra jobs)
  - [x] M6-01 ESP profile schema, loader, CI validation (opus)
  - [x] M6-02 domain_esps model, migration, repository (opus)
  - [x] M6-03 ESP assignment service + REST + profile catalogue (opus)
  - [x] M6-04 ESP profile check: SPF include, DKIM CNAMEs, return-path, tracking (opus)
  - [x] M6-05 combined ESP SPF lookup budget finding (opus)
  - [x] M6-06 wire ESP check into domain runs + broken-profiles handling (opus)
  - [x] M6-06b localized rendering of ESP finding params (opus, depends on M6-06)
  - [x] M6-06c client viewers read ESP data on assigned domains (opus, depends on M6-06; maintainer decision 2026-11-10)
  - [x] M6-13 detect ESPs configured in DNS but not assigned (opus, depends on M6-06, M6-04/05)
  - [x] M6-13b bounded, fail-fast DKIM detection probes (opus, depends on M6-13; M6-08..10 depend on it)
  - [x] M6-07 domain page ESPs tab (depends on M6-06, M6-06b, M6-06c, M6-13; client viewers read-only)
  - [x] M6-14 public repository: workflow, release, security docs and agent permissions (maintainer decision 2026-11-11, run before M6-08)
  - [x] M6-15 CI: CodeQL advanced setup excluding tests (maintainer decision 2026-11-11, run before M6-08; depends on M6-14)
  - [x] M6-08 profiles: SendGrid, Amazon SES, Mailgun (official docs only)
  - [x] M6-09 profiles: MailUp/TeamSystem + up to two Italian ESPs (official docs only)
  - [x] M6-10 profiles: Google Workspace, Microsoft 365, Brevo (official docs only) (Brevo skipped)
  - [x] M6-11 acceptance: sample domains produce expected findings, docs/CHECKS.md
  - [x] M6-16 ESP profiles from maintainer-supplied pages: SendGrid link branding, Mailgun, Brevo
  - [x] M6-17 MailUp SPF: apply maintainer decision, include only when an SPF record exists (opus, depends on M6-16)
  - [x] M6-12 contributor guide docs/ESP_PROFILES.md
  - [x] M6-18 DKIM seed: add mailchef (Emailchef) and brevo1/brevo2 (Brevo) (sonnet, depends on M6-17); merged e158ab4, QA APPROVE
  - [ ] M6-18 follow-up (QA nit): seeds/dkim_selectors.yaml:4 file-level verified_on stays 2026-11-06 while mailchef/brevo1/brevo2 were verified 2026-11-11; load_dkim_selector_seed (app/services/seed_sync.py:200-217) gives every synced row the file-level date. Bump the file-level date once all entries are re-read, or support per-entry verified_on.
  - [x] M6-19 esp check: report DNS failures on an ESP's SPF include host (opus, depends on M6-17); merged 00bed63, QA APPROVE round 2
  - [ ] M6-19 follow-up (QA nit, round 2): app/checks/esp_profile.py:335-343 — for an `a` term where the A query succeeded but AAAA hit the query cap, the ESP_DNS_ERROR finding says rdtype "A" instead of "AAAA" (cosmetic; status is still error). Optional: a direct MAX_NODES test (same branch as the depth cap).
  - [x] M6-20 deps: upgrade dnspython to 2.9.0, CVE-2026-114605 (opus, no dependencies); dev CI green at 390cf69
  - [x] M6-21 deps: dnspython 2.9.2 plus compression-pointer regression test (opus, depends on M6-20); merged 9b0d610, QA APPROVE
  - [x] M6-22 docs: record the xato.net dataset terms (public domain, Mark Burnett) in the password list header and THIRD_PARTY_NOTICES, add attribution (sonnet; resolves the "MAINTAINER TO CONFIRM ... xato.net" item below)
  - [ ] M6-21 nit (QA, optional): tests/dns/test_backends.py:229-247 — add a pointer-chain variant whose chain resolves to the qname itself, to prove a vulnerable parser cannot yield a spoofed ok.
  - [x] pip-audit as a CI job on dev: APPROVED by the maintainer 2026-11-12 -> M6-24
  - [x] M6-23 MailUp DKIM: ml01+ml02 CNAMEs OR ml00 TXT, alternative selector sets in the ESP schema (opus; maintainer decision 2026-11-12); merged 99e408b, QA APPROVE
  - [x] M6-24 CI: pip-audit job on dev pushes and PRs (skips docs-only pushes) plus weekly run on main (sonnet); merged 2336d26, QA APPROVE
  - [x] M6-25 knowledge data: PSL licence MPL-2.0 and Gmail clip size 102,400 marked verified (sonnet); merged 348959d, QA APPROVE
  - M6 closed 2026-11-12. Report: docs/reports/M6.md
  - Dependabot (resolved 2026-11-12): the two open alerts (#1 pyproject.toml, #2 uv.lock) are the same advisory GHSA-45c3-73f7-pv4m, fixed by M6-21 (dnspython 2.9.2, on main since PR #2 9d793cb). The "second unidentified alert" item is closed; the alerts should close on the next Dependabot scan.

## R1 — Code review fixes 2026-11-12
Goal: fix the findings of the maintainer-requested code review of dev 06869fb (review files in docs/reviews/2026-11-12/ on the review branch; each ticket carries its own copy of the details).
Accept: each ticketed finding is reproduced by a failing test and fixed, or recorded as not reproduced; CI green on dev.
Tickets (docs/tickets/):
- [x] R1-01 PARSE-01 quadratic style regexes (ReDoS) + `_REPLY` rewrite (opus)
- [x] R1-02 AUTH-01 release the DB connection after authentication (opus)
- [x] R1-03 AUTH-02 login throttle: per-IP limit, argon2 concurrency bound, eviction reset; includes the "Per-IP cap on throttle keys" item (opus)
- [x] R1-04 AUTH-03 compose.yaml forwards BASE_URL and the other documented settings (sonnet)
- [x] R1-05 DNS-01 DMARC inherited policy uses sp (sonnet)
- [x] R1-06 DNS-02 SPF tree own domain-spec target normaliser (opus)
- [x] R1-07 DNS-03 trace reports an unfinished CNAME chain (opus); following the CNAME is a follow-up
- [x] R1-08 DNS-04 DKIM non-key TXT is not a found selector, one aggregated finding (sonnet)
- [x] R1-09 PARSE-02 alignment: dkim=none is no signature; spf from the resinfo with smtp.mailfrom (opus)
- [x] R1-10 PARSE-03 error status always carries an explaining finding (sonnet; depends R1-09)
- Lows, run only if budget allows:
- [x] R1-11 AUTH-06 missing-i18n-key warning shows the key (sonnet)
- [x] R1-12 AUTH-07 default error bodies translated, no echo, no blank 413 (sonnet)
- [x] R1-13 AUTH-08 sync DB calls on the event loop in async web handlers (sonnet; depends R1-02)
- [x] R1-14 AUTH-09 purge expired and revoked sessions (opus)
- [x] R1-15 AUTH-10 `__Host-` cookies on https, CSRF token expiry (opus; depends R1-04)
- [x] R1-16 AUTH-11 Cache-Control no-store centrally (sonnet); keyed on the session cookie, see R1-32
- [x] R1-17 DNS-05 SPF terms after `all` not counted (opus)
- [x] R1-18 DNS-06 drop the 255-octet SPF_RECORD_TOO_LONG info branch (opus)
- [x] R1-19 DNS-07 empty reply without RA is an error (sonnet; confidence low) — maintainer 2026-11-12: precautionary rule (a)
- [x] R1-20 PARSE-04 `dtk check` escapes control characters (sonnet)
- [x] R1-21 PARSE-05 Received from_ip prefers the TCP-info comment (opus; merged a349692, QA APPROVE round 2)
- [x] R1-22 PARSE-06 forged lower Authentication-Results field (opus; depends R1-09; option (c), maintainer agreed 2026-11-13; merged 854d34e, QA APPROVE)
- [x] R1-23 PARSE-07 message analyzer One-Click via the List-Unsubscribe parser (sonnet)
- [x] R1-24 PARSE-08 To/Cc counts from raw values (sonnet)
- [x] R1-25 INFRA-03 postgres compose profile: URL, retry, CI smoke (sonnet; depends R1-04)
- [x] R1-26 INFRA-04 pin app image bases by digest, rebuild check (sonnet; digests need network)
- [x] R1-27 INFRA-05 run Docker jobs for app/ and locales/ changes (sonnet)
- [x] R1-28 INFRA-06 migration race between replicas (sonnet)
- [x] R1-29 INFRA-07 app container hardening (sonnet; related to the safe_regex orphan item below; depends R1-04)
- [x] R1-30 AUTH-04 TRUSTED_PROXIES setting: client IP from X-Forwarded-For/Forwarded only for a trusted peer; login throttle, setup wizard, .env.example, compose (opus; depends R1-03, R1-04); covers the item "Trusted-proxy setting for the client IP"
- [x] R1-31 AUTH-05 domain rename rewrites the ESP host suffixes in the same transaction, user notice en+it (sonnet)
- [x] R1-32 AUTH-11 follow-up: Cache-Control no-store on every response except /static/ and exactly /healthz, regardless of the cookie (sonnet; depends R1-16)
- [x] R1-33 INFRA-01/02 push policy docs as enforced, workflow permissions test, settings.json deny rules (sonnet; in-review; settings.json and any .github/.claude change pushed only after maintainer approval)
Follow-ups:
- R1-21 follow-up (low, needs real MTA Received samples): `helo= [x]` with a space and `(HELO [x])` without "=" are not recognised as labelled, so `from [8.8.8.8] (helo= [10.1.2.3])` gives from_ip 10.1.2.3; consider skipping spaces before "[". "Prefer the comment literal" and helo=/ehlo= handling rest on RFC 5321 4.4 reasoning only, not on real samples.
- [x] R1-25b postgres-profile startup race fixed: bounded DB wait before migrations (docs/tickets/R1-25b-postgres-startup-wait.md; merged; CI infra proof on the next dev run).
- R1-25b follow-up (QA nits, low): docs/SETUP.md section 8: say a localized external server only falls back to fail-fast then the restart loop; a hanging connect is bounded by psycopg default 130 s, set connect_timeout if it ever matters; unused type: ignore at migrations/env.py:157 (outside mypy app).
- R1-25 follow-up (QA nit): ci-infra.yml postgres smoke relies on the CMD `alembic && uvicorn` chain to prove the app uses PostgreSQL; optionally query alembic_version in the postgres container. The comment at ci-infra.yml:116 ("Default profiles only") now describes only the first smoke.
- R1-26 follow-up (QA nit): docs/DOCKER-PINS.md:16 names only the OCI index media type (say "image index or manifest list"); rebuild.yml:5-6 "Rule and cadence: docs/UNBOUND.md" should also cite docs/DOCKER-PINS.md.
- R1-30 follow-up (QA nits): resolve_client_ip (app/web/auth.py:148-154) falls back to the peer silently; add a rate-limited WARNING so a proxy sending ip:port hops is noticed (otherwise all users share one throttle key again). docs/SETUP.md section 7: use a /32 example instead of 172.16.0.0/12. Dev run command in CLAUDE.md lacks --no-proxy-headers (dev-only, loopback; maintainer's file).
- R1-22 follow-up: addressed in F-01-01 (MSG_ALIGNMENT_FAIL reworded; `_topmost_results` documented and pinned).
- [x] F-01-03 (done dcca37e; ticket docs/tickets/F-01-03-topmost-authres-per-method.md; maintainer decision 2026-11-13): per-method findings (MSG_DKIM_NOT_PASS, MSG_SPF_NOT_PASS, same rule for any other per-method result) use ONLY the topmost Authentication-Results field: the message's authentication outcome is what the receiver stated. A lower field never suppresses or replaces it. Where a lower hop passed and the top did not, the hop view and MSG_AUTH_BROKE_AFTER_HOP already show that it was correct earlier; the message still counts as not authenticated. Change `_topmost_results` (app/services/message_findings.py) and its F-01-01 pin test, update docs/HEADERS.md; verdict/computed_dmarc unchanged (opus).
- F-01 follow-up (low, UX): hop numbering differs on one page: Received table shows the 0-based index, the hop view and MSG_HOP_DELAY_HIGH / MSG_AUTH_BROKE_AFTER_HOP show 1-based. Unify to 1-based in the Received table display.
- F-01-01 QA nits: detail_no_hop text says "below every Received field" even when the Received list was truncated at 100 (message_hops.py:317, locales :535): use the no_hop variant only when received_truncated is false or reword; docs/HEADERS.md:209 add "and signing algorithm" to the RFC 8617 4.2.1 uniqueness rule.
- F-01-02 QA nits: shared HOP_SCENARIOS chain test modules (tests/api, tests/web import tests/cli/test_analyze.py, which imports tests/services): move to tests/support/; _result.html:144 `kind_text[e.kind]` fails on an unknown kind: use the i18n key pattern as the CLI does.
- R1-12 follow-up: comment at app/web/templating.py:37 and test docstring tests/web/test_default_error_bodies.py:210 miscompute the 4-byte worst case (8192 fits the browser 3-byte maxlength case, ~6.6 KB); test_framework_validation_error_has_no_input_for_api_clients (line 67) already passed before the fix.
- R1-13 follow-up: AST guard tests/web/test_async_handlers_guard.py:22-37 only knows listed method names and 5 modules; glob app/web and flag db/service/repo_for receivers. Nit: stray comment app/web/rules.py:744-746. Also app/api/v1/content.py:170 sync db.rollback() (existing item below, one line).
- R1-14 follow-up: the purge runs only at startup; a long-running process accumulates rows until the M7 scheduler calls purge_sessions with a policy; no test sends a purged cookie.
- R1-23 follow-up: with two List-Unsubscribe fields (one over-long, one mailto-only) the message analyzer reports no One-Click while the content analyzer is silent; align optionally. Nit: a NUL-only unknown https value is called "safety limits".
- R1-01 follow-up: an over-cap inline style also marks the links section not evaluated (content_analysis.py treats any body not-evaluated reason as incomplete); narrow it to body + rules. Timing tests in tests/parsers/test_content_html.py add ~25 s; consider a `slow` marker.
- R1-03 follow-up: login throttle limits (IP_MAX_ATTEMPTS, MAX_CONCURRENT_VERIFICATIONS, VERIFICATION_WAIT) are module constants; behind a reverse proxy the per-IP budget is per client once `TRUSTED_PROXIES` is set (R1-30); consider settings.
- R1-04 follow-up: optional startup warning for a non-localhost http:// BASE_URL; parity test could also assert every forwarded Settings field is documented.
- R1-05 follow-up: inherited-sp scenario in tests/checks/test_acceptance_m3.py; assert the PCT_PARTIAL p argument in the sp-pct row.
- R1-06 follow-up: comment in app/checks/dnsutil.py fetch_txt noting the SPF tree builds its TXT question directly; the SPF parser still accepts empty/over-long labels and names that the tree rejects as invalid_target.
- R1-07 follow-up: follow the CNAME target in the trace (restart from the root within budgets); a CNAME from a non-AA server ends the trace instead of trying the next server; trace.py:556 uses getattr where ServerReply has the fields.
- R1-09 follow-up: a stated dkim=none header.d=X still adds X to stated_ds, so a DKIM-Signature d=X is not reported as unverified (message_alignment.py:260-262); two spf resinfos with smtp.mailfrom: first wins (RFC 8601 silent).
- R1-10 follow-up: MSG_AUTHRES_UNPARSED detail says the issue codes are 'listed in the finding data', but CLI/web do not show params unused by the text — add an {issues} placeholder (safe codes) or reword, en+it; property test could map each skipped area to its required code.
- R1-17 follow-up: no test pins error-over-AFTER_ALL precedence (tests/checks/test_esp_profile.py).
- R1-15 follow-up: remove the legacy dt_session fallback next release (app/core/security.py session_cookie_value, auth._clear_legacy_session_cookie); dt_lang needs no `__Host-` prefix (not security relevant).
- R1-31 follow-up: the docstring at app/repositories/domain_esps.py:263 should mention the invalid-rewrite case.
- R1-32 follow-up: SESSION_COOKIE_NAMES in app/core/security.py:47 is now unused.
- R1-33 follow-up: tests/test_workflow_permissions.py globs only *.yml (a future .yaml workflow is not checked).
Not ticketed — maintainer:
- INFRA-01 and INFRA-02: covered by R1-33 (maintainer set the rulesets and token rights; settings.json deny rules, docs and a workflow permissions test).
Decided 2026-11-13 (maintainer):
- AUTH-04: ticket R1-30. AUTH-05: ticket R1-31 (rewrite). AUTH-11 follow-up: ticket R1-32.
- PARSE-03 leniency: STRICT. An Authentication-Results field without authserv-id is not counted as evaluated (RFC 8601 section 2.2 ABNF; sections 2.5 and 4.1). No code change; MSG_AUTHRES_UNPARSED (R1-10) explains it; sentence added to docs/HEADERS.md.
- docs/CHECKS.md vs app/checks/dmarc.py: the doc was aligned to the code (failed external-authorization lookup gives `error` only when no critical/high finding is present; always reported as DMARC_EXTERNAL_AUTH_UNVERIFIED).

## Backlog (maintainer request 2026-11-13)
- [x] F-01 message analysis: authentication per hop view (Authentication-Results and ARC sets ordered among Received fields, info finding where pass turns to fail; display only, never feeds computed_dmarc) (opus; depends R1-22; ticket docs/tickets/F-01-auth-per-hop-view.md; analyzer extension, no SPEC scope change); split into:
  - [x] F-01-01 hop view service, MSG_AUTH_BROKE_AFTER_HOP info finding, R1-22 QA inputs, docs/HEADERS.md (opus; docs/tickets/F-01-01-hop-view-service.md)
  - [x] F-01-02 hop view in API JSON, web and CLI, i18n en+it, permission tests (opus; depends F-01-01; docs/tickets/F-01-02-hop-view-surfaces.md)

## M7 — Monitoring
- [x] Guarded outbound client (SSRF protection) + tests
- [ ] Custom check kind http_fetch via guarded client (SPEC §5 still lists HTTP custom checks and http_fetch is deferred to M7: maintainer decision 2026-11-11, leave the wording and review it when M7 starts)
- [ ] DNSBL/URIBL engine with refusal detection, `dnsbl.yaml` seed
- [ ] Scheduler, history, DNS snapshots + diff, trend charts
- [ ] Alerts: email, webhook, Slack/Teams
- Accept: scheduled runs respect rate limits; changes produce alerts exactly once.
Tickets (docs/tickets/M7-*.md, split 2026-11-13; model in brackets):
- [x] M7-00 CI test speed 3: pytest-xdist for both test jobs, target at most 50% duration, identical test ids (opus; serialized after M7-01; ci.yml push by maintainer)
  - Status: done (9bf618f, QA APPROVE round 1); dev CI run 43523482419: test-postgres 6.1 min (was about 12.9), test-sqlite 5.5 min (was about 11.4), target met, thin margin due to runner variance.
  - [ ] Follow-up (low): give tests/core/test_csrf.py and tests/core/test_security.py stable parametrize ids so the separate single-process CI step can be removed
  - [ ] Follow-up (low): tests/conftest.py:96-106 worker DB name could be truncated near PostgreSQL's 63-char limit (gw1/gw10 collision), local only
  - [ ] Follow-up (low): watch wall-clock tests under -n auto on CI: test_content_rules_engine.py:242/277, test_spf.py:374, test_received.py:565, test_authres.py:738, test_content_rules_admin.py:657
- [x] M7-01 guarded outbound HTTP client + ARCHITECTURE decision record (opus)
- [ ] Follow-up (low): tests/parsers/test_message.py::test_fold_bomb_is_bounded_and_fast failed once in two local PostgreSQL full runs under load (timing test, flaky candidate)
- [ ] M7-02 custom check kind http_fetch via guarded client (opus; depends M7-01)
- [x] M7-03 DNSBL/URIBL engine, refusal detection (opus)
  - [ ] Follow-up (low): move the private loader helpers (_StrictLoader, _list, _text, ...) imported by app/checks/dnsbl_schema.py from app/esp/profile.py and app/dns/knowledge.py into a shared public module
- [ ] M7-04 seeds/dnsbl.yaml + docs/DNSBL.md, unverified entries to the maintainer (sonnet; depends M7-03)
- [ ] M7-05 dnsbl check registration, API, CLI, web (sonnet; depends M7-03, M7-04)
- [ ] M7-06 monitor_targets model, migration, repository (sonnet)
- [ ] M7-07 check_runs history model, migration, retention (sonnet; depends M7-06)
- [ ] M7-08 DNS snapshots + diff (sonnet; depends M7-06)
- [ ] M7-09 scheduler core: rate limits, jitter, concurrency, session purge (sonnet; depends M7-06, M7-07)
- [ ] M7-10 scheduled run executor + change detection (sonnet; depends M7-05, M7-07, M7-08, M7-09)
- [ ] M7-11 monitor target API + permissions (opus; depends M7-06)
- [ ] M7-12 history and snapshot read API (sonnet; depends M7-07, M7-08, M7-11)
- [ ] M7-13 monitoring page + SVG trend charts (sonnet; depends M7-11, M7-12)
- [ ] M7-14 alert state, dedup, exactly-once design (opus; depends M7-10)
- [ ] M7-14b secret encryption service, Fernet/MultiFernet, ARCHITECTURE §9 (opus; no deps)
- [ ] M7-15 alert channel config, encrypted secrets, dispatcher (opus; depends M7-14, M7-14b, M7-11; alert.manage = owner, admin)
- [ ] M7-16 alert channel email (sonnet; depends M7-15)
- [ ] M7-17 alert channel generic webhook (sonnet; depends M7-15, M7-01)
- [ ] M7-18 alert channel Slack, payload to verify in official docs (sonnet; depends M7-17)
- [ ] M7-19 alert channel Teams, mechanism to verify in official docs (sonnet; depends M7-17)
- [ ] M7-20 M7 acceptance tests + docs/MONITORING.md (sonnet; depends all channels, M7-02, M7-05, M7-13)

## M8 — DMARC aggregate reports
- [ ] IMAP ingestion + HTTP endpoint, safe XML/zip/gz parsing
- [ ] Dashboard by source / disposition / alignment, unknown sender detection
- Accept: real-world report samples parsed; zip-bomb and XXE tests pass.

## M9 — Integrations and extra records
- [ ] BIMI (SVG Tiny-PS + VMC/CMC), MTA-STS, TLS-RPT, DANE, DNSSEC view
- [ ] Provider requirements checklist (Gmail/Yahoo/Microsoft) as dated data
- [ ] Optional SMTP module (off by default)

## M10 — Multi-tenant polish and release
- [ ] Share links, tenant branding, PDF/CSV/JSON export, audit log UI, TOTP, API keys
- [ ] Docs site, OpenAPI, install guides (Docker, Unraid/Synology/Proxmox notes), screenshots
- [ ] Security review checklist, dependency/license audit, v0.1.0 release
- Note: v0.1.0 ships without the M11 integrations (Postmaster Tools, SNDS).

## M11 — External reputation integrations
Maintainer decision 2026-11-12: moved from M9; no test domains or access yet, and the rest must work first. SPEC unchanged (both already optional, no milestone in SPEC).
- [ ] Google Postmaster Tools (OAuth, per domain) — verify current API first
- [ ] Microsoft SNDS — verify current access method first

## Follow-ups (post-M1)
- [ ] (low, possible after M7) operator-level allowlist for private/internal webhook targets (self-hosted Mattermost, internal gateway); M7 keeps guarded-client rules unchanged (GM decision 2026-11-13).
- Maintainer principle 2026-11-11 (ESP profiles): the known-record checks exist mainly to find which records a domain already has and associate them with an ESP; the seed/profile list is a convenient starting point for the best-known providers; whether a vendor marks a record required or optional matters little, because if a record is missing the client is told to add it. Vendor required/optional disputes are not escalated.
- [ ] MAINTAINER (M6-09): MailUp SPF conflict DECIDED 2026-11-11 (include musvc.com only when the domain already has an SPF record; never create an SPF record containing only MailUp's include; DMARC unaffected because SPF for DMARC is evaluated on the return-path domain) — implemented by M6-17. `mailchef` (Emailchef, TXT) DKIM seed question DECIDED 2026-11-11: add it (-> M6-18). Italian wording of esp.mailup.* and esp.emailchef.* APPROVED as is by the maintainer 2026-11-12 (closed; the esp.mailup.dkim_txt_alternative text is reworded by M6-23 and its new Italian goes back for review). Contactlab/Experian, Agile Telecom, Aruba not evaluated (two-profile cap).
- [ ] ESP schema gap (M6-08): DKIM selectors that are per-identity (Amazon SES, names shown in the console) or not documented (Mailgun) cannot be expressed; both profiles ship `selectors: []` plus a pitfall. Plan a schema extension (e.g. per-assignment selector names) in a later ticket. A future SES target pattern must not assume dkim.<region>.amazonses.com (hosted zone varies by Region and identity).
  Microsoft 365 (M6-10): selector1/selector2 CNAME targets have two documented formats with different label counts (`...-v1.dkim.mail.microsoft`, May 2025, and `...onmicrosoft.com`), so the profile has no target_pattern; the check only confirms the CNAMEs exist and detection skips them.
- [x] MAINTAINER (M6-10): Brevo-blocked part resolved by M6-16. Italian of esp.google_workspace.* and esp.microsoft_365.* APPROVED as is by the maintainer 2026-11-12 (Microsoft labels kept in English: the it-it page is inconsistent).
- [x] MAINTAINER (M6-08 vendor facts, unverified): resolved by M6-16. SendGrid link-branding/tracking CNAME (host, target, optional); Mailgun DKIM selector name, tracking host, whether Automatic Sender Security/key rotation makes DKIM a CNAME, whether the tracking CNAME is required with tracking off. Maintainer is collecting the official pages (2026-11-11).
- [x] MAINTAINER (M6-16): the Mailgun tracking CNAME optional/required confirmation is closed by the maintainer principle above (2026-11-11). Italian of esp.brevo.*, esp.mailgun.*, esp.sendgrid.tracking APPROVED as is by the maintainer 2026-11-12.
- [ ] ESP schema gaps (M6-16, later milestone): per-domain generated DKIM selector names (Mailgun TXT, Mailgun ASS pdk-like CNAMEs); DKIM "TXT or CNAME" alternatives (the mechanism exists since M6-23, `dkim.alternatives`; applying it to Brevo, Mailgun and SendGrid m1 vs s1/s2 is open and needs official sources); verification TXT records (Brevo code); target for tracking_domain/return_path; Brevo new-flow branded CNAMEs (help article 35337929909778, "only available to some accounts").
- [x] DKIM seed (M6-16): brevo1/brevo2 confirmed on help.brevo.com; adding them needs `"help.brevo.com": "brevo"` in `_VENDOR_HOSTS` in tests/checks/test_dkim_selectors.py. Moved to M6-18.
- [ ] SendGrid domain-authentication page documentation error recorded (M6-16 QA): it says "To route click and open tracking statistics ... Twilio SendGrid requires this CNAME record" under the bullet describing the s1/s2 DKIM CNAMEs, and mentions a selector "s" while the table uses s1/s2; profile values follow the table. "optional" for link branding rests on "If you choose No, you can add Link Branding later".
- [ ] M6-17 QA nits: (a) docs/templates/esp-profile.example.yaml: add a commented `only_if_record` line pointing to the docs/ESP_PROFILES.md table (new opt-in field `spf.only_if_record`, used only by MailUp). (b) locales/it.json:227 `esp.mailup.spf_only_if_published`: avoid repeating "il DMARC" (e.g. "...perché verifica l'SPF sul dominio del return-path..."); nit (b) CLOSED 2026-11-12: the maintainer approved the Italian as is. (c) Optional test: opt-in profile with an "ok" DNS answer carrying no TXT records (classified as error), same path as the existing failure-state test.
- [ ] Test nit (M6-16 QA): tests/esp/test_acceptance.py:393-419 could add a variant per profile with only one part unverified.
- [ ] nit (M6-08 QA): SendGrid Note quote reads '...and supports SPF'; the page says '...supports SPF and DKIM'.
- [ ] ESPs tab (M6-07 QA): should-fix test gap: tests/web/test_domain_esps_ui.py:295-311 has no regression test for hostile DNS evidence (an SPF include or CNAME target carrying `"><script>` from a fake-DNS zone, asserted escaped in `esps-detected` and the per-ESP group); QA checked it by hand and it is escaped. Nits: removing an already-removed assignment shows the full 404 page (app/web/domain_esps.py:291), a redirect with a notice is friendlier; the M6-07 ticket says app/web/__init__.py but routers register in app/main.py. Per-user rate limiting of DNS-running GETs is a project-wide gap (app/api/v1/checks.py:33).
- [x] ESP SPF include-host DNS failure (M6-11 QA): DECIDED 2026-11-11 (maintainer accepted the GM recommendation): the `esp` check must never swallow it, in the one-ESP and multi-ESP case; implemented by M6-19. Original note: with one ESP assigned, SERVFAIL on the ESP's include host (e.g. musvc.com) gives `esp` status info with no finding, by design ('the ESP's own record is the SPF check's business', docs/CHECKS.md); with two SPF ESPs it gives ESP_DNS_ERROR part=spf.lookups but no test covers it. GM to confirm with the maintainer that this fits 'never swallow DNS failures' (the `spf` check reports it in a domain `all` run); add a two-ESP include-host failure test.
- [ ] ESP acceptance nits (M6-11 QA): pin the empty_label variant outcome (tests/esp/test_acceptance.py:327-329); assert severity in the mutation test (:262); ESP_DETECTION_TRUNCATED has no acceptance test (unreachable with shipped profiles: 4 names vs cap 32); docs/CHECKS.md:9 'Registered ids: dkim, dmarc, spf' is stale.
- [ ] ESP detection cache (M6-13b): the assigned-ESP part (app/checks/esp_profile.py) and detection keep separate DNS caches, so a selector shared with an assigned ESP is queried twice; sharing needs a change to `detect`'s signature.
- [ ] Finding rendering leftovers (M6-06b QA):
  - Localize DNS state tokens (`{state}`, e.g. `timeout`) in one place for all checks; ESP_DNS_ERROR still shows them raw.
  - ESP_DNS_ERROR for an invalid domain reads "of -" because app/checks/esp_profile.py:523 sends `esp: "-"`; give that case its own detail text or drop "of {esp}".
  - Once `esp.*` note keys exist, add a catalogue test that note texts use only `{esp}` (app/checks/finding_text.py:67 formats with `esp` only).
  - Add a `<script>` selector/esp case to the web safety test (tests/checks/test_finding_text.py:423) so HTML escaping is pinned.
  - Timing flake: tests/parsers/test_message.py::test_fold_bomb_is_bounded_and_fast failed once under load (same pattern as test_received.py).
- [ ] ESP tests nit (M6-05 QA): tests/checks/test_esp_profile_spf_budget.py:16 imports private helpers (`_ctx`, `_assert_params_cover_placeholders`) from tests/checks/test_esp_profile.py; move them to a shared helper/conftest.
- [ ] ESP API nits (M6-03 QA): no test turns off `domain.update` for an owner and expects 403 on PUT/DELETE (tests/services/test_domain_esps_service.py:161-164 covers the list and read toggles only). PUT runs `check_write` twice (app/api/v1/domain_esps.py:167 and app/services/domain_esps.py:427), which is harmless but costs a second domain lookup.
- [ ] domain_esps (M6-02 QA): the 10-per-domain cap is checked by count before insert, so a concurrent add can exceed it by one (soft cap, not a security boundary).
- [ ] ESP loader nit (M6-01 QA): app/esp/profile.py:53 imports private helpers (`_check_keys`, `_fail`, `_str`, `_date`, `_status`) from app/dns/knowledge.py; make them public (pairs with the M5-09 seed loader item).
- [ ] Custom checks (M5-23 QA nits): "id order" (app/services/custom_checks_admin.py:172) vs "creation order" (app/api/v1/checks.py:12), pick one wording; `with_checks` DuplicateCheckError at app/api/v1/checks.py:69 would 500 the whole `all` run (unreachable today: catch it or comment why); tests/api/test_custom_checks_api.py:569 viewer run test should assert pattern/range text never appears in the response.
- [ ] DKIM provider nits (M5-23b QA): `ProbeSelectors.providers` is a MappingProxyType in a frozen dataclass, so hashing it raises TypeError (app/services/dkim_probe_selectors.py:50-57; add `field(hash=False)` or a comment); CLI `--selector` gets seed providers implicitly via `providers=None` (app/cli/check.py:97).
- [ ] Flaky timing tests (GM, 2026-11-10): tests/parsers/test_received.py:365 `test_scanners_linear` asserts wall-clock < 1.0 s; it failed once ([keywords]) while two full suites ran at once, passes alone. Use a relative bound or an operation counter instead of wall-clock (same pattern at :384). Also tests/parsers/test_dmarc.py::test_adversarial_inputs_are_fast[text0] failed once under load in a full PG run (passes alone 3/3). Three wall-clock tests have now flaked (with test_message.py::test_fold_bomb_is_bounded_and_fast): fix them together as one item.
- [ ] ESP detection notes (M6-13 QA): two unassigned candidates sharing an include are both flagged (esp_detection.py:111-114); `claimed` uses only assigned profiles' verified includes (:102). Revisit when M6-08..10 profiles share infrastructure.
- [ ] ESP profile overrides (GM decision 2026-11-10, M6 split): SPEC §5 lists tenant/global "ESP profiles overrides" and ARCHITECTURE sections 4/5 an `esp_profiles` table and ESPProfileOverride; M6 ships YAML profiles plus `domain_esps` only. Plan overrides for a later milestone. Maintainer decision 2026-11-10 (overrides the earlier GM default): a client viewer on a domain assigned to them sees, read-only, (a) the ESPs assigned to the domain, (b) ESPs detected in the domain's DNS that match a loaded profile but are not assigned, flagged as possible stale configuration, (c) the full `esp` check result; writes stay forbidden. Implemented by M6-06c and M6-13; SPEC §3 "cannot see other ESP data" is read as "ESP data of other domains" (GM decides on a wording clarification). Italian notes for profiles need maintainer review.
- [ ] CodeQL (M6-15 QA nit): .github/workflows/codeql.yml:24 comment says actions: read is only for private repositories; the codeql-action README at the pinned SHA does not say so — reword to 'not required by the codeql-action README at the pinned SHA'. HUMAN: switch CodeQL Default -> Advanced setup before the next PR to main; first real run on that PR.
- [ ] M6-00 follow-ups: tests/integration/test_unbound.py:3 docstring still says the integration-unbound job is in ci.yml (now ci-infra.yml). M6-00 is unverified on GitHub until the next dev push: check that qa pushes run nothing, dev pushes skip infra jobs unless their paths change, and main runs `infra / *`.
- [ ] DKIM selectors (M5-20 QA): seed sync adoption at app/services/seed_sync.py:232 silently replaces the admin's provider and record_type (only `enabled` and `notes` survive); add one log line per adoption (id only) and assert those fields in tests/services/test_seed_sync.py:274. Free checks and CLI `check` stay on the seed, so a global selector edit does not affect them. A list near the 250 cap can hit the API's 15 s `CHECK_TIMEOUT` (`error`) where SSE has 60 s. Maintainer decision 2026-11-10 (overrules the earlier GM decision): a client viewer sees the selector name and the provider (not notes, which stay admin-only) in DKIM results for its assigned domain; see M5-23b.
- [ ] Rules admin UI (M5-19 QA): a broken stored rule cannot be disabled by toggle or by an unchanged edit, because the service re-validates its pattern on enabled-only updates (toggle gives a 422; a tenant row can be deleted, a broken seeded global row can only be edited with a replacement pattern). Toggle, delete and error responses return to page 1. Every list view reads all rows (about 0.65 s at 10003 rows on SQLite, no per-tenant cap). The localized 413 stops at 1 MiB because `register_form_cap` matches exact paths only. `/rules/test` has no language input (the page says so).
- [ ] Rules admin (M5-18 QA): a tenant admin can fill the process-wide 4-slot regex pool through `/rules/test` and push other tenants' analyses to `busy`/`not_evaluated` (same exposure as `/content/analyze`; pairs with the safe_regex per-tenant fairness and rate-limit items). app/services/content_rules_admin.py imports private helpers (`_clean_values`, `_text`, `_evidence`, `_find_keyword`, `_fold`, `_keyword_is_valid`); make them public. GM decisions: DELETE of a seeded global row is 409 (disable it instead; a tombstone would need a migration); any accepted PATCH on a seeded row pins it against seed updates, even with unchanged values.
- [ ] Id overflow leftovers (M5-17b QA): the comment at app/cli/tenant_scope.py:45 still says `coerce_id` allows 63 bits. `app/api/v1` has no `__init__.py`, so `pkgutil.walk_packages` at tests/tenancy/test_matrix.py:95 finds none of its 6 modules and `declared_endpoints` sees 30 of 45 endpoints; no route escapes today because the main guard reads the route table, but the self-test is weaker than the test_matrix.py docstring and docs/TESTING.md:57 claim. tests/tenancy/test_id_range.py guards are name-based (limits in its docstring).
- [ ] CLI content (M5-17 QA): make `_fail`, `read_bounded` and `InputRejected` shared public helpers (copied in app/cli/content.py, comments at :52 and :67), with the M4-13 item. `dtk analyze - <&-` gives a traceback and exit 1 because `sys.stdin` is None (app/cli/analyze.py:56; fixed for `content`). docs/CONTENT.md (M5-25) must state that `dtk content --lang` is the content language hint and `--output-lang` the output language, unlike `check` and `analyze`, and that a run without `--eml` has List-Unsubscribe `not_evaluated`, so `complete` is false and it exits 1.
- [ ] CLI tenant scope (M5-17a QA): `_load` in app/cli/tenant_scope.py duplicates private `_build`/`_with_assigned_domains` from app/web/deps.py (a parity test guards it for tenant-level actions); extract a public `load_tenant_principal(db, user, tenant_id)` in app/repositories/principal.py. It also imports `_fail` from app/cli/check.py (shared public helper, with the M4-13 item). A driver error's class name is logged at INFO, so its cause is invisible until the CLI configures logging. A config error without `name` prints the raw key.
- [ ] Content UI nit (M5-16 QA): matched rows in app/web/templates/content/_result.html show the raw r.status in <code>; use a localized label.
- [ ] Test DB fixtures (M5-15b QA nits): tests/test_db_isolation.py:90 never sets `_pg.fingerprint`, so removing `_require_vetted` from `_truncate_postgres` survives locally (set a non-None fingerprint); the schema fingerprint at tests/conftest.py:31 omits constraints, defaults and nullability; the "never both fixtures" failure at tests/conftest.py:181 has no pinned test; the .github/workflows/ci.yml:39 comment still says only `db_url`; the lint-test job has no `timeout-minutes`.
- [ ] Test collection fixtures (M5-15c QA): the `seed_table_access` failure path at tests/conftest.py:243 is not pinned (mutant `if False:` survives); add a self-test that a recorded statement fails the test. Backend selection at tests/conftest.py:202-203: build both lists in one pass so a dropped test cannot go unnoticed. `SEED_TABLE_DML` at tests/conftest.py:53 misses statements starting with `WITH` or a SQL comment (app/ has no CTEs today).
- [x] MAINTAINER TO CHECK (M5-15c): branch protection required checks (was `lint-test`; docs-only PRs stay Pending because the CI workflow is skipped). Closed 2026-11-11: rulesets active, required checks lint, test-sqlite, test-postgres, secret-scan.
- [ ] Content rule targets (M5-12, GM decision 2026-11-08): add a target field to `content_rules` (subject / body; model, migration, repository, seed schema, engine) plus reply context (In-Reply-To/References) so real replies are exempt. Until then `subject_fake_reply_forward_prefix` stays disabled, and no seeded content rule is enabled.
- [ ] content_rules seed (M5-12 QA): before `shouting_punctuation` or `all_caps_run` is enabled, reword their en/it text. "not a requirement published by a mailbox provider" is a universal claim nothing cited supports; say instead that this tool has no official source for it (locales/en.json, locales/it.json).
- [ ] Seed sync (M5-12 QA): move `list_seeded` into GlobalContentRuleRepository and expose a public cleaner like DKIM's `clean_global_values`, replacing the subclass and the private `_clean_values` import in app/services/seed_sync.py.
- [ ] Seed loader (M5-12 QA): duplicate YAML keys inside an entry are last-wins in the shared loader (app/dns/knowledge.py:142, all seeds); detect them. Content rule `language` gets a format check only (`zz` passes); revisit with the first non-null language.
- [ ] Seed sync tests nit (M5-12 QA): the non-SeedSyncError startup failure cases in tests/services/test_seed_sync.py are monkeypatched; add a real DB error case. Pattern nit: `\s*` in `subject_fake_reply_forward_prefix` also matches " re : x".
- [ ] Dev setup (M5-12): no pre-commit hook is installed in .git/hooks, so plain commits do not run it; run `uv run pre-commit install` or document it.
- [ ] MAINTAINER TO CONFIRM (M5-12): seeded content rules `shouting_punctuation` and `all_caps_run` have no primary source, so they are unverified and disabled. Maintainer decision 2026-11-08: all seeded content rules stay disabled for now; revisit after in-depth testing.
- [ ] Rules engine (M5-13 QA): a regex match ending exactly at the cut of a capped part still counts as `matched` (`\bfree\b` on "freedom" cut after "free"; the part is in `capped_parts` and `complete` is False). Option: treat a match ending at the cut as unconfirmed unless another ended earlier (partial, lookaheads can depend on the unseen tail). Then fix the "score is a lower bound" wording at app/services/content_rules_engine.py:50 and :160, which is no longer strictly true.
- [ ] Rules engine nits (M5-13 QA): `TOO_MANY_MATCHES` is reachable only for a truncated result with no spans, which the real runner does not produce (:426). Word-boundary default True misses unspaced CJK keywords; `word_boundary` is engine-wide because rows have no such column. Documented `ok` gaps: NFC/NFD, dotted İ, fullwidth and zero-width evasion.
- [ ] safe_regex (M5-13 QA): a worker is orphaned if the parent is SIGKILLed; it kept running past the 5 s rule limit (app/core/safe_regex.py:192). Add RLIMIT_CPU or PDEATHSIG.
- [ ] safe_regex capacity (M5-13 QA): the 4-slot worker pool is process-wide, so one tenant's slow rules can cause `busy`/`not_evaluated` for other tenants; consider per-tenant fairness alongside rate limiting.
- [ ] tests/support/test_socket_guard.py: add a string-port case `getaddrinfo("db.test", "5432")` (psycopg passes the port as str) (QA nit).
- [x] MIME cap consistency (M4-14 QA): exceeding the part cap gives MSG_PARSER_LIMIT + status error, but exceeding the depth cap only gives MSG_MIME_TRUNCATED (low, warn); message_findings.py:71 says any capped input is error-class. Decide one rule, align code + HEADERS.md.
- [ ] M4 i18n scanner nits (M4-14 QA): 1-2 letter text ("OK", "No") passes the 3+ letter rule; `data-*` and `label` attributes not scanned; any dotted string ending in "." passes as a key prefix. Fold-bomb corpus sample trips no cap (stress sample only).
- [ ] CLI analyze (M4-13 QA): text output omits finding evidence (check and web UI show it; add the cli.check.evidence line); status label borrows message.arc.status (add cli.analyze.status); imports private `_fail` from app.cli.check (make a shared public helper); optional rename of key not_found to cannot_read.
- [ ] Message UI nits (M4-12 QA): MIME table first column uses `message.col.hop`; needs a part/index key. (JS `data-max-bytes` part closed by M5-01.)
- [x] Message UI (M4-12): CSRFMiddleware rejects form bodies > 1 MiB with token-in-body as 403, so no-JS pastes above ~1 MiB encoded get 403 instead of the localized 413; fix in core/csrf (raise its form cap or return 413). Closed by M5-01.
- [ ] CSRF form cap nits (M5-01 QA): Content-Length `isdigit()` accepts non-ASCII digits (use isascii()) in core/csrf.py and web/message.py; oversize opted-in post holds ~3x cap (avoid join+slice copy); test-registered BIG_PATH form cap never cleaned up.
- [ ] safe_regex nits (M5-03 QA): search_many should re-validate CompiledRule flags/pattern (or only compile_checked may build rules — M5-13/18/22 must use compile_checked); kill+reap the child if _Worker setup fails after Popen; suppress TimeoutExpired from wait() after SIGKILL; docstring: synchronous call up to ~15s, async callers use a thread pool; fix the subprocess docs citation (project runs 3.12, "3.15.2" looks wrong); rewrap ARCHITECTURE.md:204. Worker cap is per OS process (N uvicorn workers x 4).
- [ ] MIME warning overflow (M5-02 QA): header-block warning overflow gives limit `warnings` + error, but MIME warning overflow (too_many_warnings, parse complete) gives warn; pick one rule (check TOO_MANY_WARNINGS in mime.warnings or document in HEADERS.md). Test nit: `warnings_full_then_parts` never reaches the `mime` fallback; assert the label it gets (mime_parts).
- [ ] content_rules tests (M5-05 QA nit): add regression tests for a tenant override of a disabled seeded global row and for an uppercase seed_key ("G.ONE" → invalid_format).
- [ ] dkim_selectors comment nit (M5-06 QA): model:86 and migration 0006:123 blame the plain tenant_id index; the partial tenant index is the cause. Fix wording.
- [ ] custom_checks nits (M5-07 QA): DB does not check remediation_text has exactly en+it keys (repo does; document in docstring); ints over 4300 digits raise a bare ValueError from json.dumps instead of a typed `too_large` reason; if `definition` ever becomes jsonb the length CHECK no longer matches json.dumps.
- [ ] Seed loaders (M5-09 QA): make the private helpers public (app.dns.knowledge _check_keys/_url_list…, app.core.org_domain _psl) and move seed tests to tests/knowledge.
- [ ] DEFERRED, not a blocker (maintainer decision 2026-11-12: keep as is, stays unverified; revisit if someone publishes a census) (M5-09): URL shorteners unverified against official pages: t.co (help.x.com returned 403), tinyurl.com, ow.ly, buff.ly, lnkd.in, is.gd, j.mp (seeds/url_shorteners.yaml). Nit: all_aligned is None (not False) when a link is known unaligned and another is unevaluated; M5-14 should use unaligned_count.
- [ ] Content findings (M5-14 QA): internal parser failure surfaces as CONTENT_INPUT_CAPPED, whose remediation tells the user to fix the input (pairs with the MSG_SECTION_FAILED follow-up); raw reason codes appear in localized text; `{prefix}` shows the normalised "re".
- [ ] Content parsers (M5-14 QA): add a public visible-text API from M5-08, replacing `_VisibleText` subclassing private `_Collector`; `_lookup_charset` is private.
- [ ] tests/services/test_content_analysis.py (M5-14 QA): the socket guard does not detect an attempt whose exception is caught and ignored; a guard recording attempts, asserted empty, would close it.
- [ ] Content visible text (M5-14 QA): text runs are joined by a space, so a word split across inline tags is not matched by rules.
- [ ] app/parsers/content_html.py (M5-14 QA): ContentStructure `gmail_*` field names (internal, not on the wire) should be renamed to match the clip-risk wording.
- [ ] Content API (M5-15 QA): `db.rollback()` at app/api/v1/content.py:170 runs synchronously on the event loop; a stalled PostgreSQL connection would block the loop. Use `await run_in_threadpool(db.rollback)`; no test pins it.
- [ ] Content analysis (M5-15 QA): `analyze_content` keeps a pooled DB connection in a transaction through rule evaluation, up to about 15 s (idle-in-transaction on PostgreSQL). Release it after loading the rules (M5-14 code).
- [ ] M4-11 message analyze route has the same Content-Length `isdigit()` pattern fixed in M5-15 with `isascii()`; extends the existing CSRF form cap nit (M5-01 QA).
- [ ] Subject lookalikes (M5-11 QA nits): fullwidth Latin mixed with ASCII Latin (`ｐaypal`) is not flagged (FULLWIDTH prefix stripped); Letterlike Symbols excluded so `ℎello` is not flagged. Add a width-mixing / confusable fact (consider Unicode confusables data).
- [ ] tests/tenancy World.send: add a raw-body option so the matrix can show 200 for permitted roles on raw-body routes (M4-11 QA nit).
- [ ] Received redaction (done in M4-10: all `@` tokens masked). Remaining: `<local>` with no domain and fullwidth ＠ stay visible; Message-ID-style hop ids become None. Also a dedicated MSG_SECTION_FAILED code (en+it) instead of reusing MSG_PARSER_LIMIT, whose "exceeded limits" text misleads for internal failures.
- [ ] Public RFC 5322 Date parser; message_findings parses Date via parse_received_values, so a valid Date with a comment containing ";" is reported MSG_DATE_INVALID (M4-09 QA). Also rename test_authserv_mismatch_lists_ids_escaped (no longer escaped).
- [ ] Received: a 4-word date is reported as `date_no_timezone` without a shape check (received.py:256, M4-03 QA nit)
- [ ] M4-01 QA nits: make `decode_rfc2047` private or give it a public signature, and make `_lookup_charset` and `_Warnings` public (imported privately by app/parsers/mime.py, M4-02 QA); warn mixed endings on the header-terminating blank line; document that MAX_HEADER_BYTES excludes the blank line
- [ ] authres `_Issues` and the DKIM tag-list parser are private; arc.py has local copies — consider a shared public helper (M4-05)
- [ ] ARC (M4-05 QA nits): store a has_h_tag flag on the seal, not a lookup in the capped issue list (arc.py:530); an empty `h=` on a seal should also count as cv fail (GM reading of RFC 8617 4.1.3: an h tag is found).
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
- [x] Per-IP cap on throttle keys, plus a warning log when the table is full (a single IP can fill the table with locked keys and block new logins) (done in R1-03)
- [x] (covered by R1-30: `TRUSTED_PROXIES`, docs/SETUP.md section 7; uvicorn proxy headers disabled in the image) Trusted-proxy setting for the client IP (needed before any reverse-proxy deployment). Consequence added by the 2026-11-12 review: behind a proxy every client shares one throttle IP, so anyone who knows an email address can lock that account remotely (ten wrong passwords per 15 minutes) and can lock the setup wizard (five wrong setup tokens delay, ten lock it); the documented HTTPS path already implies a proxy; uvicorn `forwarded-allow-ips` default (127.0.0.1 only) is unverified, check the uvicorn documentation before designing (review AUTH-04)
- [ ] `services.auth.rotate_session` helper (`_switch` reads the sessions row directly)
- [ ] Dispose of the DB engine at shutdown via the lifespan
- [ ] A breached-password corpus check, offline
- [x] MAINTAINER TO CONFIRM before the public release: the terms of the original xato.net dataset behind the SecLists password list are unverified: resolved by M6-22 (public domain per the original 2015 post; attribution to Mark Burnett added)
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
- [x] MAINTAINER TO CONFIRM: Public Suffix List data licence: GM read github.com/publicsuffix/list LICENSE on 2026-11-12 ("Mozilla Public License Version 2.0"), maintainer accepts; seed record updated by M6-25 (M3-09)
- [x] Gmail clipping threshold 102,400 bytes: confirmed by the maintainer 2026-11-12 from their own experience (source: maintainer confirmation, no URL); recorded by M6-25
- [ ] SPF parser nits (M3-04 QA): at the 4096-char cut, drop the partial last term so it does not add a second misleading issue; add a comment on Unicode-whitespace term splitting
- [ ] DMARC parser: reject a `!size` whose value after the unit (number*unit) exceeds 64 bits (M3-05 QA).
- [ ] Move the no-network socket guard from tests/dns/conftest.py to tests/conftest.py so tests/checks need no cross-package import (M3-07 QA).
- [ ] spf_tree.py:319 per-term `valid` filter is dead code; remove or assert (M3-07 QA nit).
- [ ] DKIM parser: optionally reject base64 with non-zero padding bits (M3-06 QA nit).
- [x] HTMX under CSP `script-src 'self'`: closed 2026-11-12 (GM): the app does not use HTMX (no vendored HTMX; web JS is static files under script-src 'self'). If HTMX is ever introduced, verify https://htmx.org/docs/ first (includeIndicatorStyles=false and allowEval=false when vendored).
- [ ] Authentication tab: catch InvalidTarget from run_checks and render the error page instead of a 500 (M3-17 QA nit)
- [ ] _result.html uses class dns-state-absent for warn/fail/info; use a neutral per-status class (M3-17 QA nit)
