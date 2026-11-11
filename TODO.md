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
- [ ] YAML schema + CI validation, loader, per-domain ESP assignment
- [ ] Profile checks (SPF include, DKIM CNAMEs, return-path, tracking domain)
- [ ] Initial profiles verified against official docs, incl. MailUp/TeamSystem and other Italian ESPs
- [ ] Contributor guide for adding a profile
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
  - [x] M6-12 contributor guide docs/ESP_PROFILES.md

## M7 — Monitoring
- [ ] Guarded outbound client (SSRF protection) + tests
- [ ] Custom check kind http_fetch via guarded client
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
- [ ] MAINTAINER (M6-09): MailUp help pages conflict on domains without an SPF record (810156046/809926670 'non è necessario'; 37519762 asks for v=spf1 include:musvc.com ~all, needed for DMARC) — the pitfall reports both; decide. Add `mailchef` (Emailchef, TXT) to seeds/dkim_selectors.yaml? Review the Italian wording of the esp.mailup.* and esp.emailchef.* strings. Contactlab/Experian, Agile Telecom, Aruba not evaluated (two-profile cap).
- [ ] ESP schema gap (M6-08): DKIM selectors that are per-identity (Amazon SES, names shown in the console) or not documented (Mailgun) cannot be expressed; both profiles ship `selectors: []` plus a pitfall. Plan a schema extension (e.g. per-assignment selector names) in a later ticket. A future SES target pattern must not assume dkim.<region>.amazonses.com (hosted zone varies by Region and identity).
  Microsoft 365 (M6-10): selector1/selector2 CNAME targets have two documented formats with different label counts (`...-v1.dkim.mail.microsoft`, May 2025, and `...onmicrosoft.com`), so the profile has no target_pattern; the check only confirms the CNAMEs exist and detection skips them.
- [ ] MAINTAINER (M6-10): Brevo profile blocked — help.brevo.com returns 403 (Cloudflare); maintainer to supply the official DNS setup page text. Review the Italian of esp.google_workspace.* and esp.microsoft_365.* (Microsoft labels kept in English: the it-it page is inconsistent).
- [ ] MAINTAINER (M6-08 vendor facts, unverified): SendGrid link-branding/tracking CNAME (host, target, optional); Mailgun DKIM selector name, tracking host, whether Automatic Sender Security/key rotation makes DKIM a CNAME, whether the tracking CNAME is required with tracking off. Maintainer is collecting the official pages (2026-11-11).
- [ ] nit (M6-08 QA): SendGrid Note quote reads '...and supports SPF'; the page says '...supports SPF and DKIM'.
- [ ] ESPs tab (M6-07 QA): should-fix test gap: tests/web/test_domain_esps_ui.py:295-311 has no regression test for hostile DNS evidence (an SPF include or CNAME target carrying `"><script>` from a fake-DNS zone, asserted escaped in `esps-detected` and the per-ESP group); QA checked it by hand and it is escaped. Nits: removing an already-removed assignment shows the full 404 page (app/web/domain_esps.py:291), a redirect with a notice is friendlier; the M6-07 ticket says app/web/__init__.py but routers register in app/main.py. Per-user rate limiting of DNS-running GETs is a project-wide gap (app/api/v1/checks.py:33).
- [ ] ESP SPF include-host DNS failure (M6-11 QA): with one ESP assigned, SERVFAIL on the ESP's include host (e.g. musvc.com) gives `esp` status info with no finding, by design ('the ESP's own record is the SPF check's business', docs/CHECKS.md); with two SPF ESPs it gives ESP_DNS_ERROR part=spf.lookups but no test covers it. GM to confirm with the maintainer that this fits 'never swallow DNS failures' (the `spf` check reports it in a domain `all` run); add a two-ESP include-host failure test.
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
- [ ] MAINTAINER TO CONFIRM (M5-09): URL shorteners unverified against official pages: t.co (help.x.com returned 403), tinyurl.com, ow.ly, buff.ly, lnkd.in, is.gd, j.mp (seeds/url_shorteners.yaml). Nit: all_aligned is None (not False) when a link is known unaligned and another is unevaluated; M5-14 should use unaligned_count.
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
