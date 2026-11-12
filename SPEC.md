# SPEC — Deliverability Toolkit (working name)

> Open-source (AGPL-3.0), self-hostable web app + API + CLI that makes
> email deliverability checks simple for people who send through an ESP
> and want more control over the fundamentals.

## 1. Vision

Most deliverability tools either target MTA operators or are closed SaaS.
This project targets **specialists and agencies who send through ESPs**
(SendGrid, Mailchimp, MailUp, ...) and control the DNS and the domain
configuration, but not the sending servers.

Every check must answer three questions: **what is the state, why does it
matter, what should I do about it.** A check that only says "SPF: 11 lookups"
is incomplete; it must explain the 10-lookup limit, show which includes weigh
most, and suggest how to reduce them.

## 2. Principles

1. **Self-hostable in one command.** `docker compose up` works with zero config
   (SQLite). PostgreSQL and a dedicated resolver are optional upgrades.
2. **API-first.** Every check is an independent function exposed by the web UI,
   the REST API and the CLI.
3. **Data, not code, for knowledge.** ESP profiles, DKIM selectors and content
   rules are data files (YAML/JSON) and DB rows, extendable without redeploy.
4. **Progressive results.** Slow checks stream results as they complete.
5. **Safe by default.** Private (login required), SSRF-protected, rate-limited.
6. **i18n from day one.** English and Italian at launch.

## 3. Users, tenants and roles

Multi-tenant. A **tenant** (Organization / Workspace) groups domains, users,
custom rules and settings. Data isolation between tenants is a hard requirement.

| Role | Scope | Capabilities |
|---|---|---|
| Instance admin | Whole instance | Manage tenants, global rules/selectors/ESP profiles, instance settings, SMTP for notifications |
| Tenant owner | One tenant | Everything inside the tenant, users, billing-like settings, API keys |
| Tenant admin | One tenant | Manage domains, custom checks, integrations, invite users |
| Analyst | One tenant | Run all checks, see all domains, no user/integration management |
| Client viewer | Selected domains of one tenant | Read-only dashboards and reports for assigned domains; feature access limited by per-user toggles |

Requirements:
- A user may belong to several tenants (agency scenario) and switch between them.
- Per-user, per-domain visibility (a client sees only their own domains).
- Per-role or per-user feature toggles (e.g. a client viewer cannot run
  content analysis, cannot see raw DNS tools, cannot see ESP data of domains
  not assigned to them; on assigned domains they see assigned and detected ESPs
  and the ESP check result read-only, maintainer decision 2026-11-10).
- Optional read-only **share links** (token, expiry, revocable) for a domain report.
- Audit log of sensitive actions (login, role change, rule change, export).
- Local login with argon2 hashes + optional TOTP 2FA; OIDC/SSO is a later milestone.
- Scoped API keys (per tenant, per role).

## 4. Functional modules

### 4.1 Authentication records (per domain)
- **SPF**: full parse, recursive include resolution, 10-lookup count, void lookup
  count (limit 2), loops, `+all`/`?all`/missing `all`, multiple SPF records,
  deprecated `ptr`, size limits, flattening hints.
- **DKIM**: probe a list of selectors (built-in + tenant + admin custom);
  validate syntax, key type and length (flag 1024-bit, flag missing),
  `t=y` test mode, revoked key (`p=` empty), CNAME delegation chains.
  Selectors cannot be enumerated: UI must say so and let users add selectors.
- **DMARC**: policy, subdomain policy, `pct`, `rua`/`ruf`, alignment modes,
  external report destination authorization (`_report._dmarc`), syntax errors,
  organizational-domain fallback.
- **BIMI**: record, SVG validation (Tiny-PS profile), VMC/CMC certificate checks.
- **MTA-STS / TLS-RPT / DANE**: records and policy file fetched over HTTPS.
- **DNSSEC** status for the domain.

### 4.2 ESP profiles
YAML files in `profiles/esp/` describing how a domain should look for each ESP:
expected SPF includes, DKIM selectors (and whether they are CNAME or TXT),
return-path / bounce / tracking domain setup, common pitfalls, doc links.
The domain page lets the user attach one or more ESPs; the engine then runs
profile-specific checks (e.g. "SendGrid DKIM CNAMEs missing", "SPF combines
three ESPs and exceeds 10 lookups").

Initial profiles (to be verified against each vendor's current docs before
publishing): SendGrid, Mailgun, Amazon SES, Postmark, Brevo, Mailchimp,
Mandrill, Klaviyo, HubSpot, ActiveCampaign, Salesforce Marketing Cloud,
Google Workspace, Microsoft 365, **MailUp (TeamSystem)** and other Italian
providers (candidates to verify: Emailchef, Contactlab/Experian, Agile
Telecom, Aruba). New ESPs are added by pull request with a schema-validated YAML.

### 4.3 Monitoring
- **Blacklists** for domains and IPs (DNSBL/URIBL/RBL), parallel queries with
  timeouts, correct interpretation of special return codes
  (e.g. "query refused" must not read as "listed" or "clean").
- **Google Postmaster Tools** via OAuth, per domain (optional integration).
- **Microsoft SNDS** via personal key for owned IP ranges (optional).
- **Scheduled checks** with history, trend charts and diffs of DNS records.
- **Alerts**: email, webhook, Slack/Teams on record changes, new listings,
  expiring certificates/keys, policy regressions.

### 4.4 DMARC aggregate reports (rua)
Ingest reports via IMAP mailbox or HTTP endpoint, parse XML (zip/gz), store
aggregated rows, dashboard by source IP / sending service / disposition /
alignment, identify unknown senders and map known IPs to ESPs.

### 4.5 Content analysis
Input: plain text and/or HTML (and optionally a full `.eml`).
Structural checks first, word lists last:
- text/image ratio, images without alt, missing plain-text part
- masked links (text differs from href), URL shorteners, link domains not
  aligned with the sender, tracking-domain consistency
- malformed HTML, size (Gmail clipping near 102 KB), hidden text, excess CSS
- `List-Unsubscribe` and One-Click (RFC 8058) when headers are provided
- subject issues (all caps, punctuation, length)
- configurable rules (regex/keyword, weight, category, language, on/off)

### 4.6 Message original analyzer
Parse raw message: `Received` chain with hop delays, `Authentication-Results`,
ARC chain, SPF/DKIM/DMARC evaluation and alignment, return-path vs from vs
DKIM `d=`, header anomalies, list headers, MIME structure, size breakdown.

### 4.7 DNS tools
Lookup of all record types, resolver selection, trace (dig +trace style),
reverse lookup, propagation check across several public resolvers,
DNSSEC validation display.

### 4.8 SMTP / infrastructure checks (optional module)
Banner, STARTTLS, certificate validity/expiry, PTR and FCrDNS, HELO
consistency. Disabled by default (outbound port 25 is often blocked and the
module is a SSRF risk).

### 4.9 Provider requirements checklist
Per domain traffic-light checklist for Gmail / Yahoo / Microsoft bulk-sender
requirements (authentication, alignment, one-click unsubscribe, spam rate
thresholds when Postmaster data is connected). Requirements must be stored as
data and dated, since providers change them.

### 4.10 Reports
Per-domain PDF/CSV/JSON export, shareable read-only link, branding of the
tenant (logo, name) for agencies.

## 5. Admin and extensibility

All of the following live in the DB with a **global** scope (instance admin)
or **tenant** scope (tenant admin), seeded from files shipped with the code:
- DKIM selectors (name, provider, notes)
- content rules (pattern, weight, category, language, enabled)
- custom checks: declarative definitions (DNS record exists / matches regex /
  value in range / HTTP fetch matches) with severity and remediation text
- ESP profiles overrides
- every rule can be tested against a sample before saving, with a timeout
  guard on regexes (ReDoS protection)

## 6. Landing and navigation

- **Tenant landing page**: one card/row per domain with an overall status
  (traffic light), SPF/DKIM/DMARC/blacklist summary, last check time, trend.
- **Domain page**: tabs Authentication, ESPs, Reputation, DMARC reports,
  History, Settings.
- **Free tools menu** (not bound to a domain): DNS, original analyzer,
  content analyzer, DKIM probe, blacklist lookup.
- Client viewers see only the landing (filtered) and the allowed domain tabs.

## 7. Non-functional requirements

- Single Docker image, amd64 + arm64. Idle memory target under 200 MB.
- SQLite default, PostgreSQL supported through SQLAlchemy; both tested in CI.
- All outbound network from checks goes through a guarded client: blocks
  loopback, private, link-local and metadata ranges; enforces timeouts and
  response size limits.
- Rate limiting per user, per tenant and per IP.
- Secrets encrypted at rest (OAuth tokens, SNDS key, IMAP credentials).
- Accessibility: keyboard navigable, WCAG AA contrast, dark mode.
- Test coverage: parsers and check engine > 90%; tenant-isolation tests mandatory.
- Documentation: install guide, ESP profile authoring guide, rule authoring
  guide, API reference (OpenAPI), contributor guide.

## 8. Out of scope for v1

Sending email, inbox placement panels from third parties, multi-region probes,
billing, mobile apps, SSO (planned later).

## 9. License

GNU AGPL-3.0-or-later. Contributions under DCO sign-off.
