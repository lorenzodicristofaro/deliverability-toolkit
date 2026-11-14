# Checks (M3)

How the deliverability checks work, as implemented. Design rules live in `ARCHITECTURE.md`
(section 3); DNS behaviour is in `docs/DNS.md`. Checks run live; **nothing is persisted in M3**.

## Check interface

A check is a class with a string `id` and `async run(ctx: CheckContext, target: Target) -> CheckResult`
(`app/checks/models.py`, protocol `Check`). Registered ids: `dkim`, `dmarc`, `dnsbl`, `spf`.

- `CheckContext`: resolver, clock, optional `tenant_id` / `domain_id`. No database handle by design.
- `CheckResult`: `check_id`, `target`, `status`, `findings`, `data`, `started_at`, `duration_ms`.
  Its JSON (`model_dump_json`) is shared by the API and the CLI; the UI renders the same
  `CheckResult` objects. For each of the six acceptance scenarios, `tests/checks/test_acceptance_m3.py`
  loads the Authentication tab and asserts that the SPF and DMARC sections are present once each and
  that their status and ordered finding (code, severity) pairs equal the service result for the same
  zone. DKIM is compared through the SSE stream, not the tab.
- `Finding`: stable `code`, `severity`, i18n keys `finding.<CODE>.title|detail|remediation`,
  `params`, `evidence`, optional `docs_url`. Findings are sorted by severity, then code.
- The only entry point is `app/services/checks.py` (`run_check`, `run_checks`). It re-stamps the
  result (`check_id`, `target`, `started_at`, `duration_ms`), bounds concurrency (8) and each check
  (15 s deadline), and turns any exception, timeout or invalid return into status `error`
  (`CHECK_INTERNAL_ERROR`, `CHECK_TIMEOUT`).

## Status rules

`status` is derived from the findings (`derive_status`):

| Condition | Status |
|---|---|
| the check could not evaluate (DNS failure, timeout, internal error) | `error` |
| any `critical` or `high` finding | `fail` |
| else any `medium` or `low` finding | `warn` |
| else any `info` finding | `info` |
| no findings | `ok` |

- **`error` is never `ok` and never "missing".** Only `nxdomain` and `nodata` count as absence.
  Every other DNS state (servfail, refused, timeout, truncated, malformed, network_error, blocked,
  error) makes the lookup, and so the check, `error`. This covers every lookup: the SPF tree, the
  `_dmarc` record (and the organizational-domain fallback), the DMARC external authorization
  lookups at `<domain>._report._dmarc.<destination>`, and the DKIM selector probe.
  One exception for the DMARC external authorization lookups: when one fails, the DMARC check is
  `error` only if no `critical` or `high` finding is present; otherwise the status follows the
  findings (`app/checks/dmarc.py`). The failure is always reported as `DMARC_EXTERNAL_AUTH_UNVERIFIED`.
- **DKIM rule.** Selectors cannot be enumerated in DNS, so the check probes a seed list and never
  claims DKIM is absent. Failed selectors are always listed in `DKIM_PROBE_ERRORS`. If at least
  one selector is found, the status follows the findings. If none is found and any failed, the
  status is `error`. `DKIM_NO_SELECTOR_FOUND` appears only when every selector was `not_found`.
  A probe cut short by the stream deadline is `error`.
  A TXT record counts as a DKIM key candidate if it starts with `v=DKIM1` (case and spaces
  tolerated) or has a `p=` tag; a malformed candidate is still `DKIM_KEY_SYNTAX_ERROR`. A selector
  whose TXT records are all non-candidates (typically a wildcard TXT such as `v=spf1 -all`) is
  `not_found`, with no syntax error; ONE `DKIM_NON_KEY_TXT` (info) per run gives the count and up
  to 20 selector names with a truncated text. A selector with at least one candidate is `found`:
  every TXT record at the name still counts for `DKIM_MULTIPLE_RECORDS` (a verifier may pick the
  non-key one), while key findings (syntax, size, revoked, test mode) look at candidates only.
  In `esp` checks a primary `txt` selector answered
  only by non-candidates is missing, not ok.
  An empty list (every selector disabled) probes nothing: status `error` with
  `DKIM_NO_SELECTORS_PROBED`, never a verdict about the domain. A list cut by the probe cap is
  incomplete: status `error` with `DKIM_SELECTORS_CAPPED`, and `data["dropped"]` gives the number.
- **DKIM selector list.** Domain checks (REST and the SSE stream) probe the enabled global rows of
  `dkim_selectors` plus the active tenant's enabled rows, deduplicated and sorted by name, at most
  250 per run (`app/services/dkim_probe_selectors.py`). With only the synced seed that is exactly
  the seed list. If the global table has no rows at all (a seed sync that failed or never ran),
  the seed file replaces the global rows. Free checks (`/api/v1/checks/free`, `/tools/dkim/stream`)
  and the CLI `check` have no tenant and always use the seed file. The list is resolved before any
  DNS query, and the database connection is released first. Admins may keep at most 50 rows per
  tenant and 200 global rows. Every role that can see a domain, client viewer included, gets each
  selector's name and provider in the DKIM result (maintainer decision 2026-11-10, M5-23b); `notes`
  never leaves the admin surfaces. Inside a tenant, an enabled tenant row's non-empty provider wins
  over a same-name global row; free checks and the CLI show seed providers.
- `data["report_destinations"]` (DMARC) lists each report URI with its authorization state.
  `data["selectors"]` (DKIM) lists each probed selector with state `found`, `not_found` or `error`.

## Finding codes

Severity is the one the code emits. "RFC section" is the section the finding text relies on;
"none" means a tool heuristic or limit with no RFC section behind it. Codes are listed in each
module's `CODES`; `tests/checks/test_acceptance_m3.py` requires en and it text for every one.

### Runner (`app/services/checks.py`)

| Code | Severity | RFC section |
|---|---|---|
| `CHECK_INTERNAL_ERROR` | medium (status `error`) | none |
| `CHECK_TIMEOUT` | medium (status `error`) | none |

### SPF (RFC 7208)

| Code | Severity | RFC section |
|---|---|---|
| `SPF_MISSING` | medium | 2.6.1, 4.5 |
| `SPF_MULTIPLE_RECORDS` | high | 4.5 |
| `SPF_SYNTAX_ERROR` | high | 4.6, 5.2 |
| `SPF_TOO_MANY_LOOKUPS` | high | 4.6.4 |
| `SPF_NEAR_LOOKUP_LIMIT` | low | 4.6.4 |
| `SPF_TOO_MANY_VOID_LOOKUPS` | medium | 4.6.4 |
| `SPF_INCLUDE_LOOP` | high | 4.6.4 |
| `SPF_INCLUDE_NOT_FOUND` | high | 5.2, 6.1 |
| `SPF_PLUS_ALL` | critical | 2.6.3, 5.1 |
| `SPF_QUESTION_ALL` | medium | 2.6.2 |
| `SPF_NEUTRAL_ALL_SOFTFAIL` | info | 2.6.5 |
| `SPF_NO_ALL` | medium | 4.7 |
| `SPF_REDIRECT_WITH_ALL` | low | 5.1, 6.1 |
| `SPF_PTR_DEPRECATED` | low | 5.5 |
| `SPF_RECORD_TOO_LONG` | medium (name plus SPF text over 450 octets; a record over 255 octets published as several strings is valid and not flagged, R1-18) | 3.4 (3.3 for multiple strings) |
| `SPF_RESOLUTION_TRUNCATED` | info | 4.6.4 |
| `SPF_FLATTENING_HINT` | info | none (advisory; no addresses are generated) |
| `SPF_DNS_ERROR` | medium (status `error`) | 4.4 |
| `SPF_MX_TOO_MANY_HOSTS` | high | 4.6.4 |
| `SPF_TERMS_AFTER_ALL` | low | 5.1 (mechanisms after the first `all` are never tested, so they are not counted or followed; still syntax-checked) |

SPF tree targets (`include`, `redirect`, `a`, `mx`, `exists`) follow the RFC 7208 `domain-spec` rule
the SPF parser applies plus DNS limits (visible ASCII labels such as `spf_c` or `x-`, 1-63 octets
each, 253-octet name, no backslash), so only names that cannot be queried are `invalid_target`
(`SPF_SYNTAX_ERROR`); DKIM and ESP CNAME targets intentionally keep the stricter `to_dns_name`
host-name rule.

### DMARC (RFC 7489)

| Code | Severity | RFC section |
|---|---|---|
| `DMARC_MISSING` | medium | 6.6.3 |
| `DMARC_MULTIPLE_RECORDS` | medium | 6.6.3 |
| `DMARC_SYNTAX_ERROR` | medium | 6.3 |
| `DMARC_POLICY_NONE` | low | 6.3 |
| `DMARC_POLICY_QUARANTINE` | info | 6.3 |
| `DMARC_SUBDOMAIN_POLICY_WEAKER` | low | 6.3 |
| `DMARC_PCT_PARTIAL` | low | 6.3 |
| `DMARC_NO_RUA` | low | 6.3 |
| `DMARC_RUF_PRESENT` | info | 6.3 |
| `DMARC_ALIGNMENT_STRICT` | info | 6.3 |
| `DMARC_INHERITED_FROM_ORG` | info | 6.6.3 |
| `DMARC_P_ASSUMED_NONE` | low | 6.6.3 |
| `DMARC_NO_USABLE_POLICY` | high | 6.6.3 |
| `DMARC_DNS_ERROR` | medium (status `error`) | none |
| `DMARC_EXTERNAL_UNAUTHORIZED` | medium | 7.1 |
| `DMARC_EXTERNAL_AUTH_UNVERIFIED` | medium | 7.1 |
| `DMARC_EXTERNAL_AUTH_RECORD_INVALID` | low | 7.1 |
| `DMARC_EXTERNAL_AUTH_RECORD_UNPARSEABLE` | medium | 7.1 |
| `DMARC_EXTERNAL_OVERRIDE_MISMATCH` | medium | 7.1 |
| `DMARC_EXTERNAL_NOT_CHECKABLE` | low | 7.1 (our interpretation: a URI that names several hosts) |
| `DMARC_EXTERNAL_TOO_MANY_DESTINATIONS` | low | none (we check at most 8 destinations) |

Inherited record (found at the organizational domain for a subdomain target): the applied policy is
`sp` when present and valid, else `p` (RFC 7489 section 6.3). `effective_policy`, `DMARC_POLICY_NONE`,
`DMARC_POLICY_QUARANTINE` and `DMARC_PCT_PARTIAL` are derived from it, and `DMARC_SUBDOMAIN_POLICY_WEAKER`
is not emitted (it describes the parent). `data["p"]` and `data["sp"]` stay as published. An invalid `sp`
follows the section 6.6.3 step 6 path as before.

### DKIM (RFC 6376, RFC 8301)

| Code | Severity | RFC |
|---|---|---|
| `DKIM_NO_SELECTOR_FOUND` | info | none |
| `DKIM_KEY_SYNTAX_ERROR` | medium | RFC 6376 (key record tags) |
| `DKIM_KEY_REVOKED` | low | RFC 6376 (empty `p`) |
| `DKIM_KEY_WEAK_1024` | low | RFC 8301 (recommends 2048-bit signing keys) |
| `DKIM_KEY_TOO_SHORT` | medium | RFC 8301 (verifiers must not accept RSA below 1024 bits) |
| `DKIM_TEST_MODE` | low | RFC 6376 (`t=y`) |
| `DKIM_MULTIPLE_RECORDS` | medium | none |
| `DKIM_CNAME_LOOP` | medium | none |
| `DKIM_CNAME_CHAIN_LONG` | low | none (we follow at most 8 hops) |
| `DKIM_PROBE_ERRORS` | low | none |
| `DKIM_NO_SELECTORS_PROBED` | low | none |
| `DKIM_SELECTORS_CAPPED` | low | none |
| `DKIM_NON_KEY_TXT` | info | none |

For DKIM the finding texts cite the RFCs without section numbers, so none are given here
(`unverified`: the maintainer should add the sections after checking the RFC text).

### ESP (`esp`, M6)

`app/checks/esp_profile.py` (`EspProfileCheck`) with detection in `app/checks/esp_detection.py`;
built per domain run by `resolve_esp_run` (`app/services/domain_esps.py`). It is not in
`load_builtin_checks`: only the domain routes know `esp` (by id, in `ids` and in `all`, where it
always runs); `/api/v1/checks/free` and the CLI `check` do not. Profiles are the YAML files in
`profiles/esp/` (`docs/ESP_PROFILES.md`). Every role that may run checks on the domain gets the
full result, a client viewer on an assigned domain included (M6-06c); assigning and removing
ESPs needs `domain.update` (403 for a client viewer on an assigned domain, 404 where the domain
is invisible).

What it checks, for each ESP assigned to the domain (one section per profile in
`data["esps"]`, sorted by id):

- **SPF includes** (`spf.includes`): each include host must appear as an `include:` or
  `redirect=` target anywhere in the domain's resolved SPF tree (nested includes count). The
  part is `ok` when the term is present, but a DNS failure (servfail, timeout, ...) on the ESP's
  own record or on anything it includes, or a cap stopping resolution there, is never swallowed
  (M6-19): it adds `ESP_DNS_ERROR` with part `spf.lookups` and the result is `error`, with one
  ESP as with several. NXDOMAIN or NODATA
  on the include host is an answer, not a failure: the part stays `ok` and the missing target is
  reported by the SPF check (`SPF_INCLUDE_NOT_FOUND`). A profile with
  `spf.only_if_record: true` (M6-17, opt-in; MailUp) expects its includes only when the domain
  already has an SPF record: when the domain's TXT query completes without an SPF record
  (NXDOMAIN, NODATA, or only non-SPF TXT) the part state is `no_record`, each include
  `not_required`, and no finding is added. A DNS failure on that lookup is still
  `ESP_DNS_ERROR` and `error`; several SPF records or a syntax error are still `ESP_SPF_PERMERROR`.
- **DKIM selectors** at `<selector>._domainkey.<domain>`: a `cname` selector must be a CNAME
  whose chain (at most 8 hops) reaches a target that fits the profile's `target_pattern`
  (a `*` label is exactly one DNS label; no pattern: any target fits); a `txt` selector must
  hold a TXT record. A record of the other type is `ESP_DKIM_WRONG_TYPE`.
- **Alternative DKIM sets** (`dkim.alternatives`, M6-23; MailUp: ml01+ml02 CNAMEs or a TXT key
  at `ml00._domainkey`, maintainer decision 2026-11-12): DKIM is correct when every selector of
  `dkim.selectors` is, OR every selector of one alternative set is. With the primary set
  correct the alternatives are not queried. In an alternative, a `txt` selector counts only for
  exactly one TXT record that is a valid, not revoked DKIM key (otherwise state `invalid`,
  `reason` `syntax_error`, `revoked` or `multiple_records`). No set correct and every answer
  in: one `ESP_DKIM_NO_OPTION_SATISFIED` listing the accepted setups, instead of the
  per-selector findings. A DNS failure on a set that was needed and no set correct: only
  `ESP_DNS_ERROR` (part `dkim.selectors.<name>` or `dkim.alternatives.<name>`), status `error`.
  When a later set is correct the earlier failure gives no finding, but its `error` part in
  `data` keeps `name`, `rdtype` and `failure`. `data` adds `dkim_alternatives` and
  `dkim_satisfied_by` for these profiles only. Alternatives are never used for detection.
- **Return path / tracking domain** at the hosts entered with the assignment: the expected
  record type must exist. Profiles carry no target for these, so only the type is compared.
  No host entered: `ESP_HOST_NOT_CONFIGURED`.
- **Combined SPF lookup budget**: when two or more assigned ESPs with verified includes are
  found in the SPF tree, the tree's lookup count is attributed to them
  (`ESP_SPF_COMBINED_OVER_LIMIT` above 10, `ESP_SPF_COMBINED_NEAR_LIMIT` from 9). With two or
  more such ESPs, any DNS failure or truncation in the tree adds one `ESP_DNS_ERROR` with part
  `spf.lookups` naming all of them (`esp` "A, B"). With one, only a failure or a truncation
  (a record or query a cap stopped, state `truncated`) at or below its own include hosts does
  (`esp` that ESP); a failure elsewhere in the tree is the SPF check's.
- **Detection**: the loaded profiles that are not assigned are probed for their verified SPF
  include hosts (on the same SPF tree) and their verified `cname` selectors with a
  `target_pattern` (one CNAME query each, first target only, at most 32 names, 8 in flight).
  A hit is `ESP_DETECTED_NOT_ASSIGNED` (a possibly stale configuration); hits are listed in
  `data["detection"]`. TXT selectors and CNAME selectors without a pattern are never used for
  detection (they cannot be attributed to one ESP).

**`error` semantics.** Only NXDOMAIN and NODATA count as absence. Any other DNS state on a name
the check needs (servfail, refused, timeout, truncated, malformed, network_error, blocked,
error), a name that cannot be built, an SPF tree with a DNS failure or truncated by a cap (when
an include was not found, at or below an ESP's include host, or for the lookup budget), or an SPF record `resolve_spf` cannot follow
(several records, syntax error: `ESP_SPF_PERMERROR`) makes that part not evaluated and the
result `error`, never `ok` and never "missing". In detection, a failed DKIM probe makes the
result `error` and stops new probes; an SPF tree with a failure, truncation or permerror makes
it `error` when a candidate with verified includes cannot be ruled out. A profile id stored for the domain that is no longer loaded
adds `ESP_PROFILE_UNAVAILABLE` and makes the result `error`; profiles that cannot be loaded, or
a repository failure, give `CHECK_INTERNAL_ERROR` (status `error`).

**Unverified fields.** A profile with status `unverified` adds `ESP_PROFILE_UNVERIFIED` (info,
evidence the unverified fields). The parts named in `unverified_fields` (and their children)
are not queried and get no verdict: their state is `skipped_unverified` and they are listed in
the section's `skipped`. Unverified fields are never used for detection, and an unverified
pitfall is not reported.

No ESP assigned: `ESP_NONE_ASSIGNED` (info) plus any detection findings.

| Code | Severity | Notes |
|---|---|---|
| `ESP_SPF_INCLUDE_MISSING` | high | include host not in the SPF tree |
| `ESP_SPF_INCLUDE_AFTER_ALL` | high | include host present only after the first `all` of a record: never evaluated (RFC 7208 5.1, R1-17); replaces `ESP_SPF_INCLUDE_MISSING` for that host |
| `ESP_SPF_PERMERROR` | high (status `error`) | include not found and a record in the tree is a permerror |
| `ESP_DKIM_RECORD_MISSING` | high | selector name absent |
| `ESP_DKIM_TARGET_MISMATCH` | medium | no CNAME in the chain fits `target_pattern`; `reason` `chain_end`, `loop`, `empty_target` or `hop_limit` |
| `ESP_DKIM_WRONG_TYPE` | medium | TXT where a CNAME is expected, or the reverse |
| `ESP_DKIM_NO_OPTION_SATISFIED` | high | profile has `dkim.alternatives` and no DKIM set (primary or alternative) is satisfied; params list every accepted setup |
| `ESP_RETURN_PATH_MISSING` | medium (info if the profile marks it optional) | NXDOMAIN at the return-path host |
| `ESP_RETURN_PATH_MISMATCH` | medium (info if optional) | the host exists without the expected record type |
| `ESP_TRACKING_MISSING` | low (info if optional) | NXDOMAIN at the tracking host |
| `ESP_TRACKING_MISMATCH` | low (info if optional) | the host exists without the expected record type |
| `ESP_HOST_NOT_CONFIGURED` | info | no return-path or tracking host entered for the assignment |
| `ESP_PROFILE_UNVERIFIED` | info | the profile has unverified fields (not evaluated) |
| `ESP_PITFALL` | info | static advice from the profile; the declared severity is only a param |
| `ESP_NONE_ASSIGNED` | info | no ESP assigned to the domain |
| `ESP_DNS_ERROR` | low (status `error`) | params name, record type and state |
| `ESP_SPF_COMBINED_OVER_LIMIT` | high | two or more assigned ESPs, SPF over 10 lookups or truncated |
| `ESP_SPF_COMBINED_NEAR_LIMIT` | low | two or more assigned ESPs, 9 or 10 lookups |
| `ESP_DETECTED_NOT_ASSIGNED` | low | DNS records of a loaded ESP that is not assigned |
| `ESP_DETECTION_TRUNCATED` | low | detection stopped at the 32-name DKIM cap (partial) |
| `ESP_PROFILE_UNAVAILABLE` | low (status `error`) | assigned profile id no longer loaded (`app/services/domain_esps.py`) |

None of these cite an RFC section: they compare DNS with the ESP profile data. The acceptance
tests in `tests/esp/test_acceptance.py` run every shipped profile against a zone built from the
profile (`tests/esp/dns_builder.py`) and its mutations; `tests/api/test_esp_acceptance.py`
covers assignment and run end to end.

### DNSBL / URIBL (`dnsbl`, M7-05)

`app/checks/dnsbl.py` (`DnsblCheck`) over the engine `app/checks/dnsbl_engine.py` and the list
data `seeds/dnsbl.yaml` (`docs/DNSBL.md`). Registered in `load_builtin_checks`, so it is part of
`all` and of the CLI default.

- **Targets (choice).** A domain name runs the `domain` lists. An IP literal runs the `ip` lists,
  but only on the tenant-less routes: `/api/v1/checks/free` and the CLI, and only when the request
  is the `dnsbl` check alone (an IP is a 422 / usage error for any other check). The domain routes
  always use the registered domain name. The IPs that a domain's MX/A records resolve to are NOT
  checked (out of scope for M7-05). Private, loopback, link-local, documentation, multicast and
  IPv4-mapped forms of those are never queried (`not_applicable`); the query-name builder is
  private to the engine, which applies that rule first.
- **Status.** Any list `error` (refused, resolver refused, blocked resolver, unverified list, DNS
  failure, unmapped or malformed answer) gives status `error` AND a finding naming the list.
  Never `ok` when any list errored. A list `listed` gives `DNSBL_LISTED` with a severity from the
  category (our own mapping in `CATEGORY_SEVERITY`: malware, phishing, cracked_site `high`;
  unknown `medium`; informational categories `low`). All clean gives `ok`.
- **Finding codes.** `DNSBL_LISTED`, `DNSBL_LIST_ERROR`, `DNSBL_LIST_REFUSED`,
  `DNSBL_LIST_UNVERIFIED`; the list name, return code, category and reason are params (templates
  escape them; the CLI escapes control characters). `DNSBL_NO_LISTS_APPLICABLE` (info) says that
  nothing was queried (every list disabled or not applicable), so that is never shown as clean.
- **Enablement (M7-05c).** A list with `default_enabled: false` (all three shipped lists today)
  runs only if its id is in the check's `enabled_ids`. The instance admin sets them
  (`docs/DNSBL.md`, "Enablement"); they are stored in `dnsbl_list_enablements` and read per request
  on every run path: the domain routes (`dnsbl` by id, in `ids` or in `all`), the free route and
  the CLI (`app.services.checks.with_dnsbl_enabled`). A disabled list is `not_applicable` /
  `list_disabled` and no DNS query is sent. The CLI reads the configured database; if it cannot
  (no configuration, no schema, driver error) it prints a localized notice on stderr and the
  `dnsbl` result is `error` with `DNSBL_ENABLEMENT_UNAVAILABLE` (reason `enablement_unavailable`,
  no query sent, exit 2); there is no fallback list set. Other checks of the run are unaffected.
- **Permissions.** Same as every check: `check.run` on a tenant domain, `dns.tools` on the free
  route; the CLI has none.

## Surfaces

All three call `app/services/checks.py` and print the same `CheckResult` JSON.

- **UI.** `/domains/{id}/authentication` renders SPF and DMARC server-side and streams the DKIM
  probe over SSE from `/domains/{id}/authentication/dkim/stream` (one event per selector, then
  `done`, a 60 s overall deadline). `/tools/dkim/stream?name=...` is the free variant. Opening the
  tab runs the checks (there is no stored result).
- **API.** All POST, same CSRF rules as `/api/v1/domains`:
  - `/api/v1/domains/{id}/checks/{check_id}`: one check (an object) or `all` (an array sorted by id);
  - `/api/v1/domains/{id}/checks` with `{"ids": [...]}`: an array in request order;
  - `/api/v1/checks/free` with `{"name": ..., "ids": [...]}`: no tenant data.

  Up to 8 ids per request; unknown or duplicate ids, a bad name or a bad body give 422. A DNS
  failure is data, not an HTTP error: the response is 200 with status `error`.
- **CLI.** `dtk check <domain> [--only a,b] [--format text|json] [--lang en|it] [--selector NAME]`
  (also `python -m app.cli check`). One `--only` id prints an object; several ids, or none (all
  checks), print an array. It needs shell access to the instance, uses no tenant data and no
  database, and reads the resolver from the same environment settings as the app. `--selector`
  adds ad-hoc DKIM selectors for that run only.

`--format json` output is byte-equal to the API body (arrays are joined as `[a,b]` without spaces).

### CLI exit codes

| Code | Meaning |
|---|---|
| 0 | all results `ok` or `info` |
| 1 | any `warn` or `fail` |
| 2 | any `error` (could not evaluate), or a configuration error |
| 64 | usage error (unknown or duplicate check, bad domain, format or language) |

## CLI `analyze` (M4)

`dtk analyze <file|-> [--format text|json] [--lang en|it]` (also `python -m app.cli analyze`)
analyzes one raw message from a file, or from stdin with `-`. It is offline, uses no tenant data
and no database, and reads at most 2 MiB. See `docs/HEADERS.md` for what is analyzed.

`--format json` prints `MessageAnalysis.model_dump_json()` followed by exactly one trailing
newline (added by `typer.echo`); the REST body is the same bytes without the newline.

| Code | Meaning |
|---|---|
| 0 | no finding above info |
| 1 | any `warn` or `fail` |
| 2 | status `error`, or unreadable, oversize, empty or NUL input |
| 64 | usage error (unknown format or language) |

## Permissions

- `check.run`: run checks on one tenant domain (REST domain routes, the DKIM stream, the
  Authentication tab). Owner, admin and analyst have it; a client viewer has it only on assigned
  domains. It can be denied per user with the feature toggle `{"check.run": false}`.
- `dns.tools`: the free (tenant-less) routes, `/api/v1/checks/free` and `/tools/dkim/stream`. Owner,
  admin and analyst; never a client viewer. Deniable with `{"dns.tools": false}`.
- Anonymous requests get 401 (or a redirect to login in the browser); an invisible domain (missing,
  another tenant's, or unassigned to a client viewer) gets 404. A denied request sends no DNS
  query. The CLI `check` and `analyze` commands have no permission model: their trust boundary is
  shell access to the instance.

### CLI commands that use tenant data

`app/cli/tenant_scope.py` is for commands that need tenant data (first user: M5-17). Such a
command requires `--tenant-id N --user-id M`; there is no default tenant and no system context. The
helper connects with the app configuration and builds the principal and `TenantContext` the same
way as the web layer, then runs the same `can()`. A denied command does not run.

These options select who the command acts as. They are **not authentication**: anyone with shell
access and the database configuration can name any user, and the database configuration alone
already gives full access to the data. The trust boundary remains shell access. The permission
check keeps the CLI consistent with the web (for example, a client viewer cannot run an action
the web denies them); it does not protect the instance from its operator.

| Code | Meaning |
|---|---|
| 0 | the command ran (the command may define further result codes, as `check` does) |
| 2 | could not evaluate: missing or invalid configuration, database unreachable, schema not migrated, or a database driver error while the command runs |
| 64 | usage error: missing option, or an id that is not a plain decimal in 1..2147483647 |
| 77 | permission denied: unknown or inactive user, no membership in that tenant, or a role or toggle without the permission (one message for all, like the web's 404) |

## How to add a check

1. Write a class with `id` and `async run(ctx, target)`; build findings only with `finding(...)`
   and results with `CheckResult.build(..., evaluated=...)`. Use `app/checks/dnsutil.py` for
   lookups so a failure cannot look like absence; return `evaluated=False` when it cannot decide.
2. Declare `CODES` in the module and add `finding.<CODE>.title|detail|remediation` to
   `locales/en.json` and `locales/it.json` (same placeholders).
3. Register it in `load_builtin_checks` (`app/checks/registry.py`).
4. Add table-driven tests with recorded zones, including malformed input and every failing lookup
   state; no network. Extend `tests/checks/test_acceptance_m3.py` if the check adds a lookup point.
5. Knowledge (selectors, rules) goes in a data file with `verified_on` and sources; do not invent
   vendor behaviour.

## Known limitations

- **DKIM selectors are unverified.** `seeds/dkim_selectors.yaml` holds probe guesses; every entry
  is `unverified` and no provider is claimed. A selector that is not in the list is not probed, so
  a DKIM result never proves DKIM is absent.
- **Public Suffix List licence.** The organizational-domain lookup (DMARC fallback and same-org
  report destinations) uses the PSL; its licence (MPL-2.0) is recorded as verified in
  `seeds/public_suffix_source.yaml`: the LICENSE text at github.com/publicsuffix/list was read on
  2026-11-12 and the maintainer accepts it.
- **No persistence.** Results are not stored: there is no history, scheduling or diff, and each
  request or page view runs the checks again.
- No per-user rate limiting yet: one request can fan out many DNS queries (the DKIM probe).
- The Authentication tab renders SPF and DMARC server-side; DKIM arrives through the stream and
  needs JavaScript.
