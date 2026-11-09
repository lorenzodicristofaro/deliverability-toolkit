# Checks (M3)

How the deliverability checks work, as implemented. Design rules live in `ARCHITECTURE.md`
(section 3); DNS behaviour is in `docs/DNS.md`. Checks run live; **nothing is persisted in M3**.

## Check interface

A check is a class with a string `id` and `async run(ctx: CheckContext, target: Target) -> CheckResult`
(`app/checks/models.py`, protocol `Check`). Registered ids: `dkim`, `dmarc`, `spf`.

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
- **DKIM rule.** Selectors cannot be enumerated in DNS, so the check probes a seed list and never
  claims DKIM is absent. Failed selectors are always listed in `DKIM_PROBE_ERRORS`. If at least
  one selector is found, the status follows the findings. If none is found and any failed, the
  status is `error`. `DKIM_NO_SELECTOR_FOUND` appears only when every selector was `not_found`.
  A probe cut short by the stream deadline is `error`.
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
| `SPF_RECORD_TOO_LONG` | medium (answer over 450 octets) or info (a string over 255 octets) | 3.3, 3.4 |
| `SPF_RESOLUTION_TRUNCATED` | info | 4.6.4 |
| `SPF_FLATTENING_HINT` | info | none (advisory; no addresses are generated) |
| `SPF_DNS_ERROR` | medium (status `error`) | 4.4 |
| `SPF_MX_TOO_MANY_HOSTS` | high | 4.6.4 |

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

For DKIM the finding texts cite the RFCs without section numbers, so none are given here
(`unverified`: the maintainer should add the sections after checking the RFC text).

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
  report destinations) uses the PSL; its licence is recorded as `unverified` in
  `seeds/public_suffix_source.yaml` and the maintainer still has to confirm it.
- **No persistence.** Results are not stored: there is no history, scheduling or diff, and each
  request or page view runs the checks again.
- No per-user rate limiting yet: one request can fan out many DNS queries (the DKIM probe).
- The Authentication tab renders SPF and DMARC server-side; DKIM arrives through the stream and
  needs JavaScript.
