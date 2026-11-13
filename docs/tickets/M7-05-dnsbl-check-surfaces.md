# M7-05 DNSBL check registration, API, CLI and web fragment
Milestone: M7
Branch: feature/m7-05-dnsbl-surfaces
Files in scope: app/checks/dnsbl.py, app/checks/registry.py, app/checks/finding_text.py, app/services/checks.py, app/api/v1/checks.py, app/cli/check.py, app/web (domain result fragment, existing check result template only), tests/checks/test_dnsbl_check.py, tests/api/test_dnsbl_api.py, tests/cli/test_check_dnsbl.py, locales/en.json, locales/it.json, docs/CHECKS.md
Out of scope: scheduling, history, alert rules, new migrations, seed content
Depends on: M7-03, M7-03b, M7-04
Parallel-safe: no (registry, locale files, checks API)
Model: sonnet
Acceptance criteria:
- `dnsbl` registered as a check id; domain check runs domain-kind lists, and IP lists for IPs the domain's MX/A resolve to is OUT of scope unless trivial: default is IP check only on an explicit IP input in the existing tenant-less/free check endpoints. State the choice in docs/CHECKS.md.
- Status mapping: any list `listed` -> finding with category-based severity; any list `error` (refused, blocked_resolver, unverified, dns failure) -> check status `error` AND a finding saying which list could not be evaluated; all clean -> ok. Never ok when any list errored.
- Findings carry stable codes DNSBL_LISTED, DNSBL_LIST_ERROR, DNSBL_LIST_REFUSED, DNSBL_LIST_UNVERIFIED with remediation text from i18n; list name and return code appear as params, HTML-escaped by templates.
- Permission: running it requires the existing `check.run` (tenant domains) or `dns.tools` (tenant-less), same as other checks; tenancy and permission tests copied per role including client viewer on unassigned domain -> 403/404 as existing checks do.
- CLI prints findings with control characters escaped (existing helper); no network in tests (fake DNS backend).
- `build_query_name` (app/checks/dnsbl_engine.py) must be made private, or apply the address policy (non-public check) inside itself, so no caller can skip the non-public IP check. Add a test that no public path builds a query name for a non-public IP.
- Lists with `default_enabled: false` (maintainer decision 2026-11-14: SURBL, URIBL; SpamCop pending verification) are disabled by default: a disabled list yields `not_applicable` and no DNS query is made (test asserts zero queries). The instance-admin enablement setting, UI/API and its permission test MOVED to M7-05c (GM scope decision).
New i18n keys: DNSBL_LISTED, DNSBL_LIST_ERROR, DNSBL_LIST_REFUSED, DNSBL_LIST_UNVERIFIED (.title/.detail/.remediation) plus the check's display name key (en + it)
Status: done
Outcome: dnsbl check in registry/API/CLI/web (merged bd75e5d, QA APPROVE first round). IP targets only on /checks/free and CLI as sole check. `_build_query_name` is private. Extra info finding DNSBL_NO_LISTS_APPLICABLE. All lists disabled until M7-05c; enablement criterion moved to M7-05c.
