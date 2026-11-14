# M7-05c DNSBL list enablement by instance admin
Milestone: M7
Branch: feature/m7-05c-dnsbl-enablement
Files in scope: app/models (new instance-level table), migrations/versions (one new revision), app/repositories (new dnsbl enablement repo), app/api/v1 (instance-admin dnsbl lists router + registry entry), app/web (minimal admin page + template), app/checks/dnsbl.py, app/checks/registry.py, app/services/checks.py, app/api/v1/checks.py, app/cli/check.py, audit facility (only if one exists), tests/checks/test_acceptance_m3.py, tests/api/test_dnsbl_enablement.py, tests/repositories/test_dnsbl_enablement.py, tests/migrations, locales/en.json, locales/it.json, docs/DNSBL.md, docs/CHECKS.md
Out of scope: Spamhaus DQS (M7-05b), scheduling, per-tenant enablement, new list seed content
Depends on: M7-05
Parallel-safe: no (migration, models, locale files, router registry, checks API). Serialize with every other migration ticket (take the next revision at merge time).
Model: opus (permissions + migration)
Acceptance criteria:
- Instance-level table of enabled DNSBL list ids: list id, enabled_by, enabled_at, policy_acknowledged (bool), policy_acknowledged_at, unverified_confirmed (bool). Access only through a repository.
- Migration is the next revision; up/down tested on SQLite and PostgreSQL.
- Instance-admin-only API: list lists (usage-policy text, source links, verified/unverified status, enabled state); enable requires explicit policy acknowledgement (rejected without it); disable. Lists with unverified status require a second explicit confirmation to enable. No vendor policy text invented: shown text comes from seeds/dnsbl.yaml; if absent, state so in the UI.
- Minimal admin UI page for the same, i18n en + it, no hardcoded strings, output escaped.
- Enable/disable written to the audit log if an audit facility exists; otherwise note "no audit facility" in Outcome.
- `enabled_ids` loaded per request and passed to the dnsbl check on registry, API and CLI paths; disabled lists still yield `not_applicable` with zero DNS queries.
- Permission tests: instance admin only; every tenant role (incl. client viewer) gets 403/404 on list/enable/disable; unauthenticated rejected.
- QA nit: tests/checks/test_acceptance_m3.py:468-478 inject an enabled list so "servfail everywhere" asserts `error` on every surface.
- QA nit: one shared helper for the IP-target rule, used by app/api/v1/checks.py:170-176 and app/services/checks.py:55-64; behavior unchanged, existing tests pass.
New i18n keys: admin page title, list columns, enable/disable actions, policy acknowledgement text, unverified second-confirmation text, error messages (en + it)
Status: done
Outcome: merged into dev (commits 5e70100 + ff73bb9), QA APPROVE round 2.
- instance.manage only (list/enable/disable); policy acknowledgement required, plus a second confirmation for unverified lists.
- Migration 0010 (integer id + unique list_id).
- No audit facility exists: enable/disable are logged as structured events.
- Round 1 CHANGES REQUESTED: CLI with unreadable enablement now gives error DNSBL_ENABLEMENT_UNAVAILABLE, exit 2 (no fallback).
- Both M7-05 QA nits closed.
- Files added beyond scope: enablement service, app/main.py, ARCHITECTURE.md, tenancy/id-range/async-guard test registrations, tests/cli/test_check_dnsbl.py loader stub.
Follow-up (low): no nav link to the /dnsbl-lists admin page yet.
