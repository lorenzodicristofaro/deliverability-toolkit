# M7-20 M7 acceptance tests and docs/MONITORING.md
Milestone: M7
Branch: feature/m7-20-monitoring-acceptance
Files in scope: tests/acceptance/test_m7_monitoring.py, tests/support/ (fake clock, fake DNS zone fixtures only if missing), docs/MONITORING.md, docs/SETUP.md (monitoring settings table consolidated), TODO.md (M7 checkboxes), docs/HANDOFF.md is NOT touched (GM owns it)
Out of scope: feature code (defects found go back as new tickets), SPEC.md
Depends on: M7-02, M7-05, M7-13, M7-16, M7-17, M7-18, M7-19
Parallel-safe: no (final ticket)
Model: sonnet (QA opus)
Acceptance criteria:
- Scenario "scheduled runs respect rate limits": many targets sharing DNSBL lists and one remote host, fake clock and fake resolver, run the scheduler for a simulated period; assert per-list and per-host query counts never exceed the configured rate, no target starves, skipped targets run later.
- Scenario "changes produce alerts exactly once": baseline run, change an SPF/DMARC record in the fake zone, run, run again unchanged, restart (rebuild services over the same DB), run again, revert, run; assert exactly one alert per transition, one delivery per channel (fake channels incl. a failing-then-succeeding one), none re-sent after restart, an `error` run (SERVFAIL) produces no change alert and no clearing alert, a DNSBL list refusal produces no new_listing.
- Cross-tenant scenario: two tenants monitor the same domain name; events, alerts and channels never cross.
- An end-to-end guard test: no outbound HTTP library call outside app/net during the scenarios.
- docs/MONITORING.md: architecture of scheduler, rate limit keys and settings, history and retention, snapshot/diff semantics (error != removed), event kinds and fingerprint, alert delivery guarantees (honest statement of the exactly-once limit from M7-14), channel setup (email, webhook payload and signature, Slack, Teams with the sources and retrieval dates and every `unverified` item), what is NOT in M7 (certificate/key expiry alerts, Postmaster/SNDS in M11), DNSBL list table link to docs/DNSBL.md, operator checklist.
- TODO.md: M7 checkboxes ticked by the GM at merge, not by this ticket's coder except this ticket's own line.
New i18n keys: none
Status: todo
