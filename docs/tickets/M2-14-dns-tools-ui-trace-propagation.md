# M2-14 DNS tools web UI: trace and propagation views
Milestone: M2
Branch: feature/m2-14-dns-tools-ui-trace-propagation
Files in scope: app/web/dns_tools.py (extend), app/web/templates/dns/trace.html, app/web/templates/dns/propagation.html, locales/en.json, locales/it.json, tests/web/test_dns_tools_trace_ui.py, tests/tenancy/ (route classification)
Out of scope: SSE/streaming, charts, history, new JS
Depends on: M2-13 (and M2-09, M2-10 via the M2-12 API/services)
Parallel-safe: no (same files as M2-13; locales)
Model: sonnet
Acceptance criteria:
- `/tools/dns/trace`: renders the hop list in dig +trace style (zone, server, referral NS set, state, elapsed), final answer or failure; blocked hops shown with a clear "skipped: address not allowed" message; limit/loop outcomes have their own messages.
- `/tools/dns/propagation`: table with one row per resolver (name, operator, state, records, TTL), agreement summary (consistent / differing / inconclusive), "not evaluated" resolvers listed separately and visibly distinct from "missing" (test as in M2-13); unverified resolver entries labelled.
- Permission: same gate as M2-13 (`dns.tools`; client viewer 403, anonymous redirect); tenancy/permission test per route.
- i18n en + it for all new text, both rendered in tests; all DNS data escaped.
New i18n keys (en + it): tools.dns.trace.title, tools.dns.trace.hop, tools.dns.trace.zone, tools.dns.trace.server, tools.dns.trace.referral, tools.dns.trace.skipped_blocked, tools.dns.trace.outcome.loop, tools.dns.trace.outcome.depth_exceeded, tools.dns.trace.outcome.all_failed, tools.dns.trace.outcome.lame, tools.dns.propagation.title, tools.dns.propagation.resolver, tools.dns.propagation.consistent, tools.dns.propagation.differing, tools.dns.propagation.inconclusive, tools.dns.propagation.not_evaluated, nav.tools.dns.trace, nav.tools.dns.propagation
Status: todo
