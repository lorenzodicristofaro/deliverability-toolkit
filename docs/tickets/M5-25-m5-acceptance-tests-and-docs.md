# M5-25 M5 acceptance tests and docs/CONTENT.md
Milestone: M5
Branch: feature/m5-25-acceptance
Files in scope: tests/content/test_acceptance_m5.py, docs/CONTENT.md, docs/reports/M5.md, TODO.md (M5 checkboxes and status line), README.md (link only, if M4 did the same for HEADERS.md)
Out of scope: new features; fixes found go back as separate tickets.
Depends on: all M5-01..M5-24
Parallel-safe: no (last ticket)
Model: sonnet
Acceptance criteria:
- "Rules editable without redeploy": through the admin API, as a tenant admin create a rule, run content analysis and see the match; edit the weight and see the new score; disable it and see it gone; no restart or re-seed between steps. Same for a global rule by an instance admin, visible to two tenants, and a tenant rule invisible to the other tenant.
- "Regex timeout enforced": a catastrophic admin-supplied rule (a) is cut off in `POST /rules/test` with `timed_out`, (b) inside a full analysis yields a rule-level `error` and overall status `error`, with a wall-clock bound; the other rules still ran.
- Surfaces equal: service = API = CLI JSON byte-equal; UI status/codes equal. Zero DNS and sockets during content analysis (links never fetched).
- Custom check acceptance: DNS kinds work end to end with a fake DNS backend; `http_fetch` rejected at schema, API and UI.
- docs/CONTENT.md documents: inputs and limits, every CONTENT_* code, static link analysis (no fetching), List-Unsubscribe/One-Click with the RFC 2369 / RFC 8058 section citations from M5-10, rule model (scope, weights, categories, language), seed provenance (`verified_on`, sources, which rules are `unverified`), ReDoS guard design and caps, custom check DNS kinds and the M7 deferral of http_fetch, and heuristic thresholds flagged as unverified.
- Report lists the unverified seed items and shortener entries awaiting maintainer confirmation.
New i18n keys: none
GM notes (from M5-10): docs/CONTENT.md must carry the List-Unsubscribe citations from app/parsers/list_unsubscribe.py's docstring (RFC 2369 §2, §3, §3.2; RFC 8058 §3.1, §4, §5; RFC 5234 §2.3) and the documented heuristics: case-insensitive One-Click match (exact match exposed as post_value_exact), eligibility requires exactly one of each field, the one-space ABNF rule is not checked, and the parser limits are project choices.
Status: done
