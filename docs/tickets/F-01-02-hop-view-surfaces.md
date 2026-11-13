# F-01-02 Per-hop authentication view: API JSON, web and CLI output
Milestone: F-01 (backlog, child of docs/tickets/F-01-auth-per-hop-view.md)
Branch: feature/f-01-02-hop-view-surfaces
Files in scope (coder confirms before coding): app/api/v1/message.py (response schema only, if it is not derived from `MessageAnalysis`), app/web/message.py, app/web/templates/message/_result.html, app/cli/analyze.py, locales/en.json, locales/it.json (UI/CLI label keys), docs/HEADERS.md (surface notes), docs/CHECKS.md (CLI `analyze` section, only if the text output is documented there), tests/api/ message analyze tests, tests/web/ message tests, tests/cli/ analyze tests
Out of scope: the hop-view service, finding logic and finding keys (F-01-01); changes to permission `message.analyze` or its checks; any new endpoint; cryptographic verification; changing `computed_dmarc`
Depends on: F-01-01
Parallel-safe: no (shares locale files and docs/HEADERS.md; serialized after F-01-01)
Model: opus
Description:
- Show the hop view from `MessageAnalysis` on all three surfaces: REST JSON (the new section appears in the schema and stays byte-equal with the service JSON and CLI `--format json`, one trailing newline), web template (ordered list/table among the hops, columns: position, kind, authserv-id or ARC domain/instance, spf, dkim, dmarc, arc), CLI text output.
- Lower Authentication-Results entries are labelled "stated by {authserv_id}, not verifiable" (en + it). Unparsed entries are labelled as unparsed. Display only.
- Escaping: web output is HTML-escaped at render time (Jinja autoescape, no `|safe`); CLI strips or escapes control characters like the existing output; no input echo beyond the bounded excerpts already in the view models.
- Labels go through i18n keys on every surface (CLI honours `--lang en|it`); no hardcoded user-facing strings.
- The REST endpoint already exists and its permission model is unchanged, but its response schema changes: keep and extend the tenancy/permission tests (anonymous 401, wrong tenant 404, denied user 403, allowed roles 200) and assert the new section is present for an allowed user and absent for a refused request.
Acceptance criteria (no network, ruff and mypy green):
- API: JSON contains the hop section for the forwarding, mailing-list, forged-lower-field, interleaved and malformed scenarios from F-01-01 (reuse its fixtures); schema test; service JSON, REST body and CLI JSON byte-equal (existing equality test extended).
- Web: each scenario renders the hop view in header-position order; lower field shows the "stated by <authserv-id>, not verifiable" text in en and it; a hostile authserv-id (`<script>`, control characters, very long) is escaped and bounded; malformed fields render as unparsed without an error page.
- CLI text: each scenario prints the hop view; `--lang it` output uses it labels; exit codes unchanged by the new section (the info finding does not change the status beyond `info`).
- Permission tests above pass for the changed endpoint (non-negotiable: tenancy/permission test for the changed endpoint).
- i18n: every new key exists in en and it (the repo's locale-parity test is green).
- Existing API/web/CLI message tests stay green.
New i18n keys (en + it; final names set by the coder): hop view title and column labels (position, kind, authserv-id, instance, spf, dkim, dmarc, arc), kind names, "stated by {authserv_id}, not verifiable", "unparsed", empty-state text for a message with no hop data.
Status: todo
