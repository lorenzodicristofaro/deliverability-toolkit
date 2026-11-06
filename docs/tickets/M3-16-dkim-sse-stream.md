# M3-16 DKIM probe SSE stream
Milestone: M3
Branch: feature/m3-16-dkim-sse
Files in scope: app/web/checks_stream.py, app/main.py (router registration only), app/web/templates/checks/_dkim_row.html (HTML fragment per selector), locales/en.json, locales/it.json (checks.dkim.* UI keys), tests/web/test_checks_stream.py, tests/tenancy/ (route classification)
Out of scope: the tab page itself (M3-17), JS beyond what M3-17 owns, tenant selectors (M5)
Depends on: M3-13, M3-14
Parallel-safe: no (app/main.py, locale files)
Model: sonnet
Acceptance criteria:
- `GET /domains/{domain_id}/authentication/dkim/stream` (text/event-stream) iterates `probe_selectors` and emits one event per selector as soon as it is ready (`event: selector`, data = rendered HTML fragment, escaped; selector names and record text are untrusted DNS data), then `event: done` with the summary Finding list rendered; a failure in one selector yields a row with an error state, never an empty/`not found` row.
- Free variant `GET /tools/dkim/stream?name=...` gated by `Action.DNS_TOOLS`.
- Same data as `POST /api/v1/.../checks/dkim` (the stream reuses the generator, test asserts the set of per-selector states equals the REST `data["selectors"]`).
- Gated by `Action.CHECK_RUN` / `DNS_TOOLS`; tenancy/permission tests for both routes (client viewer assigned vs unassigned, other tenant 404, anonymous redirect/401 per existing web convention). Client disconnect cancels the probe tasks (test with a cancelled generator).
- Response headers: `Cache-Control: no-store`, `X-Accel-Buffering: no`; works under the existing CSP (no inline script).
- Rows show the static note that selectors cannot be enumerated (key `checks.dkim.not_enumerable`).
New i18n keys: checks.dkim.row.*, checks.dkim.not_enumerable, checks.dkim.done (en + it)
Status: todo
