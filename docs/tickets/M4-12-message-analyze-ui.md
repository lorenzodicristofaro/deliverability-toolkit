# M4-12 Web UI: paste or upload headers/.eml
Milestone: M4
Branch: feature/m4-12-ui
Files in scope: app/web/message.py, the template(s) under the existing templates dir for the page (new files), app/main.py (one include_router line plus nav link), tests/web/test_message_ui.py, locales/en.json, locales/it.json
Out of scope: API changes, CLI, storage, multipart/new dependencies.
Depends on: M4-06, M4-10 (M4-11 not required: UI calls the service directly, same as web/dns_tools.py does)
Parallel-safe: no (app/main.py router registry and locale files)
Model: sonnet
Acceptance criteria:
- Page `/tools/message` (tenant-level, no domain): textarea for paste plus a file picker that reads the `.eml` in the browser into the textarea (FileReader; no multipart, no server-side file handling). Server cap enforced on the POST body (MAX_RAW_BYTES + form overhead) with a localized 413 message; NUL -> localized error.
- Result rendering from `MessageAnalysis`: Received hop table with delays (negative highlighted), Authentication-Results table, ARC chain, alignment table, MIME tree and size breakdown, findings list with severity badges. All user-controlled values auto-escaped; test with `<script>` in subject/hostnames.
- CSRF as other POST forms; 401/redirect anonymous, 403 for client viewer (nav link hidden for them), analyst/admin/owner allowed. Denied requests never run the analyzer (spy).
- Route added to the route-coverage matrix. No hardcoded strings: i18n scan passes. Page works with JS disabled for paste.
- Nothing stored; the pasted text is not echoed into logs, URLs or cookies; response `Cache-Control: no-store`.
New i18n keys: message.page.title, message.form.label, message.form.file, message.form.submit, message.error.too_large, message.error.nul_byte, message.error.empty, message.section.received, message.section.authres, message.section.arc, message.section.alignment, message.section.mime, message.section.size, message.section.findings, message.col.* (hop, from, by, delay, time, method, result, instance, domain, aligned, type, bytes) (en + it)
Status: todo
