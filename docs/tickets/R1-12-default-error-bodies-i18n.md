# R1-12 Framework default error bodies: translate, never echo input, no blank 413 pages
Milestone: R1
Branch: feature/r1-12-default-error-bodies-i18n
Findings: AUTH-07 (low)
Files in scope: app/web/checks_stream.py, app/main.py (exception handlers), app/web/templating.py (`MAX_FORM_BYTES`, 413 helper), the small-form routes returning bare 413: app/web/auth.py, app/web/setup.py, app/web/domains.py, app/web/dns_tools.py, locales/en.json, locales/it.json, tests/web/ and tests/api/ (new rows)
Out of scope: the rules-forms 413 at 1 MiB (`register_form_cap`, TODO M5-19 QA), Content-Length `isdigit()` nits (TODO), permission order, auth logic
Depends on: none
Parallel-safe: no with R1-02/R1-03/R1-13 if they touch the same route files (app/web/auth.py with R1-03; app/web/dns_tools.py with R1-02): serialize after them. Locale files shared.
Model: sonnet (error rendering and i18n; no auth logic)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- `/tools/dkim/stream`: `name` is a plain `str`; its length is checked in `_free_target` like the other routes. An over-long name gives a translated 422 that does not contain the submitted value.
- A `RequestValidationError` handler returns the generic translated 422 without `input` (en + it by Accept-Language/session language as the existing handlers do).
- `http_error`: the default 404 and 405 detail for API and non-HTML clients is translated (`GET /api/v1/nope`, `PUT /api/v1/domains` with `Accept-Language: it` give Italian text, JSON shape `{"detail": ...}` kept stable for existing clients: state in the summary what shape is used).
- Small forms over `MAX_FORM_BYTES` get a localized 413 page (or the form re-rendered with an error) instead of an empty `Response(status_code=413)` at app/web/auth.py:144,237, app/web/setup.py:195, app/web/templating.py:246, app/web/domains.py:221,277, app/web/dns_tools.py:157,188,280,359.
- `MAX_FORM_BYTES` sized for the setup form's documented maxima: setup with 128-character passwords (twice) plus a 200-character CJK tenant name, percent-encoded, succeeds.
- Tests: over-long SSE `name` -> translated 422 without the value; API 404/405 bodies in `it`; max-length CJK setup succeeds; oversized small form -> translated page (each small-form route table row); no input echoed anywhere in these responses.
- en/it completeness green. No network. ruff, mypy, relevant tests green; existing 401/403/404 behaviour unchanged.
New i18n keys: generic 422 validation message, 404/405 API messages, 413 page text (en + it); the coder lists exact names and reuses existing keys where they exist.
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/web/checks_stream.py:102` (`Query(max_length=...)` validated by FastAPI), `app/main.py:124-129` (only the HTML 404 is translated), `app/web/deps.py:189,208` and other bare `HTTPException(status_code=404)`, `app/web/templating.py:36,57-68` (`MAX_FORM_BYTES = 4096`), `Response(status_code=413)` at `app/web/auth.py:144,237`, `app/web/setup.py:195`, `app/web/templating.py:246`, `app/web/domains.py:221,277`, `app/web/dns_tools.py:157,188,280,359`.
- Problem: three paths answer with text that is neither translated nor under the "never echo input" rule. (1) An over-long `name` on `/tools/dkim/stream` gets FastAPI's default 422, English, returning the whole submitted value. (2) Unknown API paths, wrong methods and bare 404s for non-HTML clients answer `{"detail":"Not Found"}` / `"Method Not Allowed"`. (3) Small forms over 4096 bytes get an empty 413 with no page. The setup form can reach that limit with valid input: 128-character passwords (twice) plus a 200-character tenant name in CJK are over 4096 bytes once percent-encoded.
- Evidence (run): `GET /tools/dkim/stream?name=AAAA...(1030)` with `Accept-Language: it` -> 422 `{"detail":[{"type":"string_too_long","loc":["query","name"],"msg":"String should have at most 1024 characters","input":"AAAA..."}]}`; `GET /api/v1/nope` -> `{"detail":"Not Found"}`; `PUT /api/v1/domains` -> `{"detail":"Method Not Allowed"}`.
- Suggested fix: as in the criteria (plain `str` + `_free_target` check; `RequestValidationError` handler; translate default 404/405 in `http_error`; localized 413 page; size `MAX_FORM_BYTES`).
- Tests to add: as in the criteria.
- Confidence: high.
- Related TODO: the localized 413 for the rules forms stops at 1 MiB (M5-19 QA) and the `isdigit()` nits: not here.
