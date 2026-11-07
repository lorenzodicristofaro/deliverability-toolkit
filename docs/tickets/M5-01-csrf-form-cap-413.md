# M5-01 CSRF form-body cap vs localized 413
Milestone: M5
Branch: feature/m5-01-csrf-form-cap
Files in scope: app/core/csrf.py, app/web/message.py, the message template/JS that sets `data-max-bytes` (coder names them), tests/core/test_csrf.py, tests/web/test_message_ui.py
Out of scope: content UI (M5-16, which reuses this), new dependencies, locale files (reuse the existing message 413 key).
Depends on: none
Parallel-safe: yes (core/csrf + message web only; disjoint from M5-02, M5-03)
Model: opus (CSRF is a security control)
Follow-up closed: TODO "Message UI (M4-12): CSRFMiddleware rejects form bodies > 1 MiB..." and "JS data-max-bytes is 2 MiB but form posts over 1 MiB hit the CSRF 403".
Acceptance criteria:
- A urlencoded form body over MAX_FORM_BYTES is never buffered beyond the cap. Decision to implement: for routes that opt in to a larger form cap (message analyze, and later content analyze, via a small registry/param in csrf.py), the cap is raised to that route's limit; for all other routes an oversize body still gets a refusal. The refusal for an opted-in route is the localized 413 of that route, not 403.
- CSRF is still enforced: oversize body with a missing/invalid token is rejected (no bypass by sending a big body); valid token + body under the route cap passes.
- JS `data-max-bytes` equals the real server cap (single constant, imported, not duplicated); a test asserts the rendered attribute equals the constant.
- Tests: body at cap-1, cap, cap+1 for both the default and the opted-in route; no-JS and JS-style posts; streaming (chunked) body with no Content-Length is cut at the cap.
- Existing 403-on-missing-token behaviour unchanged for every other route (regression test).
New i18n keys: none
Status: todo
