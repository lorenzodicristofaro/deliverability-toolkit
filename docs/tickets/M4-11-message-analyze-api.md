# M4-11 REST endpoint POST /api/v1/message/analyze
Milestone: M4
Branch: feature/m4-11-api
Files in scope: app/api/v1/message.py, app/api/__init__.py (one include_router line), tests/api/test_message_analyze.py, locales/en.json, locales/it.json
Out of scope: UI, CLI, new dependencies (no multipart: the body is raw), storage.
Depends on: M4-06, M4-10
Parallel-safe: no (router registry app/api/__init__.py and locale files)
Model: sonnet
Acceptance criteria:
- POST body is the raw message/headers, Content-Type `message/rfc822` or `text/plain` (else 415); response is the `MessageAnalysis` JSON from M4-10, byte-equal to the service output.
- Size cap enforced WHILE reading (stream with a counter, same style as `_common.py` MAX_BODY_BYTES but with the M4-01 MAX_RAW_BYTES limit): over cap -> 413 without buffering the rest; also reject by Content-Length first. NUL byte -> 422 `{key, message, field, reason}` shape used by dns_tools, never echoing input. Empty body -> 422.
- Auth: 401 anonymous (CSRF rules as other mutating routes), 404 no/stale active tenant, 403 when `can(principal, Action.MESSAGE_ANALYZE, TenantResource(tenant_id))` is false (client viewer, toggle false). On any denial the analyzer is NOT invoked (assert via monkeypatch spy).
- Tenancy/permission test per role (owner, admin, analyst allowed; client viewer, foreign tenant, anonymous denied) and the route added to the route-coverage matrix (tests/web/test_domains_ui.py pattern; coder updates the matrix file and names it in the summary).
- Offline: test with sockets blocked and a DNS backend fake that asserts zero queries.
- Nothing stored: test asserts no DB row counts change and no request content in logs (caplog).
New i18n keys: api.message.error.unsupported_media_type, api.message.error.too_large, api.message.error.nul_byte, api.message.error.empty (en + it)
Status: todo
