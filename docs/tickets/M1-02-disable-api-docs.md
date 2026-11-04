# M1-02 Disable unauthenticated /docs, /redoc, /openapi.json
Milestone: M1
Branch: feature/m1-02-disable-api-docs
Files in scope: app/main.py, tests/test_health.py (extend), tests/test_api_docs_disabled.py (ARCHITECTURE.md is not edited; report to GM instead)
Out of scope: serving OpenAPI behind auth (M10 "Docs site, OpenAPI"), API keys, any auth code
Depends on: M1-01
Parallel-safe: no (app/main.py)
Model: sonnet
Acceptance criteria:
- M0-03 follow-up decision: `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`; GET /docs, /redoc, /openapi.json return 404 for anonymous clients (tests).
- /healthz still returns 200.
- A code comment states that M10 re-exposes OpenAPI behind authentication.
- GM decision 2026-11-04 (M1-01 Q2): disable; revisit with auth/API keys in M10.
New i18n keys: none
Status: todo
