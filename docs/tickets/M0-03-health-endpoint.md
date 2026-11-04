# M0-03 Minimal FastAPI app with /healthz
Milestone: M0
Branch: feature/m0-03-health-endpoint
Files in scope: app/main.py, app/web/__init__.py, app/web/health.py, tests/test_health.py, pyproject.toml (add runtime deps fastapi, uvicorn, httpx for tests only), uv.lock
Out of scope: config/logging/DB (M1), /readyz and /metrics, templates, HTML UI, i18n scaffolding (M1), Docker, CI
Depends on: M0-02
Parallel-safe: no (edits pyproject.toml/uv.lock)
Model: sonnet
Acceptance criteria:
- `app.main:app` is a FastAPI instance (ARCHITECTURE section 1); `GET /healthz` returns 200 with JSON `{"status": "ok"}` (ARCHITECTURE section 12 names `/healthz`). Router lives under `app/web/` or equivalent per layout; keep it trivially small.
- The response is a machine-readable status token, not user-facing prose; no HTML and no hardcoded user-facing strings. Rationale: i18n scaffolding is M1, so the "health page" for the milestone is this JSON endpoint (see open question to GM).
- tests/test_health.py: TestClient/httpx test asserting 200 and body; no network. Tenancy/permission test not applicable (unauthenticated, no tenant data); state this in the summary.
- ruff, mypy, pytest green; run command from CLAUDE.md works and serves /healthz.
New i18n keys: none
Status: done (QA APPROVE, merged to dev in 96b5141)

Follow-up for M1: FastAPI currently exposes /docs, /redoc and /openapi.json without auth. M1 must decide whether to disable them (docs_url/openapi_url=None) or put them behind auth.
