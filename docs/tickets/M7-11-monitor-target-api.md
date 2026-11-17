# M7-11 Monitor target API and permissions
Milestone: M7
Branch: feature/m7-11-monitor-api
Files in scope: app/api/v1/monitors.py, app/services/monitors.py, app/core/permissions.py (new permission `monitor.manage`, `monitor.read`), app/main.py (router registration only), tests/api/test_monitors.py, tests/services/test_monitors.py, locales/en.json, locales/it.json
Out of scope: web UI (M7-13), history endpoints (M7-12)
Depends on: M7-06
Parallel-safe: no (permissions, router registry, locales)
Model: opus (new permissions and tenant boundary; QA opus)
Acceptance criteria:
- Endpoints: list/create/update/delete monitor target per domain; body validated (interval from the allowed set, check ids from the registry, count caps per tenant as a setting).
- Permission matrix (add the paragraph to ARCHITECTURE section 7; add both actions to ROLE_ACTIONS and the docstring in app/core/permissions.py): `monitor.manage` = owner, admin, analyst, because SPEC section 3 gives analyst "run all checks, see all domains" and scheduling is running checks repeatedly (no credentials involved); `monitor.read` = owner, admin, analyst, plus client viewer on assigned domains only (read-only dashboards, SPEC section 3), never manage for client viewers; both deniable per user by toggle (keyed by action value, as `check.run`); no anonymous.
- Every endpoint has tenancy and permission tests: cross-tenant 404, client viewer on unassigned domain denied, toggled-off user denied, CSRF/auth as other write endpoints, domain from another tenant rejected.
- Audit log entry if an audit mechanism exists at this point (if not, note it and skip; do not build one).
New i18n keys: monitor.* error and validation messages (en + it), permission labels for the new toggles
Status: done (83f4919, QA APPROVE round 1)
Record (done):
- Routes: GET /api/v1/monitors and GET/POST/PATCH/DELETE /api/v1/domains/{id}/monitor. Router registered in app/api/__init__.py (where all /api/v1 routers live, not app/main.py).
- Test file is tests/api/test_monitors_api.py (name clash avoided with the planned test_monitors.py).
- GM-approved extras: app/core/config.py MONITOR_MAX_TARGETS_PER_TENANT (default 100, range 1..1000) + .env.example + compose.yaml; ARCHITECTURE sections 7 and 11; tests/core/test_permissions.py, tests/tenancy/test_matrix.py, tests/tenancy/test_id_range.py.
- Decisions: first next_run_at = now; PATCH of interval sets next_run_at = min(current, now + new interval); 404 before 403 ordering; no audit table exists, so structured log lines instead (none built).
Note (from M7-06): per-user DomainAccess is not enforced in MonitorTargetRepository (same as DomainRepository/DomainEspRepository); the endpoint layer must enforce it. The tenant repository is `repo_for(ctx).monitor_targets`.
