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
Status: todo
