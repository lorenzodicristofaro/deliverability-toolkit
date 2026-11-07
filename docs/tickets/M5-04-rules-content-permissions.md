# M5-04 Permissions: content.analyze and rules.manage (global vs tenant)
Milestone: M5
Branch: feature/m5-04-permissions
Files in scope: app/core/permissions.py, tests/core/test_permissions.py (plus any matrix test enumerating `Action`; coder lists it)
Out of scope: endpoints, UI, CLI, storage.
Depends on: none (but see ordering below)
Parallel-safe: no (permissions.py hotspot; run alone, and before M5-13, M5-18, M5-20, M5-23)
Model: opus
Decisions (justify in code comments, same style as M4-06):
- `Action.CONTENT_ANALYZE = "content.analyze"`, resource `TenantResource`. Offline, requires an active membership; granted to OWNER, ADMIN, ANALYST; NOT CLIENT_VIEWER; toggle-deniable. Not reusing `message.analyze` (separate toggle key).
- `Action.RULES_MANAGE = "rules.manage"` with a scope-bearing resource (e.g. `RuleScopeResource(scope, tenant_id)`): scope `global` -> only an instance admin (principal flag), regardless of tenant role; scope `tenant` -> OWNER and ADMIN of that same tenant. ANALYST/CLIENT_VIEWER denied. Reading rules (`Action.RULES_READ`) for the tenant: OWNER, ADMIN, ANALYST read global + own tenant rules; client viewer denied.
- Covers content rules, DKIM selectors and custom checks (one managing permission, scope decides who).
Acceptance criteria:
- Deny-by-default tests: anonymous, inactive user, wrong tenant, no active tenant, wrong resource type, toggle false/None/"yes"/0, unknown role, malformed principal and malformed scope string.
- Tenant admin of tenant A cannot manage tenant B rules nor global rules; instance admin without membership can manage global but gets nothing on a tenant it is not a member of unless the existing model already grants that (coder states the rule and tests it).
- Existing matrix/enumeration tests updated; module docstring role matrix updated.
New i18n keys: none
Status: todo
