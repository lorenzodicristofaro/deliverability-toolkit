# M1-11 Permission layer can(user, action, resource)
Milestone: M1
Branch: feature/m1-11-permissions-can
Files in scope: app/core/permissions.py, tests/core/test_permissions.py
Out of scope: HTTP wiring/dependencies (M1-15), repositories, UI, API keys, share links
Depends on: M1-10
Parallel-safe: yes with M1-12 (disjoint files; both read-only against app/models)
Model: opus
Acceptance criteria:
- Pure function `can(principal, action, resource) -> bool` plus a `require()` helper raising a typed error; no DB access inside (principal carries memberships and domain access, loaded by caller).
- Actions enum for M1: tenant.read, tenant.manage, user.manage, domain.list, domain.read, domain.create, domain.update, domain.delete, instance.manage. Later milestones add actions; unknown action is denied (test).
- Matrix per SPEC section 3: instance admin (instance.manage, tenant management, no implicit data access unless stated by GM: see note), owner (all in tenant), admin (domains, custom checks, invite; not billing-like owner settings), analyst (read all domains, run checks, no user/integration management), client viewer (read only assigned domains, per-user feature toggles can deny).
- Cross-tenant: any resource with tenant_id different from the principal's active tenant is denied for every role (generated table-driven matrix: roles x actions x {own tenant, other tenant, assigned, unassigned}).
- Deny by default; inactive user denied.
- GM decision Q4b (2026-11-04): instance-admin access to tenant data is escalated to the maintainer. Until answered, implement deny for tenant data (manage tenants only); keep the rule in one place so it is easy to change.
New i18n keys: none
Status: todo
