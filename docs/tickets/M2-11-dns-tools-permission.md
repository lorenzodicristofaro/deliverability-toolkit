# M2-11 DNS tools permission action and role matrix
Milestone: M2
Branch: feature/m2-11-dns-tools-permission
Files in scope: app/core/permissions.py (new Action + role mapping only), tests/core/test_permissions.py (extend; check actual file name), tests/tenancy/ (only if the route-generated matrix needs a classification hook for tenant-less tool routes; read tests/tenancy/conftest.py first and keep the change minimal)
Out of scope: routes, UI, services
Depends on: none (M1 code)
Parallel-safe: no (permissions.py is a shared hotspot; schedule alone or before M2-12)
Model: opus (permissions)
Decision proposed from SPEC section 3 ("a client viewer ... cannot see raw DNS tools") and section 4.7 ("free" DNS tools): a single action `dns.tools` (`Action.DNS_TOOLS`) granting lookup, reverse, trace and propagation. Granted to owner, admin, analyst. NOT granted to client viewer (deny by role, not by toggle: toggles can only deny, never grant). Instance admin follows the existing instance-admin handling in `can()`; check and mirror it. Anonymous users have no access: the tool needs a logged-in user with an active tenant membership (it makes outbound DNS queries on the instance's behalf; open access would be an abuse vector). Tool results are not tenant data and nothing is stored in M2. OPEN QUESTION for the maintainer: confirm that analyst is allowed and anonymous is not.
Acceptance criteria:
- `Action.DNS_TOOLS = "dns.tools"`; `ROLE_ACTIONS` updated as above; per-user toggle `{"dns.tools": false}` denies it for an otherwise-allowed role (existing toggle mechanism, test it); a toggle `true` never grants it to a client viewer (test).
- Table-driven test across roles x toggles x instance-admin/no membership/inactive membership.
- Existing role-matrix tests that enumerate every Action still pass or are updated deliberately.
New i18n keys: none
Status: todo

GM decision 2026-11-05: `dns.tools` granted to owner/admin/analyst; client viewer denied by role (not toggle-grantable); anonymous denied.
