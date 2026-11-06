# M3-14 `check.run` permission action
Milestone: M3
Branch: feature/m3-14-check-run-permission
Files in scope: app/core/permissions.py (new Action + role mapping only), tests/core/test_permissions.py (extend; check actual file name), tests/tenancy/ (matrix hook only if needed; read tests/tenancy/conftest.py first)
Out of scope: routes, services, UI
Depends on: none
Parallel-safe: no (permissions.py hotspot; schedule alone, before M3-15)
Model: opus (permissions)
Decision proposed to GM: `Action.CHECK_RUN = "check.run"` with `DomainResource` (checks run against a tenant domain; no existing action fits because DOMAIN_READ is not toggle-separable and DNS_TOOLS is tenant-level and denied to client viewers). Granted to owner, admin, analyst (all domains) and client viewer (assigned domains only, enforced by `_domain_allowed`, because M3 has no persistence so viewing the Authentication tab IS running the check). A per-user toggle `{"check.run": false}` denies it. Free (tenant-less, ad-hoc name) checks reuse `dns.tools` (owner/admin/analyst), unchanged.
Acceptance criteria:
- `Action.CHECK_RUN`, `_RESOURCE_KIND[CHECK_RUN] = DomainResource`, `ROLE_ACTIONS` updated as above.
- Table-driven test roles x toggles x (assigned / unassigned domain, other tenant's domain, no membership, inactive membership, instance admin handling mirrored from `can()`); client viewer on an unassigned domain denied; toggle false denies; toggle true never grants beyond role.
- Existing tests that enumerate every Action are updated deliberately.
New i18n keys: none
Status: done
