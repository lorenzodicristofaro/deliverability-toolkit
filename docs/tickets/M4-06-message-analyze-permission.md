# M4-06 Permission action for the message analyzer
Milestone: M4
Branch: feature/m4-06-permission
Files in scope: app/core/permissions.py, tests/core/test_permissions.py (and any existing permission matrix test file that enumerates `Action`; coder lists it in the summary), docs/CHECKS.md NOT touched
Out of scope: endpoints (M4-11), UI, CLI.
Depends on: none
Parallel-safe: no (permissions.py is a shared hotspot; serialize with any other permission change)
Model: opus
Decision (justify in the code comment): add `Action.MESSAGE_ANALYZE = "message.analyze"`, resource `TenantResource`, instead of reusing an existing action.
- `dns.tools` does not fit: it means raw DNS queries, and its feature toggle `{"dns.tools": false}` would also silently switch off an offline parser (toggles are keyed by action value). Client viewers are excluded from dns.tools; same wish here.
- `check.run` does not fit: it is domain-level (needs a DomainResource and a registered domain) while a pasted message has no domain; using it would force a fake domain id.
- The analyzer is offline and touches no tenant data, but it processes user-supplied content and costs CPU, so it requires an active membership (no anonymous use), tenant-level, per-user deniable with a toggle.
Acceptance criteria:
- Granted to OWNER, ADMIN, ANALYST. NOT granted to CLIENT_VIEWER (no toggle or DomainAccess can grant it). Instance admin flag adds nothing.
- Deny-by-default tests: anonymous, inactive user, wrong tenant, no active tenant, DomainResource passed instead of TenantResource, toggle false/None/"yes"/0 denies, unknown role, malformed principal.
- Existing matrix/enumeration tests updated; role matrix comment in module docstring updated.
New i18n keys: none
Status: done
