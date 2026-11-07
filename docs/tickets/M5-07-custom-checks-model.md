# M5-07 custom_checks model, migration and repository
Milestone: M5
Branch: feature/m5-07-custom-checks-model
Files in scope: app/models/custom_check.py, app/models/__init__.py, migrations/versions/<date>_0007_custom_checks.py, app/repositories/custom_checks.py, app/repositories/__init__.py, tests/repositories/test_custom_checks.py
Out of scope: definition schema/evaluator (M5-22), API, UI.
Depends on: M5-06
Parallel-safe: no (models/migrations/repositories registry; serialize after M5-06)
Model: opus (tenant-scoped data)
Acceptance criteria:
- Columns: id, scope (global|tenant, CHECK), tenant_id (NULL iff global), name, description, kind (`dns_exists`|`dns_matches`|`dns_value_range`; DB CHECK; `http_fetch` is deliberately NOT allowed, see M5-22), definition (JSON, size-capped), severity, remediation_key or remediation_text (per-language JSON {en,it} so admins write both), enabled, timestamps, created_by.
- Same isolation rules as M5-05; repository stores the definition opaquely (validation lives in M5-22, service layer).
- Tests: tenant isolation, global/tenant CHECKs, kind `http_fetch` rejected by the DB CHECK, oversize definition rejected, NUL rejected before DB; migration up/down.
New i18n keys: none
Status: todo
