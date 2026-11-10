# M5-17b Ids above 32 bits give a 500 on PostgreSQL
Milestone: M5
Branch: feature/m5-17b-id-overflow
Files in scope: the shared id coercion (`coerce_id` and whatever else parses ids from paths, forms and JSON bodies; coder names the files), tests covering the routes below, one shared test file if it is cleaner.
Out of scope: changing column types; the CLI helper app/cli/tenant_scope.py, which already caps at 2147483647.
Depends on: none
Parallel-safe: no
Model: opus (tenant isolation paths)
Context (found by M5-17a QA on PostgreSQL): `coerce_id` allows 63 bits, but PostgreSQL binds to INTEGER, so ids 2147483648 and 2**63-1 raise DataError "integer out of range" and give a 500. 2147483647 gives 404 and SQLite gives 404. Affected:
- web GET /domains/{id}, /domains/{id}/rename, /domains/{id}/delete, /domains/{id}/authentication, /domains/{id}/authentication/dkim/stream
- web POST /domains/{id}/rename, /domains/{id}/delete
- POST /tenants/switch (form tenant_id)
- API GET, PATCH, DELETE /api/v1/domains/{id}
- PUT /api/v1/domains/{id}/access, including `user_ids` holding such an id on a real domain
- POST /api/v1/domains/{id}/checks and /checks/all
Not affected: `offset` and `limit`.
Acceptance criteria:
- An out-of-range id behaves exactly as an unknown id on that route, on both databases: same status (404 or the route's existing validation error) and same localized body, with no 500 and no information about the limit.
- The boundary is derived from the actual column type rather than a repeated literal, or is one named constant, and the coder confirms every primary and foreign key id it guards is INTEGER.
- Table-driven tests cover 2147483647, 2147483648 and 2**63-1 on each affected route, for SQLite and PostgreSQL, including the `user_ids` body and the switch form.
- A static or route-table test proves every route with a numeric id goes through the shared coercion, so new routes (including those from M5-18 onward) cannot reintroduce it, or the coder explains why that is not feasible.
- No tenant information leak: for a foreign tenant the result is the same as for an unknown id.
New i18n keys: none expected
Status: done
