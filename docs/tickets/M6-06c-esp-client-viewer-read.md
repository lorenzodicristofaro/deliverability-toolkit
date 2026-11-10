# M6-06c Client viewers read ESP data on assigned domains
Milestone: M6
Branch: feature/m6-06c-esp-client-viewer-read
Files in scope: app/services/domain_esps.py, app/api/v1/domain_esps.py, the `esp` check wiring seam touched by M6-06 (app/services/checks.py and/or app/api/v1/checks.py, plus app/web/checks_stream.py only if M6-06 touched it), tests/tenancy/test_matrix.py, tests/services/test_domain_esps_service.py, tests/api/test_domain_esps_api.py (or the existing M6-03 test files), the M6-06 run tests, docs/tickets/M6-03-esp-assignment-service-api.md and docs/tickets/M6-06-esp-check-run-wiring.md (wording only), comments in the code that state the old rule, locales only if a new key is truly needed
Out of scope: UI tab (M6-07), detection logic (M6-13), check logic (M6-04/05), profile content, new permissions or actions beyond what `can()` needs, any write path for client viewers, SPEC.md and ARCHITECTURE.md (GM decides, see below)
Depends on: M6-06 (merges as is: it withholds `esp` from viewers with 403; this ticket reverses that)
Parallel-safe: no (shared domain_esps service/API, checks seam, tenancy matrix)
Model: opus (changes who can read tenant data)
Decision: maintainer, 2026-11-10. It overrides the earlier GM default that client viewers get no ESP data. A client viewer on a domain assigned to them sees, read-only: (a) the ESPs assigned to the domain; (b) ESPs detected in DNS but not assigned (M6-13), flagged as possible stale configuration; (c) the full `esp` check result. Rationale: it helps spot old ESP configurations that were never removed.
Acceptance criteria:
- GET /api/v1/domains/{id}/esps is readable by a client viewer on a domain assigned to them. The `esp` check is readable by them in `all` and when requested by id, on assigned domains.
- Unassigned domains and domains of another tenant stay 404 (never 403, never a data leak in the body). Anonymous stays 401.
- PUT and DELETE on the ESP routes stay 403 for client viewers, and no repository call happens (spy test, `can()` before repository).
- Authorization reuses the existing read rule used for other viewer-readable domain data (coder inspects how M5-23b exposed DKIM provider to viewers and follows it); no new route.
- Profile catalogue: readable by client viewers, read-only (suggested; the catalogue is public profile data with no tenant content). If the coder finds a reason against it, stop and ask the GM.
- Viewers see the full esp result: notes, hostnames (return-path, tracking), evidence and findings, with no field redaction. Test that a viewer response equals the analyst response for the same domain.
- Remove the 403-for-viewers withholding added in M6-06; per-user feature toggles still apply as elsewhere.
- Tests: tenancy matrix rows for each ESP route and the `esp` check by role (client viewer assigned: read 200, write 403; client viewer unassigned: 404; owner/admin/analyst unchanged); role tests updated; a two-tenant test (viewer of tenant A on tenant B domain id gets 404 on list, check by id and `all` without ESP data).
- Update the old-rule statements in M6-03 (acceptance line on client viewers getting 403 including the catalogue) and M6-06 (the client viewer criterion) tickets, and any code comment or docstring stating the old rule, so no stale text remains (grep for "client viewer" and "no ESP data").
- SPEC section 3 flag for the GM: it says client viewers "cannot see other ESP data". The decision reads this as "cannot see ESP data of other domains". The coder does not edit SPEC.md; the GM decides whether to clarify the wording.
- QA (M6-06): `resolve_esp_run` (app/services/domain_esps.py:409-415) says it never raises, but after a SQLAlchemyError a PostgreSQL session is left in an aborted transaction; use `db.begin_nested()` or state in the docstring that the caller must roll back. Optional: a PostgreSQL test with a real statement failure instead of a monkeypatched OperationalError (tests/api/test_checks_api.py:551).
New i18n keys: none expected
Status: done (merged into local dev after QA APPROVE; GM gate on the combined M6-06b+06c merge: full PostgreSQL suite green, lint clean)
