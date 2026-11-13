# R1-31 Domain rename rewrites the ESP hosts to the new name
Milestone: R1
Branch: feature/r1-31-domain-rename-esp-hosts
Findings: AUTH-05 (low)
Files in scope: app/services/domains.py (`rename`), app/repositories/domain_esps.py (a method that rewrites the host suffix for one domain), app/repositories/domain.py (only if the rename must run in the same transaction), app/api/v1/domains.py (PATCH response notice), app/web/domains.py (rename route, user notice), app/services/domain_esps.py (replace the "the renaming ticket decides" comment), locales/en.json, locales/it.json, tests/api/, tests/web/, tests/repositories/, tests/checks/ or tests/services/ (esp check after rename), docs describing rename or ESP hosts
Out of scope: changing the host validation rule, refusing renames, ESP profile data, permission or tenancy logic
Depends on: none
Parallel-safe: no with any ticket editing locales/*.json or app/web/domains.py (locale files shared); yes with R1-30 and R1-32 (disjoint files)
Model: sonnet (tenant-scoped data fix inside existing repositories, no isolation or permission change)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev bcc231b. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. (Review reproduction: PUT esps/sendgrid with `return_path_host` under the old name, PATCH the name, GET esps still shows the old host.)
- Maintainer decision 2026-11-13: on rename, in the SAME transaction, rewrite the old-domain suffix of `return_path_host` and `tracking_host` to the new name. By the repository rule these hosts are always the domain or a subdomain of it, so: host equal to the old name becomes the new name; host `<label>.<old>` becomes `<label>.<new>`. Only through `/repositories` with the `TenantContext`; other domains and tenants untouched.
- If the rename fails or rolls back, the hosts are unchanged. A host that does not satisfy the old rule (legacy data) is handled explicitly: state the rule in the summary (suggest: left untouched and reported, never silently kept as if valid).
- User notice: the API PATCH response carries the information (response field or message: state which, keep existing fields stable) and the UI shows a notice when hosts were rewritten; en + it; no notice when no host was set.
- Tests: rename with assigned hosts (API and UI) leaves no host outside the new name, including apex and subdomain hosts, both host columns, and several ESPs on one domain; the `esp` check after a rename never queries a name under the old domain (fake resolver records the queries); rollback leaves hosts unchanged; notice present only when rewritten (en and it). Existing tenancy/permission tests unchanged and green; a rename of another tenant's domain still gives the existing 404.
- ruff, mypy, en/it completeness, relevant tests green. No network.
New i18n keys: rename notice for rewritten ESP hosts (en + it); the coder lists exact names.
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb; maintainer decision 2026-11-13: rewrite)
- Location: `app/services/domains.py:185-197` (`rename`), `app/repositories/domain.py` `rename`, `app/repositories/domain_esps.py:28-29` and `app/services/domain_esps.py:34-35` (both say "the renaming ticket decides"), `app/api/v1/domains.py` PATCH, `app/web/domains.py:268-290`.
- Problem: `domain_esps.return_path_host` and `tracking_host` must be the domain or a subdomain of it, and the repository enforces that on every write. Renaming the domain changes only `domains.name`, so the stored hosts silently stop satisfying the rule. The `esp` check then evaluates the return-path and tracking records of the old name and reports them for the new domain. Rename has existed since M1-18.
- Evidence (run on SQLite): `PUT /api/v1/domains/1/esps/sendgrid {"return_path_host": "em1.assigned.example"}` -> 201; `PATCH /api/v1/domains/1 {"name": "renamed.example"}` -> 200; `GET /api/v1/domains/1/esps` -> `"return_path_host":"em1.assigned.example"` on the domain now called `renamed.example`.
- Suggested fix (review offered clear, rewrite or refuse; maintainer chose rewrite): do it in the same transaction as the rename. Files: `app/services/domains.py`, `app/repositories/domain_esps.py`, both rename routes for the user message, `locales/*.json` for the notice.
- Tests to add: rename with assigned hosts (API and UI) leaves no host outside the new name; the `esp` check after a rename never queries a name under the old domain.
- Confidence: high
- Already tracked: no (only the two code comments).
