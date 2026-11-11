# M6-01 ESP profile schema, loader and CI validation
Milestone: M6
Branch: feature/m6-01-esp-profile-schema-loader
Files in scope: app/esp/__init__.py, app/esp/profile.py (frozen dataclasses + strict loader), profiles/esp/.gitkeep (directory created; real profiles come in M6-08..10), tests/esp/__init__.py, tests/esp/test_profile_loader.py, tests/esp/test_shipped_profiles.py, tests/fixtures/esp/ (fake `example-esp` fixtures, valid and malformed), Dockerfile (one `COPY profiles ./profiles` line next to `COPY seeds`), .github/workflows/ci-infra.yml (add `profiles/**` to the infra paths with its reason in the header comment)
Out of scope: DB, API, UI, checks, real vendor profiles, ARCHITECTURE.md (the GM updates section 8 if the shape below differs from its sketch; the coder lists the differences in the summary)
Depends on: none
Parallel-safe: yes with M6-02 (disjoint directories)
Model: opus (parser of contributor-supplied data files)
Acceptance criteria:
- Loader follows the pattern of `app/dns/knowledge.py` (hand-written strict validation, `KnowledgeError`-style error type, immutable result, cached per path, no network, unknown keys rejected). No new dependency (no `jsonschema`). The validator IS the schema; the contributor guide (M6-12) documents it.
- Profile shape starts from the ARCHITECTURE.md section 8 sketch: `id` (slug `[a-z0-9][a-z0-9-]{0,39}` equal to the file name), `name`, `homepage` (https URL), `spf.includes` (hostnames), `dkim.selectors[]` (`name` DNS label, `type` cname|txt, optional `target_pattern`), `return_path` and `tracking_domain` (`type` cname|txt|mx, `optional`, `notes_key`), `pitfalls[]`, `verified_on` (date, mandatory), `sources` (non-empty list of https URLs, mandatory), `status` verified|unverified (as in `app/dns/knowledge.py`), optional `unverified_fields` list.
- `target_pattern` is a restricted glob: only `*` matching exactly one DNS label, validated; no regex, never evaluated as code. Tests: pattern matching table (match, no match, empty label, extra labels, case, trailing dot).
- `pitfalls[]` are static advisory entries (`code` `ESP_<ID>_<NAME>` upper snake, `notes_key`, `severity`); the sketch's free-text `when:` is NOT supported and is rejected (no expression evaluation of data; GM to confirm, see open questions in the PM report).
- A profile with `status: verified` must have `verified_on` and at least one source; `status: unverified` is allowed but every field named in `unverified_fields` is excluded from checks (loader exposes it; M6-04 uses it).
- Hostnames and patterns are validated (length, labels, NUL, no scheme, no wildcard outside `target_pattern`); `verified_on` in the future is rejected; duplicate ids across files rejected; file name must equal `id`.
- Directory loader `load_esp_profiles(dir)`: all-or-nothing (one malformed file raises, no partial result), deterministic order, size cap per file, `yaml.safe_load` only. Malformed YAML, wrong types, empty file, huge file, duplicate keys tests (table-driven).
- `tests/esp/test_shipped_profiles.py` loads the real `profiles/esp/` (passes while the directory is empty) and emits a warning (not a failure) for any profile older than 12 months, per ARCHITECTURE section 8. This is the "CI validation": it runs in the normal pytest jobs.
- Docker image contains `profiles/` (Dockerfile) and a CI path entry exists; coder confirms the header comment lists the reason.
New i18n keys: none
Status: done
Merge note: merged to local dev at 1db639d (QA APPROVE; fix 9ecf174); SQLite suite 23320 passed, lint clean; PostgreSQL skipped (no DB change).
