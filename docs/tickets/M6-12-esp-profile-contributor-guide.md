# M6-12 Contributor guide for adding an ESP profile
Milestone: M6
Branch: feature/m6-12-esp-profile-contributor-guide
Files in scope: docs/ESP_PROFILES.md, profiles/esp/README.md (short pointer), a template file docs/templates/esp-profile.example.yaml (fake vendor `example-esp`; must pass the loader through a test), tests/esp/test_template_profile.py
Out of scope: app code, real profile data, SPEC.md and ARCHITECTURE.md (the GM updates ARCHITECTURE section 8 separately if the final schema differs)
Depends on: M6-01 (schema), M6-04 (finding codes to describe); reads best after M6-08..10 so it can point at real examples
Parallel-safe: yes with M6-11 (disjoint files); locales untouched
Model: sonnet
Acceptance criteria:
- docs/ESP_PROFILES.md covers: file location and naming, every schema field with its validation rule (taken from the M6-01 loader, not paraphrased from memory), how to verify against official documentation (vendor-owned URLs only, write the date actually read, quote the supporting line in the PR), how and when to use `unverified` / `unverified_fields`, the i18n keys for notes and pitfalls (en + it), how to run the validation and tests locally (`uv run pytest -q tests/esp`), the 12-month staleness warning, and a PR checklist (sources, date, no copied vendor text, no customer data).
- The template YAML loads with the real loader (test) and uses a reserved example domain; it cannot be mistaken for a vendor profile (the loader rejects it from `profiles/esp/` because `example-esp` is not shipped there; the test loads it from docs/templates explicitly).
- Linked from README.md contributor section only if one exists; otherwise from docs/RELEASE.md checklist line about profiles. Coder states which.
New i18n keys: none
Status: done
