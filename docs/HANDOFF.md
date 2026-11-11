# HANDOFF — 2026-11-10 (M6 in progress, session stopped by the maintainer)

Resume with `/gm`. The maintainer asked to stop after the M6-07 QA round; no coder is running.

## State
- M1–M5 accepted; `qa` → `main` pending the maintainer for M1–M5.
- M6 done on local dev: M6-00, 01, 02, 03, 04, 05, 06, 06b, 06c, 07, 12, 13, 13b. Last gate: merge ba0ee68, full PostgreSQL suite 30033 passed, lint clean.
- M6 open, in this order:
  1. M6-08 profiles: SendGrid, Amazon SES, Mailgun (sonnet coder, QA opus).
  2. M6-09 profiles: MailUp/TeamSystem + up to 2 Italian ESPs.
  3. M6-10 profiles: Google Workspace, Microsoft 365, Brevo.
  4. M6-11 acceptance tests over every shipped profile + docs/CHECKS.md.
  M6-08..10 edit the locale files: run them one at a time. Vendor facts only from official docs; anything not confirmable is `unverified` and goes to the maintainer.
- Maintainer decision 2026-11-10: client viewers read ESP data on assigned domains (assigned + detected ESPs + full `esp` result), no writes; SPEC §3 updated.

## GM decisions in M6
- Profiles live in `profiles/esp/`; the strict loader in app/esp/profile.py is the schema; `pitfalls[].when` rejected; notes_key segment = profile id with `-` → `_`.
- ESP overrides (SPEC §5, `esp_profiles` table) deferred beyond M6.
- The API returns finding keys + raw params; the CLI and web localize through app/checks/finding_text.py.
- `esp` runs in every domain `all` (detection needs it); DKIM detection: at most 32 probes, 8 concurrent, stop at the first DNS failure; a cap hit is partial with ESP_DETECTION_TRUNCATED, never ok.
- A broken profiles directory: ESP routes 503 (localized), `esp` check `error`.

## How the work runs now (maintainer decisions 2026-11-09)
- Sonnet → Opus: once Sonnet code fails (QA, tests or CI), all further coder work on that ticket goes to a NEW coder on Opus (docs/WORKFLOW.md section 3).
- QA on Sonnet only for low-risk Sonnet tickets; Opus for auth, permissions, tenancy, parsers, untrusted input.
- Coder runs relevant tests only (full suite if shared fixtures or app-wide code change); QA runs the full suite once, on the final round; GM runs it on the merge result.
- Local PostgreSQL: container `dt-test-pg` (Docker Desktop must be running). Prefix each pytest with `TEST_DATABASE_URL=postgresql://ci:ci-throwaway-password@localhost:5432/ci_test`. One suite at a time. The full suite takes about 10 minutes, so run the merge gate in the background.
- CI runs `lint`, `test-sqlite`, `test-postgres` in parallel. Docs-only pushes skip the tests; `secret-scan` still runs.
- Agent worktrees start stale: give each coder the exact `dev` hash.
- After a merge, check CI, then close the ticket and tick TODO.md.

## Open maintainer decisions
- SPEC §5 still lists HTTP custom checks; `http_fetch` is deferred to M7 (M5-22). The wording needs the maintainer.
- Gmail clipping and URL shorteners unverified (t.co, tinyurl.com, ow.ly, buff.ly, lnkd.in, is.gd, j.mp).
- Carried over: M4 provider samples; Mailchimp/Postmark/HubSpot DKIM sources; the PSL licence; SecLists terms; HTMX under CSP.

## Next 3 steps
1. M6-08 (coder sonnet, QA opus) from the current `dev` hash; then M6-09, M6-10 one at a time; record every unverified vendor fact for the maintainer.
2. M6-11 acceptance tests, then the full suite on `dev` and docs/reports/M6.md; M6 is accepted when every shipped profile has `verified_on` + sources and sample domains give the expected findings.
3. Maintainer items: Italian wording of profile notes; flaky wall-clock tests (test_received, test_message, test_dmarc) to fix together; carried items below.
