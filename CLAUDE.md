# CLAUDE.md — working rules for this repository

Read `SPEC.md`, `ARCHITECTURE.md` and `TODO.md` at the start of every session.

## How to work
- Work on ONE milestone at a time, in the order of `TODO.md`. Do not start the next until
  the current one has passing tests and updated docs.
- Before coding a milestone, restate its acceptance criteria and list the files you will touch.
- Small commits, conventional commit messages. Update `TODO.md` checkboxes as part of the commit.
- If a decision changes the architecture, update `ARCHITECTURE.md` in the same commit.

## Non-negotiables
- Tenant data is accessed ONLY through `/repositories` with a `TenantContext`.
- Every new endpoint needs a tenancy/permission test.
- Checks return `error` (not `ok`) when they could not evaluate; never swallow DNS failures.
- No hardcoded user-facing strings: use i18n keys (en + it).
- All outbound network access goes through the guarded client.
- Parsers and checks get table-driven tests including malformed input; no network in unit tests.
- Knowledge (ESP profiles, selectors, rules, provider requirements) lives in data files with
  `verified_on` and sources. Never invent vendor configuration: if unsure, mark it
  `unverified` and ask the maintainer to confirm against official docs.
- Do not claim an external API (Postmaster, SNDS, BIMI requirements, ESP docs) works a certain way
  without checking current official documentation.

## Commands
(Fill in after M0: install, run, test, lint, migrate.)
