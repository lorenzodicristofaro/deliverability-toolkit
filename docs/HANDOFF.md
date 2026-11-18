# HANDOFF — 2026-11-18 (M7 in progress, paused on maintainer request)

Resume with `/gm`. Milestone **M7 — Monitoring**, tickets in docs/tickets/M7-*.md, list in TODO.md.

## Done this session (QA APPROVE, merged into dev, pushed, dev CI green)
- M7-00b test-suite speed (CI ~3x faster: shards, slimmer permission matrices, `slow` marker on main + weekly).
- M7-13 monitoring page + SVG trends; M7-14 alert state/dedup (3 QA rounds, maintainer-authorized);
  M7-15 alert channels + encrypted secrets + dispatcher (migration 0017).
- M7-14c alert wiring: run executor sink, AlertDispatcher + AlertReleaser (ROLE worker/all), ALERT_* settings
  (3 QA rounds, maintainer chose option A).
- M7-14d latest-run check + alert insert in one transaction (target lock, then head lock).
- M7-16 email alert channel (stdlib smtplib, operator relay trusted per ARCHITECTURE section 9, strict recipients).
- Dev head dd8a80e, CI run 44372155455 green. Alembic head on dev: 0017.

## In progress
- **M7-21b** domain verification by email: implemented on branch `feature/m7-21b-domain-verify-email`,
  head **36a39f3** (base dd8a80e), clean, NOT yet reviewed. Coder: Opus. Relevant tests green on SQLite + PG,
  full suite not run. Adds migration **0018** (`domain_email_challenges` table), public `/verify-domain`
  (GET form, POST confirms, CSRF), `POST /api/v1/domains/{id}/verification/email`, rate limits under a tenant-row
  lock, token only in query/POST body (query stripped from logs).
  Out-of-scope files touched (review): app/web/domain_verify_email.py (new), model + registration,
  `CurrentTenantRepository.lock()`, tenancy matrix/id-range tests, docs/TESTING.md, ARCHITECTURE 5/7/9.

## Next 3 steps
1. QA round 1 on M7-21b (Opus, full suite both backends). Focus: public route leaks nothing, token never logged,
   rate-limit atomicity (SQLite test passes even without the lock, see coder note), rename invalidation,
   out-of-scope files. Then merge, push dev, poll CI.
2. Small follow-up: normalise mixed-case alert-channel recipients (TODO under M7-16), then M7-17 webhook
   (then M7-18 Slack, M7-19 Teams: payloads to verify in official docs, unverified otherwise).
3. M7-05b Spamhaus DQS, then M7-20 acceptance tests + docs/MONITORING.md; at milestone end full suite on dev,
   merge dev into qa, write docs/reports/M7 report.

## Maintainer decisions
- 2026-11-17: domain ownership verification required; DNS TXT primary (M7-21a), email alternative (M7-21b).
- 2026-11-18: M7-14c option A (doc the replica window, close it in M7-14d — done).
- GM accepted trade-off in M7-14d: a superseded emit may miss an alert seen only by the older overlapping run
  (missed rather than wrong); follow-up in TODO to document it and consider diffing against the stream head.

## Open maintainer actions
- None blocking. Pending from earlier: Barracuda BRBL text; SpamCop IPv6/usage terms; DMARC tag case-sensitivity;
  M7-21b role-address list is a project choice, CA/vendor alignment unverified.

## Notes
- Agent worktrees start stale: give coders the dev hash to reset to. If a branch is held by another worktree,
  use a new local branch name and merge that commit.
- Local full suite: docs/TESTING.md. PG: prefix
  TEST_DATABASE_URL=postgresql://ci:ci-throwaway-password@localhost:5432/ci_test, one run at a time.
- Commit messages must not contain the word "push" (permission rule). Changes under .github need the maintainer.
- Old agent worktrees under .claude/worktrees/ can be cleaned up once M7-21b is merged.
