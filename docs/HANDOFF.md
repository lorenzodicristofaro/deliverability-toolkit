# HANDOFF — 2026-11-13 (F-01 complete incl. F-01-03; next M7)

Resume with `/gm`. Backlog **F-01** is complete: F-01-01 6d3bf59, F-01-02 d2d5f40, F-01-03 dcca37e.
F-01-03 (maintainer decision 2026-11-13): MSG_SPF_NOT_PASS / MSG_DKIM_NOT_PASS read only the topmost
Authentication-Results field (`_topmost_results`, app/services/message_findings.py); computed_dmarc, alignment and
the hop view unchanged. QA APPROVE first round, no findings; full suite green (SQLite 25826, PostgreSQL 31773).
Dev CI green on dcca37e (CI, CI infra, Secret scan). Next: **M7 — Monitoring**.

## State
- `dev` at the commit carrying this file (974c785 + this handoff). `qa` at e140ea1 (R1 + F-01-01/02 + R1-25b);
  F-01-03 is not in `qa` yet. `main` unchanged.
- Known cost of F-01-03, told to the maintainer: receivers that write one Authentication-Results field per milter
  (e.g. Postfix + separate OpenDKIM/OpenDMARC) get MSG_DKIM_NOT_PASS low "not stated" when dkim passed in a lower
  field. Pinned in tests (R122_FINDINGS row 2, TOPMOST_ONLY). Revisit only on maintainer request.
- Local test PostgreSQL `dt-test-pg` was running this session (used by QA).
- About 25 old agent worktrees remain under .claude/worktrees/ (R1 and F-01 branches, all merged; one locked).
  Optional cleanup: check `git -C <wt> status` is clean, then `git worktree remove`; leave the locked one.

## Open maintainer actions
1. QA checklist line for .claude/agents/qa-reviewer.md ("Review steps", new step 5 after
   `   - changes stay inside "Files in scope"`): `5. Flag every change to .github/** or .claude/** in the report
   (including the diff of .claude/settings.json) and require the maintainer's approval before it is pushed; this is a
   blocker until approved.`
2. Optional (R1-30 QA nit): CLAUDE.md dev run command lacks `--no-proxy-headers` (dev-only, loopback).

## M7 notes for the next session (from TODO.md)
- Items: guarded outbound HTTP client (SSRF protection), custom check kind http_fetch via that client (SPEC §5
  wording to review when M7 starts: maintainer decision 2026-11-11), DNSBL/URIBL engine with refusal detection and
  `dnsbl.yaml` seed, scheduler + history + DNS snapshots/diff + trend charts, alerts (email, webhook, Slack/Teams).
  Accept: scheduled runs respect rate limits; changes produce alerts exactly once.
- No HTTP guarded client exists yet (only app/dns/egress.py for DNS). It is the base of M7: first ticket, opus
  (anti-SSRF is an opus area), serialize the rest on it.
- DNSBL refusal codes and list policies are vendor facts: `dnsbl.yaml` entries need `verified_on` and sources;
  anything not checked against the list operator's official docs is `unverified` and goes to the maintainer.
- Slack/Teams webhook payload formats: check current official docs before coding (CLAUDE.md non-negotiable).

## Follow-ups (low, TODO.md)
R1: R1-21 helo= with a space; R1-25 CI alembic_version check + comment; R1-26 doc wording; R1-30 fallback warning
log, /32 example. F-01: hop numbering 0- vs 1-based on one page; detail_no_hop wording when Received is truncated;
RFC 8617 4.2.1 "and signing algorithm"; shared HOP_SCENARIOS fixtures to tests/support/; `_result.html` kind label.

## Next 3 steps
1. Optional: promote `dev` → `qa` (CI green on dcca37e; the later commits are docs-only).
2. M7: restate its acceptance criteria, `pm` splits it into tickets (guarded client first, opus), GM reviews them.
3. Low follow-ups batch when convenient.
