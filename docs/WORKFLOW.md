# WORKFLOW — multi-agent development with Claude Code

## 1. Roles

| Role | Who | Responsibilities | May NOT |
|---|---|---|---|
| **General Manager (GM)** | Main Claude Code session started with `/gm` | Oversees all work: picks priorities from TODO.md, reviews the ticket plan, delegates, merges approved tickets into `dev`, promotes `dev` → `qa`, guards the token budget, writes milestone reports, escalates to the human | Write feature code, merge into `main`, handle production credentials |
| **Project Manager (PM)** | Subagent `pm` (`.claude/agents/pm.md`) | Splits milestones into tickets, marks parallel-safe ones, keeps ticket status and TODO.md checkboxes current, short status reports | Write feature code, merge, edit SPEC/ARCHITECTURE |
| **Coder** | Subagent `coder` (`.claude/agents/coder.md`) | Implements ONE ticket on its own branch/worktree with tests, short summary | Touch files outside the ticket scope, edit SPEC/ARCHITECTURE, merge |
| **QA reviewer** | Subagent `qa-reviewer` (`.claude/agents/qa-reviewer.md`) | Read-only review of a branch against ticket and non-negotiables, runs tests, verdict APPROVE / CHANGES REQUESTED | Modify code |
| **Human (safety gate)** | You | Answers GM escalations; holds production credentials; approves `qa` → `main` and releases | — |

Why the GM is the main session: subagents are delegated to by the main session and
(per the Claude Code docs) are not meant to spawn further subagents. The hierarchy is
therefore flat underneath the GM: GM → {pm, coder, qa-reviewer}. Verify with `/agents`
in your Claude Code version if this changes.

### What the GM escalates to the human (and nothing else)
1. Anything involving `main` / production: merge, release tag, production credentials and keys.
2. Changes to SPEC/ARCHITECTURE that alter scope, license or the tenancy model.
3. Vendor or external-API facts that cannot be verified (recorded as `unverified`).
4. A ticket failing a second QA round, or repeated unexplained test failures.
5. Anything needing secrets, paid services or spending beyond the plan.

If you later want a fully autonomous GM, you can move item 1 to the GM as well, but
keep production credentials out of the machine where agents run (section 5).

## 2. Token budget on Claude Pro

Usage on Pro is shared between claude.ai chat and Claude Code, and is limited by a
rolling 5-hour window plus a weekly cap. Subagents do not save tokens: each has its own
context window and consumes quota while working. Adding the GM and PM layers adds
overhead on top of coders and QA, so keep the GM's own messages short.

Recommended operating point for Pro:
- **GM + at most 1 coder at a time**; 2 coders in parallel only on disjoint directories and only with quota to spare.
- Do not run chat-heavy work on claude.ai during coding sessions.
- Check `/status` before launching a batch of tickets.
- On a usage warning the GM finishes or parks the current ticket, writes `docs/HANDOFF.md`
  and stops; the next `/gm` session resumes from it.
- If you hit the limit regularly: wait for reset, enable extra usage (pay-as-you-go, set a
  spending cap), or move to a Max plan.

Token hygiene:
1. Tickets are small: one concern, a list of files, explicit acceptance criteria.
2. `/clear` between unrelated tickets; `/compact` when a session grows long.
3. PM runs on Sonnet; coder and QA follow the model rules in section 3.
4. Agents read only the files named in the ticket plus what they must.
5. Keep CLAUDE.md short; detail lives in docs read on demand.
6. Tests and linters produce concise output (`-q`, `--tb=short`).

## 3. Ticket format

Tickets live in `docs/tickets/<milestone>-<nn>-<slug>.md` (or GitHub issues).

```markdown
# M3-02 SPF lookup counter
Milestone: M3
Branch: feature/m3-02-spf-lookup-counter
Files in scope: app/parsers/spf.py, app/checks/spf.py, tests/checks/test_spf.py
Out of scope: UI, i18n files other than the keys listed below
Depends on: M3-01
Parallel-safe: yes | no
Model: sonnet | opus
Acceptance criteria:
- ...
New i18n keys: SPF_TOO_MANY_LOOKUPS.title/detail/remediation (en + it)
Status: todo | in-progress | in-review | changes-requested | done
```

Model rule: `opus` for authentication, permissions and tenant isolation, secret encryption,
the anti-SSRF network client, ReDoS protection, SPF logic, and parsers for raw messages and DMARC reports;
`sonnet` for everything else.

Escalation rule (maintainer decision 2026-11-09): once code written by Sonnet fails (QA CHANGES REQUESTED,
red local tests or red CI), every further code or test change on that ticket goes to `coder` on `opus`,
whatever the ticket's `Model:` line says. Start a new `coder` with the Opus override and give it the
branch and the findings, because resuming the Sonnet agent would keep Sonnet. The 2-round limit is unchanged.

QA model (maintainer decision 2026-11-09): `qa-reviewer` defaults to Opus. The GM runs it on Sonnet (model override)
only for a `sonnet` ticket that stays outside the `opus` areas above and neither parses nor renders untrusted
input. A ticket that hit the escalation rule gets Opus QA for the rest of its rounds.

Test runs per ticket (maintainer decision 2026-11-09): the coder runs ruff, mypy and only the tests relevant to the
change, including the PostgreSQL params when local PostgreSQL is up, and the full suite only if the ticket changes
shared test fixtures, migrations or code used across the app. QA runs the full suite once, on the final round's
commit. The GM runs it on the merge result. CI on `dev` remains the gate after every merge.

## 4. Loop

1. GM reads CLAUDE.md, WORKFLOW.md, TODO.md and `docs/HANDOFF.md` (if present).
2. GM asks `pm` to split the current milestone into tickets; GM reviews and sends back anything vague.
3. For each ticket: GM delegates to `coder` (own worktree/branch) → coder implements, runs ruff + mypy + the relevant tests (section 3), commits, replies in max 15 lines.
4. GM delegates to `qa-reviewer` (ticket + branch). If CHANGES REQUESTED, back to coder, on Opus if the failed code came from Sonnet (section 3; max 2 rounds, then escalate to the human).
5. On APPROVE and green tests the GM merges into `dev` and asks `pm` to update ticket status and TODO.md.
6. At milestone end the GM runs the full suite on `dev`; if green, merges `dev` → `qa` and writes `docs/reports/<milestone>.md` (max 30 lines).
7. Promotion `qa` → `main` is requested from the human.

## 5. Environments and repositories

### Decision: one PRIVATE repository, three long-lived branches (Option A)
- All work happens in one private repository. Branches: `feature/*` → `dev` → `qa` → `main`. `main` = release candidates (tags).
- When the project is ready for release, a NEW public repository is created that contains only
  clean release snapshots, never this repository's history. See `docs/RELEASE.md`.
- The three-repo layout (dev / qa / prod) was considered and rejected for now: more sync work,
  more tokens for GM/PM, duplicated CI. Revisit only if outside contributors need access to dev.
- Three deployments in the home lab: `compose.dev.yaml`, `compose.qa.yaml`, `compose.prod.yaml`
  with separate ports, volumes, databases and secrets.

### Push policy (important)
- **Only the GM pushes, and only `dev` and `qa`** (maintainer decision 2026-11-04). Preconditions: QA APPROVE
  and green local tests (for `qa`: milestone accepted). After each push the GM watches the run with
  `gh run watch` and, on failure, sends the ticket back to `coder` with the log (counts toward the 2-round limit).
- Batched pushes (maintainer decision 2026-11-10, GitHub Actions minutes): the GM merges tickets into local
  `dev`, each with the full local suite on PostgreSQL as the gate, and pushes `dev` once every 2–3 tickets
  and always before promoting to `qa`. A failing CI run is bisected across the batch's merges. A `code` push
  costs about 25 billed minutes, a docs-only push about 1. `qa` only ever receives a `dev` commit whose CI is
  green, so `qa` pushes do not run CI again (from M6-00).
- What runs when (M6-00): `ci.yml` (lint, test-sqlite, test-postgres) runs on `dev` and `main` pushes and on
  pull requests, skipped for docs-only changes. `ci-infra.yml` (docker-build, integration-unbound,
  unbound-arm64-smoke) runs on `dev` pushes and pull requests only when a Docker-related path changes (list and
  reasons at the top of that file); on `main` pushes `ci.yml` calls it without a path filter, so `main` runs
  every job. `qa` pushes run nothing. A path-filtered or skipped workflow reports no check at all, so a
  branch protection rule that requires these checks would block merges; do not require them (or the `infra /`
  checks) without allowing for that.
- Local-only period: no pushes to `dev` or `qa` until the Actions minutes renew on 2026-12-21, unless
  the maintainer says otherwise. Commit locally; the local PostgreSQL suite is the only gate meanwhile.
- Coder, PM and QA never push. `main`, tags, releases, force pushes and branch deletions stay with the human.
- Enforced by `.claude/settings.json`: exact allow rules for `git push origin dev|qa`, deny rules for
  `main`, tags, force, `--all`, `--mirror`, delete refspecs. `gh` uses a fine-grained token scoped to this
  repository (Contents read/write, Actions read).
- Reason: branch protection on private repositories may not be available on the free GitHub plan
  (reported by users, not confirmed by official documentation: check your plan). Do not rely on it;
  rely on the permission rules above (see `docs/SETUP.md`).
- If you later get branch protection (paid plan), enable it for `qa` and `main` as a second layer.

### Credentials and permissions
- The machine where agents run has no GitHub write token and no production secrets.
- Production credentials, release tokens and the production encryption key are never present there.
- QA and prod use separate databases and separate `SECRET_KEY` / `ENCRYPTION_KEY`. Never test on the production database.
- Secret scanning runs on every commit (pre-commit hook) and in CI.
- Test fixtures never contain real client domains, IPs or mailboxes: use `example.com` / reserved ranges
  (the public release is built from a snapshot, but fixtures must be safe anyway).

## 6. Parallel work with worktrees

```
git worktree add ../app-wt-m3-02 -b feature/m3-02-spf-lookup-counter dev
```
One worktree per parallel coder; remove it after the merge. Never let two coders edit the
same file. Shared files (models, migrations, locale files, router registry) are conflict
hotspots: serialize tickets that touch them.

## 7. Definition of done (every ticket)
- Acceptance criteria met; tests added; ruff, mypy and tests green.
- Tenancy/permission test for any new endpoint.
- i18n keys present in en and it.
- No secrets, no hardcoded strings, guarded outbound client used.
- TODO.md and docs updated if behavior changed.
