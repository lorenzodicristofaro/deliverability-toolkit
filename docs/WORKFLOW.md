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

Non-code tickets (maintainer decision 2026-11-11): when the diff touches only comments, documentation or data files
(seeds, profiles, locale strings, notices), or only adds tests without changing app code, QA runs ruff, mypy and the
relevant tests instead of the full suite; the GM skips a local full suite on the merge. CI on `dev` (SQLite and
PostgreSQL) is the full-suite gate. Such tickets default to `sonnet` for coder and QA unless the data needs judgement
across conflicting vendor sources.

QA worktree rule (GM, 2026-11-12): `qa-reviewer` reviews in its own temporary git worktree and never checks out a
branch in the main working tree (a QA run once left the main tree on a detached HEAD).

## 4. Loop

1. GM reads CLAUDE.md, WORKFLOW.md, TODO.md and `docs/HANDOFF.md` (if present).
2. GM asks `pm` to split the current milestone into tickets; GM reviews and sends back anything vague.
3. For each ticket: GM delegates to `coder` (own worktree/branch) → coder implements, runs ruff + mypy + the relevant tests (section 3), commits, replies in max 15 lines.
4. GM delegates to `qa-reviewer` (ticket + branch). If CHANGES REQUESTED, back to coder, on Opus if the failed code came from Sonnet (section 3; max 2 rounds, then escalate to the human).
5. On APPROVE and green tests the GM merges into `dev` and asks `pm` to update ticket status and TODO.md.
6. At milestone end the GM runs the full suite on `dev`; if green, merges `dev` → `qa` and writes `docs/reports/<milestone>.md` (max 30 lines).
7. Promotion `qa` → `main` is requested from the human.

## 5. Environments and repositories

### Decision: one public repository, three long-lived branches (Option A)
- All work happens in one public repository (full history). Branches: `feature/*` → `dev` → `qa` → `main`. `main` = releases (tags).
- A release is a pull request `qa` → `main`, opened and merged by the maintainer, followed by an annotated tag
  and a GitHub Release. See `docs/RELEASE.md`.
- The three-repo layout (dev / qa / prod) was considered and rejected for now: more sync work,
  more tokens for GM/PM, duplicated CI. Revisit only if outside contributors need access to dev.
- Three deployments in the home lab: `compose.dev.yaml`, `compose.qa.yaml`, `compose.prod.yaml`
  with separate ports, volumes, databases and secrets.

### Push policy (important)
- **Only the GM pushes, and only `dev` and `qa`** (maintainer decision 2026-11-04). Preconditions: QA APPROVE
  and green local tests (for `qa`: milestone accepted). The GM pushes `dev` after every merge; CI is the
  per-ticket gate. After each push the GM polls the run with `gh run view` and, on failure, sends the ticket
  back to `coder` with the log (counts toward the 2-round limit).
- `qa` only ever receives a `dev` commit whose CI is green, so `qa` pushes do not run CI again (from M6-00).
- What runs when (M6-00): `ci.yml` (lint, test-sqlite, test-postgres) runs on `dev` and `main` pushes and on
  pull requests, skipped for docs-only changes. `ci-infra.yml` (docker-build, integration-unbound,
  unbound-arm64-smoke) runs on `dev` pushes and pull requests only when a Docker-related path changes (list and
  reasons at the top of that file); on `main` pushes `ci.yml` calls it without a path filter, so `main` runs
  every job. `qa` pushes run nothing. A path-filtered or skipped workflow reports no check at all, so a
  required check can stay Pending on a pull request that skips it (how the ruleset treats this is unverified).
  `codeql.yml` (M6-15) runs CodeQL on `main` pushes, pull requests to `main` and weekly; not a required check.
- pip-audit (M6-24): `pip-audit.yml` audits `uv.lock` (`uv export --frozen ... --all-groups`, then pinned
  `uvx pip-audit --no-deps --disable-pip`) and fails on any known vulnerability. `ci.yml` calls it as the
  `pip-audit` job, so it runs on `dev`/`main` pushes and pull requests and is skipped for docs-only changes like
  the test jobs (maintainer decision 2026-11-12). New advisories appear without code changes, so the file also
  runs weekly (Mondays) on its own; scheduled workflows run from `main`, so the schedule starts after the next
  `qa` -> `main` promotion. Not a required check.
- Red pip-audit: first bump the dependency (`uv lock --upgrade-package <name>`, with a regression test where
  the advisory is reachable). If no fixed version exists, add a time-boxed ignore: `--ignore-vuln <GHSA id>` on
  the pip-audit command, with a comment next to the flag (GHSA id, reason, expiry date), and the same three
  facts in the commit message. Maximum 90 days; remove the flag when it expires or the fix ships. No silent
  ignores.
- Coder, PM and QA never push. `main`, tags, releases, force pushes and branch deletions stay with the human.
- Enforced in two layers. Client side, `.claude/settings.json`: exact allow rules for `git push origin dev|qa`
  (and both together) and `gh run list|view|watch`; deny rules for pushes naming `main`, force (`--force`, `-f`,
  `+`), `--tags`, `refs/tags`, `--all`, `--mirror`, `--delete`, `-d`, `:` refspecs, tag names `v*`, and any
  `git ... push` with options before the verb; for `git tag`, `gh pr merge`, `gh release`, `gh api`, `gh repo`,
  `gh secret`; and for Edit/Write of `.claude/settings*.json`, `.claude/agents/`, `.claude/commands/`,
  `.claude/skills/`, `.claude/hooks/`. A form neither denied nor allowed asks for confirmation. Server side,
  repository rulesets: `protect-main` (no deletion, no force push, pull request required with 0 approvals, merge
  commits only, required checks `lint`, `test-sqlite`, `test-postgres`, `secret-scan`), `protect-qa` and
  `protect-dev` (no deletion, no force push), `protect-tags` (tags `v*`: no creation, update or deletion, no
  force push, empty bypass list). See `docs/SETUP.md` and `docs/RELEASE.md`.
- Every change to `.github/**` or `.claude/**` is flagged in the merge report and goes to the maintainer before
  the push. Commits touching `.github/workflows/` are pushed by the maintainer (the GM token has no Workflows
  permission).
- `qa` → `main` is a pull request opened and merged by the maintainer.

### Credentials and permissions
- The machine where agents run has a fine-grained GitHub token scoped to this repository: Contents read/write,
  Actions read, no pull-request rights, no Workflows permission. It has no production secrets.
- Repository Actions settings: workflow permissions read-only; "Allow GitHub Actions to create and approve pull
  requests" disabled. `tests/test_workflow_permissions.py` rejects any `write` grant in a workflow.
- Production credentials, release tokens and the production encryption key are never present there.
- QA and prod use separate databases and separate `SECRET_KEY` / `ENCRYPTION_KEY`. Never test on the production database.
- Secret scanning runs on every commit (pre-commit hook) and in CI.
- Test fixtures never contain real client domains, IPs or mailboxes: use `example.com` / reserved ranges
  (the repository is public, so fixtures must be safe).

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
