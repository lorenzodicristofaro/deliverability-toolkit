# SETUP — repository and local environment

Do this once, before the first `/gm` session.

## 1. Create the repository
1. On GitHub create an **empty public** repository (no README, no license, no .gitignore).
2. Locally:
```bash
mkdir deliverability-toolkit && cd deliverability-toolkit
git init -b main
git config user.name "Your Name"
git config user.email "you@example.com"
```
3. Copy in: `SPEC.md`, `ARCHITECTURE.md`, `TODO.md`, `CLAUDE.md`, `docs/WORKFLOW.md`, `docs/SETUP.md`,
   `docs/RELEASE.md`, `SECURITY.md`, `.claude/agents/*.md`, `.claude/commands/gm.md`.
4. Add a `.gitignore` (at least: `.env`, `*.db`, `*.sqlite`, `data/`, `__pycache__/`, `.venv/`, `.worktrees/`).
5. First commit and branches:
```bash
git add -A && git commit -m "chore: project documents and agent setup"
git branch dev && git branch qa
git remote add origin git@github.com:<you>/<repo>.git
git push -u origin main dev qa      # done by you, not by agents
```
6. Work happens on `dev`: `git switch dev`.

## 2. Secret scanning from day one
Install `pre-commit` and add `.pre-commit-config.yaml` with ruff and a secret scanner (for example gitleaks).
Check the scanner's current recommended hook configuration in its own documentation before pinning a version.
Add the same scan to CI (M0).
CI layout and which jobs run on which push: see "Push policy" in `docs/WORKFLOW.md`. `ci.yml` and `ci-infra.yml` are path-filtered, so a skipped run reports no check (see the rulesets below for the checks that are required).

## 3. Push permissions (GM pushes `dev` and `qa` only)
Decision 2026-11-04: the GM session may push `dev` and `qa`; everything else stays with you (see `docs/WORKFLOW.md`).
1. **Scoped credentials**: authenticate `gh` with a fine-grained token limited to this repository
   (Contents: read/write, Actions: read, no pull-request rights). Do not use a token with access to other repositories.
2. **Permission rules** in `.claude/settings.json` (checked in).
   - Allow, exact forms only: `git push origin dev`, `git push origin qa`, `git push origin dev qa`,
     `git push origin qa dev`, `gh run list|view|watch *`.
   - Deny, push: `git push *main*`, `*--force*`, `*-f*`, `*+*`, `*--tags*`, `*refs/tags*`, `*--all*`,
     `*--mirror*`, `*--delete*`, `* -d *`, `* :*`, `git push -d*`, `git push * v*`, and `git * push*` (a push with
     options before the verb, such as `git -C . push`). `git * push*` also denies any git command that contains
     " push" after the verb (a commit message, `git log --grep push`, a branch name), so agents keep the word
     "push" out of commit messages.
   - Deny, other: `git tag *`, `gh pr merge *`, `gh release *`, `gh api *`, `gh repo *`, `gh secret *`.
   - Deny, edits (Edit and Write): `**/.claude/settings*.json`, `**/.claude/agents/**`, `**/.claude/commands/**`,
     `**/.claude/skills/**`, `**/.claude/hooks/**`.
   - A form that is neither denied nor allowed asks for confirmation.
3. **Rulesets** (server side, repository Settings -> Rules): `protect-qa` (no deletion, no force push),
   `protect-dev` (no deletion, no force push), `protect-main` (no deletion, no force push, pull request required
   with 0 approvals, merge commits only, required checks `lint`, `test-sqlite`, `test-postgres`, `secret-scan`),
   `protect-tags` (tags `v*`: restrict creations, updates and deletions, block force pushes, empty bypass list;
   disabled only while you release, see `docs/RELEASE.md`).
   **Workflow permissions** (Settings -> Actions -> General): read-only; "Allow GitHub Actions to create and approve
   pull requests" disabled. The GM token has no Workflows permission, so a push touching `.github/workflows/` is
   refused; the maintainer pushes those commits.
   **Rule**: every change to `.github/**` or `.claude/**` is flagged in the merge report and is approved by the maintainer
   before the push. `tests/test_workflow_permissions.py` fails if a workflow grants itself a `write` permission
   (only exception: `security-events: write` in `codeql.yml`).
4. **Private vulnerability reporting**: enable it in Settings -> Advanced Security, so `SECURITY.md` is accurate.
The permission-rule syntax can change between Claude Code versions: after changes, **test it** by asking
Claude Code to run each of these and confirm they are refused: `git push origin main`,
`git push --force origin dev`, `git push origin v0.0.0-test`, `git push -d origin dev`,
`git -C . push origin dev`. Edit probes: an edit in a worktree is allowed; an edit of `.claude/agents/pm.md`, of a
worktree's `.claude/settings.json` and of a worktree's `.claude/agents/coder.md` is refused.

## 4. Environments in the home lab
- `compose.dev.yaml`, `compose.qa.yaml`, `compose.prod.yaml`: different ports, volumes and `.env` files.
- Separate `SECRET_KEY` and `ENCRYPTION_KEY` per environment; never copy the prod database into dev/QA.
- `dev` is deployed from `dev`, QA from `qa`, prod from tagged commits on `main`.
- Back up the prod volume (SQLite file or PostgreSQL dump) on a schedule independent from the repo.

## 5. Worktrees for parallel coders
Keep them outside the repo directory or in `.worktrees/` (ignored by git):
```bash
git worktree add .worktrees/m3-02 -b feature/m3-02-spf-lookup-counter dev
git worktree remove .worktrees/m3-02     # after merge
```

## 6. Start working
```
claude            # in the repo root
/agents           # check that coder, qa-reviewer and pm are listed
/gm milestone M0
```

## 7. Exposing the app (Docker Compose)

`compose.yaml` publishes port 8000 as `"8000:8000"`, on every host interface, and the app
serves plain HTTP there: no TLS. Put it behind a TLS-terminating reverse proxy for anything
beyond a trusted local machine. If a proxy on the same host fronts the app, you can publish
the port on loopback only by changing the mapping to `127.0.0.1:8000:8000` (an option, not
the default). Trusted-proxy handling is not implemented yet (TODO.md); do not rely on any
particular proxy header behaviour.
