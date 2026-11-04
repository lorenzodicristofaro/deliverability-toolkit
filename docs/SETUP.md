# SETUP — private repository and local environment

Do this once, before the first `/gm` session.

## 1. Create the repository
1. On GitHub create an **empty private** repository (no README, no license, no .gitignore).
2. Locally:
```bash
mkdir deliverability-toolkit && cd deliverability-toolkit
git init -b main
git config user.name "Your Name"
git config user.email "you@example.com"
```
3. Copy in: `SPEC.md`, `ARCHITECTURE.md`, `TODO.md`, `CLAUDE.md`, `docs/WORKFLOW.md`, `docs/SETUP.md`,
   `docs/RELEASE.md`, `scripts/publish_release.sh`, `.release-ignore`, `.claude/agents/*.md`, `.claude/commands/gm.md`.
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

## 3. Stop agents from pushing
Agents must not be able to push. Two layers:
1. **No credentials**: do not configure an SSH key or token on the machine/session where agents run.
   Push from a separate terminal or machine where only you are authenticated.
2. **Deny rule** in `.claude/settings.json`:
```json
{
  "permissions": {
    "deny": ["Bash(git push:*)"]
  }
}
```
The permission-rule syntax can change between Claude Code versions: check the permissions documentation of your
version, then **test it**: ask Claude Code to run `git push` and confirm it is refused.

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
