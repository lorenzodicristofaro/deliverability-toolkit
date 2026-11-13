# R1-33 Push policy as enforced, workflow permissions test
Milestone: R1
Branch: dev (maintainer instruction, no worktree)
Findings: INFRA-01, INFRA-02
Files in scope: .claude/settings.json (committed unchanged), docs/RELEASE.md, docs/SETUP.md, docs/WORKFLOW.md, docs/tickets/R1-33-push-policy-docs.md, TODO.md, tests/test_workflow_permissions.py
Out of scope: any change to .github/**, .claude/agents/**, app code
Depends on: none
Parallel-safe: yes
Model: sonnet
Acceptance criteria:
- `.claude/settings.json` (new deny rules, prepared by the maintainer) committed byte for byte (sha256 7ab5fbf5...5cdb82).
- docs/RELEASE.md: protect-tags set to Disabled before the tag step, back to Active after the GitHub Release.
- docs/SETUP.md §3 and docs/WORKFLOW.md describe the real client-side deny list, the server-side rulesets (protect-main, protect-qa, protect-dev, protect-tags), read-only workflow permissions, the token without Workflows, and the rule that `.github/**` and `.claude/**` changes go to the maintainer before the push.
- tests/test_workflow_permissions.py fails on any `write` or `write-all` in a workflow or job `permissions` block (only exception: `security-events: write` at job level in codeql.yml); real files pass.
New i18n keys: none
Status: in-review

## Notes
- GitHub settings (rulesets protect-dev, protect-tags; read-only workflow permissions; pull request approval by Actions disabled; token without Workflows) were done by the maintainer.
- `.claude/agents/qa-reviewer.md` cannot be edited by agents: the maintainer adds the checklist line given in the report.
