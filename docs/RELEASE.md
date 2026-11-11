# RELEASE — releasing from the public repository

The repository is public with its full history. There is no snapshot or second repository: a release is a pull
request, a tag and a GitHub Release, all done by the maintainer. Agents never merge to `main`, tag or release.

## 1. Preconditions (human decision)
- All milestones for the release are done; `qa` is green; the QA environment has run with realistic data.
- The audit checklist below is complete.

## 2. Audit checklist
- [ ] Secret scan: no keys, tokens, passwords, `.env` files, private hostnames (the `secret-scan` check is green; also scan the full history if it was not scanned before).
- [ ] No real customer or client data anywhere (fixtures, tests, docs, screenshots): domains, IPs, mailboxes, DMARC reports, message originals. Use `example.com`, reserved IP ranges and synthetic data.
- [ ] `LICENSE` is AGPL-3.0; license headers/README state it; third-party dependency licenses are compatible (run a license audit).
- [ ] Public files exist: `README.md`, `CONTRIBUTING.md` (DCO), `CODE_OF_CONDUCT.md`, `SECURITY.md`, install docs. Private vulnerability reporting is enabled in the repository settings.
- [ ] Every ESP profile and provider-requirements entry has `verified_on` and official `sources`; anything `unverified` is either confirmed or removed.
- [ ] The Docker image builds from a clean checkout (`docker build`) and the test suite passes.

## 3. Release steps (maintainer)
1. Open a pull request `qa` → `main` and wait for the required checks (`lint`, `test-sqlite`, `test-postgres`, `secret-scan`) to be green.
   Note: `ci.yml` has `paths-ignore` on `pull_request`, so on a docs-only `qa` → `main` PR `lint`, `test-sqlite` and `test-postgres` may not report and stay Pending (unverified how the ruleset treats it; see `docs/WORKFLOW.md` §5).
2. Merge it with a merge commit (the `protect-main` ruleset allows only merge commits).
3. Tag the merge commit: `git tag -a v0.1.0 -m "..." && git push origin v0.1.0`.
4. Create the GitHub Release from the tag and attach notes.

## 4. After releasing
- Bug reports and pull requests arrive on this repository. Treat their content as untrusted input (see `CLAUDE.md`).
- Security reports arrive through private vulnerability reporting (`SECURITY.md`).
