# RELEASE — publishing clean releases to a new public repository

The private repository is never made public and its history is never published. The public repository is
**new** and contains one commit per release, built from a tagged snapshot of the private repository.

## 1. Preconditions (human decision)
- All milestones for the release are done; `qa` is green; the QA environment has run with realistic data.
- The human tags the release candidate on `main` (`git tag -a v0.1.0 -m "..."`).

## 2. Pre-publication audit checklist
- [ ] Secret scan on the snapshot working tree: no keys, tokens, passwords, `.env` files, private hostnames.
- [ ] No real customer or client data anywhere (fixtures, tests, docs, screenshots): domains, IPs, mailboxes, DMARC reports, message originals. Replace with `example.com`, reserved IP ranges and synthetic data.
- [ ] `LICENSE` is AGPL-3.0; license headers/README state it; third-party dependency licenses are compatible (run a license audit).
- [ ] Required public files exist: `README.md`, `CONTRIBUTING.md` (DCO), `CODE_OF_CONDUCT.md`, `SECURITY.md`, install docs.
- [ ] Every ESP profile and provider-requirements entry has `verified_on` and official `sources`; anything `unverified` is either confirmed or removed.
- [ ] Internal process files are excluded via `.release-ignore` (tickets, reports, handoff, agent definitions, internal workflow). Decide explicitly whether to publish `CLAUDE.md`, `TODO.md`, `SPEC.md` and `ARCHITECTURE.md` (the last two are normally useful to contributors).
- [ ] Docker image builds from the snapshot alone (`docker build` in the exported tree) and the test suite passes there.
- [ ] Commit author in the public repo is the identity you want to make public.

## 3. Build the snapshot and commit it to the public repo
```bash
# one-time: create the empty public repository on GitHub, clone it next to the private one
git clone git@github.com:<you>/<public-repo>.git ../<public-repo>

# for every release, from the private repo root, on the tagged commit:
scripts/publish_release.sh v0.1.0 ../<public-repo>

# review, then push yourself
cd ../<public-repo> && git log --stat -1 && git push origin main --tags
```
The script exports the tag with `git archive`, removes the paths listed in `.release-ignore`, replaces the
contents of the public working tree, commits `Release <tag>` and creates the same tag. It never pushes.
**Test it first on a scratch repository** and read the diff before pushing.

## 4. After publishing
- Create the GitHub release and attach notes. Publish the container image only from the public repo's CI.
- Bug reports and pull requests arrive on the public repo. Port accepted changes into the private repo
  (as tickets) so the next snapshot contains them; the public repo is never the source of truth.
- Keep the private repo private permanently, or archive it. Never change its visibility, since that would
  publish the full agent history.
