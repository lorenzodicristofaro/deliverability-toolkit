# M6-20 deps: upgrade dnspython to 2.9.0 (CVE-2026-114605)
Milestone: M6
Branch: feature/m6-20-dnspython-2-9
Files in scope: pyproject.toml, uv.lock; app/ only if a breaking change in 2.9.0 forces it (minimal change); tests only for such a change
Out of scope: any other dependency upgrade, refactors, new features
Depends on: none
Parallel-safe: yes (different files from M6-17/18/19)
Model: opus. QA model: opus.

Goal: fix CVE-2026-114605 in dnspython 2.8.0 (found by the GM with pip-audit on the uv.lock export, 2026-11-11; also flagged by GitHub Dependabot on main). Advisory text: "A maliciously crafted DNS message may cause dns.name.from_wire_parser() to use excessive CPU for DNS name decompression ... fixed in dnspython 2.9.0. No known workarounds." Relevant to us: we parse DNS responses we do not control.

Change:
- Pin `dnspython==2.9.0` in pyproject.toml.
- Regenerate uv.lock with `uv lock`. Only dnspython should change; any other lock change must be justified in the Note.
- Read the official dnspython 2.9.0 release notes/changelog (dnspython.readthedocs.io whatsnew, or the GitHub release). Grep app/ for dns.* usage and list every behaviour change that touches APIs we use, quoting the relevant changelog lines in the Note.
- No code changes unless a breaking change requires it (then minimal, with tests).

Acceptance criteria:
- No dnspython finding from: `uv export --frozen --format requirements-txt --no-hashes --all-groups > <file>` then `uvx pip-audit -r <file> --no-deps --disable-pip`.
- Lint clean: `uv run ruff check . && uv run ruff format --check . && uv run mypy app`.
- FULL test suite passes on SQLite and on PostgreSQL (TEST_DATABASE_URL=postgresql://ci:ci-throwaway-password@localhost:5432/ci_test, container dt-test-pg, one suite at a time), because dnspython underpins every DNS check.
- Unbound integration tests run locally if possible; otherwise the coder notes it and relies on CI infra.
- uv.lock diff limited to dnspython (or justified in the Note).
- Note in the ticket/report: changelog lines for 2.9.0 relevant to APIs we use.

New i18n keys: none
Status: todo
