# M6-21 deps: dnspython 2.9.2 plus compression-pointer regression test
Milestone: M6
Branch: feature/m6-21-dnspython-2-9-2
Files in scope: pyproject.toml, uv.lock, tests/dns/test_backends.py
Out of scope: any other dependency upgrade, app/ changes (unless a breaking change forces it; then stop and report to the GM), refactors, new features
Depends on: M6-20 (merged, 390cf69)
Parallel-safe: yes with M6-18 (different files)
Model: opus. QA model: opus.

Goal: move from dnspython 2.9.0 to 2.9.2 (latest on PyPI per M6-20 QA, GM decision 2026-11-11) and lock in a regression test for CVE-2026-114605 / GHSA-45c3-73f7-pv4m.
QA notes from M6-20 (to be confirmed by the coder against the official docs): 2.9.1 makes the resolver assign a fresh random query id to every query and caps negative-response TTL without SOA at 300 s (spoofing hardening); 2.9.2 fixes a WKS zone-file DoS (not used by us).

Change:
- Pin `dnspython==2.9.2` in pyproject.toml.
- Regenerate uv.lock with `uv lock`. Only dnspython may change in uv.lock; anything else must be reverted or the coder stops and reports.
- Read the official dnspython whatsnew for 2.9.1 and 2.9.2 (dnspython.readthedocs.io or GitHub releases). Quote the relevant lines in the Note, and say whether the query-id and negative-TTL changes affect our backends/tests.
- In tests/dns/test_backends.py, add a row to the bad-reply table (around lines 281-285): a DNS reply whose name compression-pointer chain is longer than 16 hops. Expected result: "unparseable"/malformed outcome, never ok. No network.

Acceptance criteria:
- uv.lock diff limited to dnspython.
- New regression row fails or is rejected as malformed in the expected way and passes with 2.9.2; the coder states whether it would have been meaningful on 2.8.0 (informational only).
- No dnspython finding from: `uv export --frozen --format requirements-txt --no-hashes --all-groups > <file>` then `uvx pip-audit -r <file> --no-deps --disable-pip`.
- Lint clean: `uv run ruff check . && uv run ruff format --check . && uv run mypy app`.
- FULL test suite passes on SQLite and on PostgreSQL (TEST_DATABASE_URL=postgresql://ci:ci-throwaway-password@localhost:5432/ci_test, container dt-test-pg, one suite at a time).
- Integration tests run if Docker is available; otherwise noted.
- Note with the quoted changelog lines for 2.9.1 and 2.9.2.

New i18n keys: none
Status: todo
