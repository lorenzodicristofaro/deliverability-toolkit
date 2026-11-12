# M6-25 Knowledge data: PSL licence and Gmail clip size verified
Milestone: M6
Branch: feature/m6-25-psl-gmail-clip-verified
Files in scope: seeds/public_suffix_source.yaml, docs/CONTENT.md, app/parsers/content_html.py (comments and docstring only, no logic), tests only if one asserts the unverified status (tests/core/test_org_domain.py, tests/parsers/test_content_html.py, seed loader tests: the coder checks)
Out of scope: seeds/dkim_selectors.yaml (M6-23), seeds/url_shorteners.yaml (stays unverified), any threshold or behaviour change, renaming gmail_* fields
Depends on: none
Parallel-safe: yes with M6-23 and M6-24 (disjoint files)
Model: sonnet. QA model: sonnet (data and comments only).

Goal: record two maintainer confirmations of 2026-11-12.

Change:
- seeds/public_suffix_source.yaml: licence MPL-2.0 verified. GM read https://github.com/publicsuffix/list LICENSE on 2026-11-12 ("Mozilla Public License Version 2.0"); maintainer accepts. Replace the `licence_status: unverified ...` line and the "per the PyPI page only" comment; add the source https://github.com/publicsuffix/list/blob/main/LICENSE; verified_on 2026-11-12. Keep `status: verified`, version and update_step untouched. If the seed loader or schema validates field names, keep it passing (adjust the field shape in line with the loader, do not break it).
- Gmail clipping threshold 102,400 bytes (GMAIL_CLIP_THRESHOLD_BYTES): confirmed by the maintainer 2026-11-12 from their own experience. Source = "maintainer confirmation 2026-11-12", no URL; do not cite a vendor page. Update every place that records it as unverified: docs/CONTENT.md (line ~338 constants table, and any other mention) and the comments/docstring in app/parsers/content_html.py (lines ~15, ~34, ~124). Wording must stay honest: confirmed by the maintainer, not by Google documentation.
- Do not change finding severity (CONTENT_GMAIL_CLIP_RISK stays low, advisory).

Acceptance criteria:
- grep for "unverified" near the PSL licence and the Gmail clip constant returns nothing stale; the new wording names maintainer confirmation 2026-11-12.
- Seed validation and the tests that load seeds pass; no behavioural diff (threshold still 102_400).
- Lint clean: `uv run ruff check . && uv run ruff format --check . && uv run mypy app`; relevant tests only (non-code ticket per docs/WORKFLOW.md section 3; CI is the full-suite gate).

New i18n keys: none
Status: done (merged 348959d, QA APPROVE; dev CI green)
