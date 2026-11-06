# M3-12 DKIM selector seed file and loader
Milestone: M3
Branch: feature/m3-12-dkim-selector-seed
Files in scope: seeds/dkim_selectors.yaml, app/checks/dkim_selectors.py (loader + validator), tests/checks/test_dkim_selectors.py
Out of scope: probing (M3-13), tenant/admin custom selectors and the admin UI (M5, SPEC section 5), editing app/dns/knowledge.py (follow its pattern in a separate module to avoid the hotspot)
Depends on: none
Parallel-safe: yes
Model: sonnet
Acceptance criteria:
- YAML schema: top-level `verified_on`, `sources`, `selectors: [{name, provider, record_type: txt|cname|either, notes, status: verified|unverified, sources: [https URL]}]`; loader validates like `app/dns/knowledge.py` (unknown keys, bad date, non-https source, duplicate names, label rules via the DNS name validator, future `verified_on` tolerance consistent with the M2-07 behaviour).
- Never invent vendor configuration: an entry is `verified` only if the coder can cite the official vendor page it read (URL in the entry's `sources`); every other entry is `status: unverified` with no provider claim beyond "commonly seen". The coder lists unverified entries in the report so the maintainer can confirm (GM escalation 3 in WORKFLOW).
- Generic selectors (`default`, `dkim`, `mail`, `s1`, `s2`, `k1`, date-based patterns are NOT enumerated) may be included as `unverified` generic guesses; the list size is capped (e.g. 200) by the loader.
- `list_selectors() -> tuple[Selector, ...]` cached, sorted, deterministic.
- Tests: valid file, every malformed schema case, guard test that no entry is `verified` without a source, shipped file loads.
New i18n keys: none
Status: done
