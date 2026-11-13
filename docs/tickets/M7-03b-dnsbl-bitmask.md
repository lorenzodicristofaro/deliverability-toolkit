# M7-03b DNSBL bitmask return codes and default_enabled
Milestone: M7
Branch: feature/m7-03b-dnsbl-bitmask
Files in scope: app/checks/dnsbl_schema.py, app/checks/dnsbl_engine.py, tests/checks/test_dnsbl_*.py, seeds/dnsbl.yaml (ONLY: switch surbl-multi and uribl-multi to bitmask mode and set `default_enabled: false` on spamcop-bl, surbl-multi, uribl-multi), docs/DNSBL.md
Out of scope: registration/API/UI (M7-05), adding or changing any other seed value, Spamhaus (M7-05b)
Depends on: M7-03 (M7-04 merged)
Parallel-safe: no (schema + seed shared with M7-05, M7-05b)
Model: opus
Maintainer decisions 2026-11-14: SURBL and URIBL official pages state their multi zones are bitmasked; lists with restrictive usage policies are disabled by default.
Acceptance criteria:
- Schema field per list `return_code_mode: exact|bitmask` (default `exact`, existing behaviour unchanged). Strict loader rejects other values.
- bitmask mode: the last octet of the 127.0.0.x answer is decomposed into bits; each set bit maps to its category from the list's code table. A sum such as 127.0.0.80 gives `listed` with both categories.
- Any set bit with no mapping, or a refusal/error code combined with bits, -> `error` with reason conflicting (never `listed`, never `clean`).
- Bit values and categories in the seed are taken only from the already recorded official sources; if the code table lacks a bit the page states, mark `unverified_fields`, do not guess.
- Schema field `default_enabled: bool` (default true). The three current seed lists get `false` (SURBL, URIBL by restrictive usage policy; SpamCop pending maintainer verification). The engine itself does not apply enablement; it exposes the field for M7-05.
- Table-driven tests: single bit, summed bits, unmapped bit, refusal plus bits, zero/out-of-range octet, non-127 answer, exact-mode regression, loader rejection of bad mode. No network.
- docs/DNSBL.md documents both fields and the maintainer decision.
New i18n keys: none
Status: todo
