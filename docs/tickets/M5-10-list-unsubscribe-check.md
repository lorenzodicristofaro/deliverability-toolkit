# M5-10 List-Unsubscribe and One-Click header analysis
Milestone: M5
Branch: feature/m5-10-list-unsubscribe
Files in scope: app/parsers/list_unsubscribe.py, tests/parsers/test_list_unsubscribe.py
Out of scope: findings/i18n (M5-14), fetching or POSTing to unsubscribe URLs (no network; a One-Click POST test would need the guarded client, M7), provider-specific requirements (M9 data).
Depends on: none (consumes headers already parsed by app/parsers/message.py)
Parallel-safe: yes (new parser file only)
Model: sonnet
Sources (cite in the module docstring; no vendor claims): RFC 2369 (List-Unsubscribe header syntax: angle-bracketed URIs, comma separated, mailto/http(s)) and RFC 8058 (One-Click: `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, HTTPS URI in List-Unsubscribe, and the requirement that the headers be covered by a valid DKIM signature). The coder must read the RFC texts and cite the exact section numbers in the docstring and docs/CONTENT.md; do not rely on memory for section numbers.
Acceptance criteria:
- `analyze_list_unsubscribe(headers, *, dkim_signed_headers=None) -> ListUnsubscribeFacts`: header present/duplicated, parsed URIs (scheme, mailto vs https vs http), malformed bracket syntax, `List-Unsubscribe-Post` present and exact value, One-Click eligible (has https URI AND Post header), http (non-TLS) URI present, header signed by DKIM (from caller-provided `h=` lists; `None` = unknown, never "ok").
- Facts only; verdicts come in M5-14. Duplicate headers, folded headers, comments, whitespace, mixed case, empty value, 100+ URIs (capped), NUL all covered by table-driven malformed tests.
- No network, no DNS.
New i18n keys: none
Status: todo
