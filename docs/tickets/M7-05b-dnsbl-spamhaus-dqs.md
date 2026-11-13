# M7-05b Spamhaus via DQS key
Milestone: M7
Branch: feature/m7-05b-spamhaus-dqs
Files in scope: seeds/dnsbl.yaml (Spamhaus entries only), app/checks/dnsbl_schema.py and app/checks/dnsbl_engine.py (DQS query form and key placeholder only), the instance-admin setting for the DQS key (existing settings service/API surface, reuse M7-14b secret service), tests/checks/test_dnsbl_*.py, tests/api (admin setting permission test), locales/en.json, locales/it.json, docs/DNSBL.md
Out of scope: other lists, M7-05 surfaces beyond reading the key-present state, new migration unless the settings store has no secret column (then stop and report to the GM)
Depends on: M7-03b, M7-05, M7-14b
Parallel-safe: no (seed, schema, locale files, secret service)
Model: opus
UNVERIFIED EXTERNAL FACTS: Spamhaus DQS query form, zone names, return codes and 127.255.255.x error codes are NOT known to this ticket. The coder fetches and cites ONLY pages under https://docs.spamhaus.com on the day, records verified_on and sources; anything not stated there is `unverified` with `unverified_fields`. No third-party sources.
Acceptance criteria:
- Seed contains Spamhaus ZEN and DBL entries using the DQS query form (key as part of the query name), `default_enabled` semantics: enabled only when a DQS key is configured.
- Key is configured by instance admin only, stored encrypted via the M7-14b secret service, never logged, never returned by any API/CLI/UI (only a "key configured" boolean), never present in findings, params or error text.
- No key -> list result `not_applicable` and no DNS query is made (test asserts zero queries).
- 127.255.255.x error/refusal codes mapped to the engine's refusal handling only as stated on the official pages; return code categories likewise.
- Permission test: non-instance-admin cannot set or clear the key (403); key never appears in response bodies or captured logs (test).
- No network in tests (fake DNS backend); query name with key is built through the engine's non-public IP policy path.
- docs/DNSBL.md lists the cited pages, verified_on and every unverified item; unverified items are reported to the maintainer.
New i18n keys: settings label/help for the DQS key and a not-configured reason text (names chosen by the coder, en + it)
Status: todo
