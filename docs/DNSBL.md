# DNSBL / URIBL seed (M7-04)

Data: `seeds/dnsbl.yaml`, loaded by the strict loader in `app/checks/dnsbl_schema.py`.
All facts were taken on 2026-11-14 from the list operators' own pages. `unverified` lists cannot
produce `listed` (M7-03); the maintainer decides what to confirm.

| id | zone | mode | return codes | default_enabled | sources | verified_on | status |
|---|---|---|---|---|---|---|---|
| spamcop-bl | bl.spamcop.net | exact | 127.0.0.2 listed | false | spamcop.net/bl.shtml, /fom-serve/cache/291.html, /297.html | 2026-11-14 | unverified (ipv6, usage_policy) |
| surbl-multi | multi.surbl.org | bitmask | 4 DM, 8 PH, 16 MW, 32 CT, 64 ABUSE, 128 CR; 127.0.0.1 refused | false | surbl.org/lists, surbl.org/usage-policy | 2026-11-14 | unverified (return_codes) |
| uribl-multi | multi.uribl.com | bitmask | 2 black, 4 grey, 8 red; 127.0.0.1 blocked | false | uribl.com/about.shtml | 2026-11-14 | unverified (return_codes) |

## Schema fields added in M7-03b
- `return_code_mode: exact | bitmask` (optional, default `exact`; any other value is rejected by
  the loader). `exact`: each answer must match a listed code (M7-03 behaviour, unchanged).
  `bitmask`: every `listed`/`info` code must be a single bit of 127.0.0.x (1, 2, 4, ... 128);
  an answer that is not itself a refusal code is split into the bits of its last octet and each
  bit is looked up. 127.0.0.80 on SURBL = 16 (MW) + 64 (ABUSE) gives `listed` with both
  categories. Never guessed, always `error`: a bit with no mapping or the answer 127.0.0.0
  (`unmapped_code`), a refusal bit summed with other bits (`conflicting_codes`, e.g. 127.0.0.3),
  an answer outside 127.0.0.0/24 (`answer_out_of_range`). Refusal codes are still matched exactly.
- `default_enabled: bool` (optional, default `true`). Read only by the `dnsbl` check (M7-05) and the
  instance enablement (M7-05c); the loader and the engine do not act on it.

Maintainer decisions 2026-11-14: the SURBL and URIBL official pages state that their multi zones
are bitmasked, so both are `bitmask`. Lists with restrictive usage policies are disabled by
default: SURBL and URIBL (usage policy above), SpamCop pending maintainer verification of its
policy (its Policies and Disclaimers page was not read).

## Enablement (M7-05c)

A list with `default_enabled: false` is queried only after the instance admin enables it. The
setting is instance-wide (every tenant's runs read it), stored in `dnsbl_list_enablements`
(migration 0010: list id, enabled_by, enabled_at, policy_acknowledged, policy_acknowledged_at,
unverified_confirmed; a row means enabled, disabling deletes it) and reached only through
`DnsblEnablementRepository`. Rules live in `app/services/dnsbl_admin.py`.

- Who: only the instance admin flag (`instance.manage`). Every tenant role, client viewer
  included, gets 403; anonymous 401 (a page load redirects to the login).
- API: `GET /api/v1/dnsbl-lists` (each list with its usage-policy text, sources, status,
  unverified fields, verified_on and enabled state), `POST /api/v1/dnsbl-lists/{id}/enable` with
  `{"policy_acknowledged": true}` and, for a list whose status is not `verified`,
  `"unverified_confirmed": true` too (422 without either), `POST /api/v1/dnsbl-lists/{id}/disable`.
  An id not in the seed file is 404; a `default_enabled: true` list cannot be toggled (409).
- Page: `/dnsbl-lists` shows the same data with one checkbox for the policy acknowledgement and a
  second one for an unverified list. It is not linked from the navigation yet.
- Shown text comes only from this file: `usage_policy` verbatim, or "the list data has no usage
  policy text" when the field is absent. Nothing about a list's policy is written in code.
- Enabling an unverified list does not make it produce `listed`: the engine still reports it as
  `DNSBL_LIST_UNVERIFIED` (status `error`) until the maintainer confirms its data.
- Audit: there is no audit log table yet; enable and disable are logged as structured events
  (`dnsbl_lists.enabled` / `dnsbl_lists.disabled`, actor and list id), like the other admin
  services.

## Why unverified
- SpamCop: pages state no query limits, commercial terms or resolver rules, and no IPv6 support
  statement (flag set to false, unconfirmed). Policies and Disclaimers page was not read.
- SURBL and URIBL: the bit tables were not reconfirmed in M7-03b (no new fetch), so
  `return_codes` stays unverified. A bit the operator page states but the table lacks would
  give `unmapped_code` (error), never a guess. URIBL also documents 127.0.0.14 (test points, now
  read as 2 + 4 + 8 = black, grey, red) and 127.0.0.255 (split-horizon block convention: bit 1
  is the refusal code, so it is `conflicting_codes`, an error); neither is mapped separately.

## Left out
- Spamhaus ZEN/DBL: official docs (docs.spamhaus.com) give return codes (ZEN 127.0.0.2/3/4/9/10/11/30;
  DBL 127.0.1.x; errors 127.255.255.250-252) but the legacy public mirror pages return 404 and
  the documented route is a registered DQS query key (`<key>.zen.dq.spamhaus.net`), plus open
  resolvers are restricted. Registration is excluded by default.
- Barracuda: barracudacentral.org returns HTTP 403, documentation not fetchable.
