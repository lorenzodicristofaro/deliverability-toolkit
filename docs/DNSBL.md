# DNSBL / URIBL seed (M7-04)

Data: `seeds/dnsbl.yaml`, loaded by the strict loader in `app/checks/dnsbl_schema.py`.
All facts were taken on 2026-11-14 from the list operators' own pages. `unverified` lists cannot
produce `listed` (M7-03); the maintainer decides what to confirm.

| id | zone | return codes | sources | verified_on | status |
|---|---|---|---|---|---|
| spamcop-bl | bl.spamcop.net | 127.0.0.2 listed | spamcop.net/bl.shtml, /fom-serve/cache/291.html, /297.html | 2026-11-14 | unverified (ipv6, usage_policy) |
| surbl-multi | multi.surbl.org | bitmask 4 DM, 8 PH, 16 MW, 32 CT, 64 ABUSE, 128 CR; 127.0.0.1 refused | surbl.org/lists, surbl.org/usage-policy | 2026-11-14 | unverified (return_codes) |
| uribl-multi | multi.uribl.com | 2 black, 4 grey, 8 red; 127.0.0.1 blocked | uribl.com/about.shtml | 2026-11-14 | unverified (return_codes) |

## Why unverified
- SpamCop: pages state no query limits, commercial terms or resolver rules, and no IPv6 support
  statement (flag set to false, unconfirmed). Policies and Disclaimers page was not read.
- SURBL and URIBL answers are bitmasks (sums such as 127.0.0.80 = MW + ABUSE); only the single
  bits are listed in the data, so combined answers would be `unmapped_code`. Enumerating the sums
  is a maintainer decision. URIBL also documents 127.0.0.14 (test points) and 127.0.0.255
  (split-horizon block convention) which are not mapped.

## Left out
- Spamhaus ZEN/DBL: official docs (docs.spamhaus.com) give return codes (ZEN 127.0.0.2/3/4/9/10/11/30;
  DBL 127.0.1.x; errors 127.255.255.250-252) but the legacy public mirror pages return 404 and
  the documented route is a registered DQS query key (`<key>.zen.dq.spamhaus.net`), plus open
  resolvers are restricted. Registration is excluded by default.
- Barracuda: barracudacentral.org returns HTTP 403, documentation not fetchable.
