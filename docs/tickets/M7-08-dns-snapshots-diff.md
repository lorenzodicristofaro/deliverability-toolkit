# M7-08 DNS snapshots and record diff
Milestone: M7
Branch: feature/m7-08-dns-snapshots-diff
Files in scope: app/models/dns_snapshot.py, app/models/__init__.py, migrations/versions/<next revision>_dns_snapshots.py, app/repositories/dns_snapshots.py, app/repositories/__init__.py, app/services/dns_snapshot.py, app/services/dns_diff.py, tests/services/test_dns_diff.py, tests/services/test_dns_snapshot.py, tests/repositories/test_dns_snapshots.py
Out of scope: scheduler, API/UI, alert emission, new DNS query code beyond reusing app/dns and app/checks/dnsutil
Depends on: M7-06
Parallel-safe: no (models registry, migration chain)
Model: sonnet
Acceptance criteria:
- Snapshot = normalised records of the monitored names: apex TXT (SPF), _dmarc TXT, MX, NS, configured DKIM selector names, BIMI/MTA-STS names only if those checks exist (they do not in M7: do not add). Each name stored with state (ok/nxdomain/nodata/error) and sorted normalised values; an `error` state is stored as error, never as "record removed".
- Snapshot only stored in full when it differs from the previous one or a heartbeat interval passed; `content_hash` per snapshot; bounded size.
- Diff is a pure function over two snapshots: added/removed/changed per name and type, order-insensitive, case/whitespace/TXT-string-splitting normalised, an `error` on either side yields `inconclusive` for that name, never added/removed. Output = stable change records (name, type, kind, before, after hashes + bounded values).
- Tests table-driven, no network: TXT multi-string equality, record reordering, SPF change, DMARC removed vs lookup error, NS change, huge value truncated, hostile values.
- Repository via TenantContext; cross-tenant tests; migration up/down SQLite and PostgreSQL. Retention: snapshots kept longer than runs per ARCHITECTURE section 5; setting with bounds, fake-clock test.
New i18n keys: none
Status: todo
