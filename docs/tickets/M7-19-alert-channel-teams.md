# M7-19 Alert channel: Microsoft Teams webhook
Milestone: M7
Branch: feature/m7-19-alert-teams
Files in scope: app/services/alert_channels/teams.py, app/services/alert_channels/__init__.py (registry line), docs/MONITORING.md (Teams section), tests/services/test_alert_teams.py
Out of scope: bots, Graph API, other channels
Depends on: M7-17
Parallel-safe: no (shared registry file; may run beside M7-18 only if the GM merges the registry lines serially)
Model: sonnet
UNVERIFIED external facts (CLAUDE.md non-negotiable): Microsoft has changed Teams webhook mechanisms (retirement of Office 365 connectors in favour of Workflows/Power Automate webhooks) and the accepted payload (MessageCard vs Adaptive Card envelope), URL host patterns and size limits. The coder MUST read Microsoft's current official documentation, record URLs and the retrieval date, pick the currently supported mechanism only, and mark anything unconfirmable as `unverified` in the docs and PR. If the documented mechanism needs behaviour this project cannot satisfy (for example authentication beyond the URL), stop and report to the GM.
Acceptance criteria:
- Payload exactly as documented for the supported mechanism; values escaped per the documented text rules; size cap per the documented limit (cite) or a stated project cap.
- Reuses the M7-17 sender; response mapping per documented codes, else as M7-17; response body never stored.
- Tests (fake guarded client): payload golden file, escaping/markup injection in domain/params, truncation, response mappings.
New i18n keys: none expected (reuse alert keys); list any added (en + it)
Status: todo
