# M6-06b Localized rendering of ESP finding params
Milestone: M6
Branch: feature/m6-06b-esp-finding-rendering
Files in scope: coder first finds where finding params are rendered (look at how existing findings localize params, e.g. app/i18n and the result templates), then touches only that rendering seam for the API, the CLI text and the existing web result rendering; locales/en.json, locales/it.json; tests for each rendering path
Out of scope: the new ESPs tab (M6-07), check logic (M6-04/05), run wiring (M6-06)
Depends on: M6-06
Parallel-safe: no (shared locale files and rendering seam)
Model: opus
Acceptance criteria:
- QA (M6-04): ESP_PITFALL findings carry `params.notes_key`. Rendering (UI, API and CLI text) looks the key up in the user's language. Otherwise the detail shows only the raw pitfall code and the remediation's "Review the note" points to nothing.
- QA (M6-04): rendering localizes the `{reason}` param of `ESP_SPF_PERMERROR` (`multiple_records`, `syntax_error`), which is a raw token today.
- QA (M6-04): the `ESP_DKIM_TARGET_MISMATCH` `reason` (`chain_end`, `loop`, `empty_target`, `hop_limit`) is shown localized.
- QA (M6-05): rendering localizes the ESP finding part names (`spf.includes`, `spf.lookups`, etc.), which now appear raw in the ESP_DNS_ERROR detail.
- QA (M6-05): the `spf.lookups` error puts a joined ESP list ("Alpha, Beta") into `{esp}`, so the text must read correctly with several ESPs (test with two or more).
- Unknown tokens fall back to the raw value without crashing; tests are table-driven, en + it, no network.
- GM decision: the API keeps returning keys + raw params (shared contract); localization happens in the CLI and web renderers via app/checks/finding_text.py `display_params`.
New i18n keys: en + it for the reason tokens (SPF permerror reasons, DKIM mismatch reasons) and the part labels (`spf.includes`, `spf.lookups`, etc.); names chosen by the coder following existing key conventions
Status: done (merged into local dev after QA APPROVE; GM gate on the combined M6-06b+06c merge: full PostgreSQL suite green, lint clean)
