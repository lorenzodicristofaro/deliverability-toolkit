# M1-09 i18n scaffolding (en + it) and missing-key test
Milestone: M1
Branch: feature/m1-09-i18n-scaffolding
Files in scope: app/core/i18n.py, locales/en.json, locales/it.json, tests/test_i18n.py
Out of scope: templates, language switch UI (M1-16), user/tenant language preference storage (M1-10 column, M1-15 use)
Depends on: M1-01
Parallel-safe: yes with M1-06/M1-07 (disjoint); no with any other ticket editing locales/
Model: sonnet
Acceptance criteria:
- `t(key, lang, **params)` loads `locales/{en,it}.json` (flat dotted keys), falls back to `en`, raises/flags unknown keys in tests (returns the key in production and logs once).
- Language resolution helper: explicit user pref > tenant pref > Accept-Language > default `en` (pure function, table-driven tests incl. malformed Accept-Language).
- CI-visible test: every key in en exists in it and vice versa; params placeholders match between languages; no empty values; every key used as a literal in `app/` (grep-style scan of `t("...")` and constants such as `RESOLVER_ADDR_INVALID_KEY`) exists in en.
- Keys declared by earlier code are added: `config.resolver_addr.invalid` (used by app/core/config.py), plus M1-01 keys.
- Locale files are a hotspot: later tickets append keys only; keys sorted alphabetically to minimise merge conflicts.
New i18n keys: config.resolver_addr.invalid, config.missing, config.invalid_value, config.resolver_addrs_required (en + it)
Status: todo
