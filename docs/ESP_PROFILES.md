# Adding an ESP profile (contributor guide)

An ESP profile tells the `esp` check which DNS records a customer of one email service provider
(ESP) should have. The profile is data, not code. The schema is enforced by the strict loader
in `app/esp/profile.py`; its docstring and validators are the source of truth. If this guide and
the loader disagree, the loader wins: fix the guide.

## Ground rules

- **Never write vendor values from memory.** Every DNS name, include, selector and target must
  come from the vendor's own documentation that you read for this PR. If you cannot confirm a
  part, mark it `unverified` (see below) and ask the maintainer to confirm it. Do not guess.
- Sources must be official documentation: `https` URLs on the vendor's own domains. No blogs,
  forums, resellers or search-result pages.
- Do not copy vendor text. Notes are short, original wording.
- No customer data (real customer domains, tokens, account ids) anywhere in a profile.

## Location and naming

- One file per ESP: `profiles/esp/<id>.yaml`. Only regular `*.yaml` files are allowed in that
  directory (hidden files such as `.gitkeep` are skipped; anything else, including a README or
  a symlink, makes the whole load fail).
- `id` is a slug matching `[a-z0-9][a-z0-9-]{0,39}` and must equal the file name without
  `.yaml` (`amazon-ses` lives in `amazon-ses.yaml`). Ids are unique.
- A file is at most 64 KiB, at most 200 profiles in total. Parsing is `SafeLoader`-based and
  additionally rejects duplicate keys, anchors/aliases and merge keys (`<<`).
- Loading the directory is all-or-nothing: one bad file fails everything.
- Start from `docs/templates/esp-profile.example.yaml` (fake vendor `example-esp`, reserved
  example domains). The template cannot ship: `example-esp` is not a profile in
  `profiles/esp/`, and the test loads it from `docs/templates/` explicitly.

## Schema, field by field

Unknown keys are rejected everywhere. Host names are lowercase ASCII, no trailing dot, no scheme,
port or wildcard, at least two labels, last label not numeric; a label may start with one
underscore (`_spf`).

| Field | Required | Rule |
|---|---|---|
| `id` | yes | Slug, equals the file name (above). |
| `name` | yes | Text, at most 100 characters, no control characters. |
| `homepage` | yes | `https` URL, lowercase host, no credentials, no port, ASCII, no spaces, at most 2048 characters. |
| `spf.includes` | yes | List (may be empty) of host names, at most 20, no duplicates. |
| `dkim.selectors` | yes | List (may be empty), at most 20 entries. Each: `name` (lowercase DNS label, unique), `type` (`cname` or `txt`), optional `target_pattern`. |
| `dkim.selectors[].target_pattern` | no | Only on `cname` selectors. Restricted glob, see below. |
| `return_path` | no | `{type, optional, notes_key}`: `type` is `cname`, `txt` or `mx`; `optional` is a boolean (default false); `notes_key` optional. |
| `tracking_domain` | no | Same shape as `return_path`. |
| `pitfalls` | no | List, at most 30, of `{code, notes_key, severity}`. Static advice only. |
| `verified_on` | yes | ISO date (`2026-11-02`), never in the future. The day you actually read the sources. |
| `sources` | yes | Non-empty list, at most 10, of `https` URLs (same URL rules as `homepage`, no duplicates). |
| `status` | yes | `verified` or `unverified`. |
| `unverified_fields` | iff `status: unverified` | Non-empty list, see below. Forbidden when status is `verified`. |

`verified_on` and `sources` are always required, for `unverified` profiles too.

`pitfalls[].code` must be `ESP_<ID>_<NAME>`: the profile id upper-cased with `-` replaced by
`_`, then an upper snake case name (`ESP_AMAZON_SES_EASY_DKIM_RANDOM_SELECTORS`), at most 80
characters, unique in the file. `severity` is one of the finding severities defined in
`app/checks/models.py`. A pitfall has no condition: a `when:` key is rejected, the pitfall is
always shown as an info finding for every domain assigned to this ESP.

### `target_pattern`

A restricted glob over DNS names, never a regex, never evaluated as code.

- Lowercase labels separated by dots. A label that is exactly `*` matches exactly **one whole DNS
  label**. `*` does not match several labels, an empty label, or part of a label (`a*b` is
  rejected).
- The **last two labels must be literal** (`s1.dkim.*.example.net` is fine; `s1.dkim.*.*` and
  `s1.dkim.example.*` are rejected).
- At least two labels, last label not numeric. Matching is case-insensitive and tolerates one
  trailing dot. The label count must be equal: `s1.dkim.*.example.net` does not match
  `s1.dkim.a.b.example.net`.

### `notes_key` (i18n)

`notes_key` on `return_path`, `tracking_domain` and each pitfall points to a user-facing note.
Notes are never written in the YAML: add the key to **both** `locales/en.json` and
`locales/it.json`. CI fails if a shipped key is missing from either catalogue.

- Format: dotted key, segments `[A-Za-z0-9_]`, at least two segments, at most 128 characters.
  **Hyphens are rejected.**
- Convention: `esp.<profile_id_with_underscores>.<topic>`. The segment is the profile id with `-`
  replaced by `_`: profile `amazon-ses` uses `esp.amazon_ses.return_path`. The id and the file name
  keep their hyphens.

### Per-customer DKIM selectors (pitfall)

Some ESPs issue selector names per customer or per domain (random-looking names). `dkim.selectors`
takes fixed names only, so these cannot be listed, and the schema has no wildcard for a selector
name. In that case:

1. Only after the official docs confirm it, use `selectors: []`.
2. Add a pitfall (for example `ESP_<ID>_PER_CUSTOMER_DKIM_SELECTORS`) whose note explains that the
   selector names are shown in the customer's ESP console and are not checked automatically.
3. Tell the maintainer in the PR description: this is a known schema limitation, a later schema
   extension may handle it. Do not invent a pattern or list guessed names.

## `unverified` and `unverified_fields`

Use `status: unverified` when you cannot confirm a part against official documentation (page
gone, contradictory pages, needs an account to read). It is not a place to park guesses: say in
the PR which parts, why, and ask the maintainer to confirm.

`unverified_fields` is required and non-empty with `status: unverified`, and rejected with
`status: verified`. Each entry is a path that must name something **present** in the profile, no
duplicates:

- `spf.includes` (only if the list is non-empty)
- `dkim.selectors` (only if non-empty) or `dkim.selectors.<name>`
- `return_path`, `tracking_domain` (only if present)
- `pitfalls` (only if non-empty) or `pitfalls.<code>`

A path covers its children: `dkim.selectors` marks every selector unverified. The check does not
evaluate an unverified part (`EspProfile.is_verified`) and reports that instead of guessing.
Anything still `unverified` must be confirmed or removed before a release (`docs/RELEASE.md`).

## How to verify against the documentation

1. Find the vendor's official DNS/domain-authentication page. Vendor-owned `https` URLs only.
2. Read it on the day you write the profile and put that date in `verified_on`.
3. List every page you used in `sources` (at most 10).
4. In the PR description, quote the line from each source that supports each value (include,
   selector, target pattern, return-path and tracking type). The reviewer re-reads those lines.
5. Anything you could not find in the pages: leave it out, or mark it unverified. Do not fill
   gaps from memory or from another provider's setup.

## Staleness

Vendors change DNS setups. A profile whose `verified_on` is older than 12 months makes CI emit a
warning (`tests/esp/test_shipped_profiles.py`, not a failure). Re-read the sources and update
`verified_on` and the data together; never bump the date alone.

## How profiles are used

- **Check (`esp`)**: for each ESP assigned to a domain, the check compares live DNS with the
  profile and reports findings (`ESP_SPF_INCLUDE_MISSING`, `ESP_DKIM_*`, `ESP_RETURN_PATH_*`,
  `ESP_TRACKING_MISSING`, `ESP_PROFILE_UNVERIFIED`, `ESP_DNS_ERROR`, and each pitfall as an info
  finding). A DNS failure is `error`, never "missing".
- **Detection (M6-13)**: reads the same profiles to spot ESPs that appear in a domain's DNS (SPF
  includes, DKIM selectors) without being assigned. A thin or wrong profile therefore causes
  false detections: keep `includes` and selector data precise.
- **Client viewers (M6-06c)**: a client viewer sees, read-only, the ESPs assigned to their domain,
  the ESPs detected but not assigned (flagged as possible stale configuration) and the `esp`
  check result. Notes you write are shown to customers: keep them neutral and accurate.

## Run the validation locally

```
uv run pytest -q tests/esp
uv run ruff check . && uv run ruff format --check . && uv run mypy app
```

`tests/esp/test_shipped_profiles.py` loads every file in `profiles/esp/` with the strict loader
and checks the notes keys in `en.json` and `it.json`. `tests/esp/test_template_profile.py`
checks the template with the same loader.

## PR checklist

- [ ] File is `profiles/esp/<id>.yaml`, `id` equals the file name, template comments removed.
- [ ] Every value comes from official vendor documentation (no memory, no other provider's setup).
- [ ] `sources` are vendor-owned `https` pages; `verified_on` is the day I read them.
- [ ] The PR quotes the supporting line for each value.
- [ ] Unconfirmed parts are `status: unverified` with `unverified_fields`, and the maintainer is asked.
- [ ] No text copied from the vendor; no customer data, real customer domains or secrets.
- [ ] `notes_key`s use `esp.<id_with_underscores>.*` and exist in `en.json` and `it.json`.
- [ ] Pitfall codes are `ESP_<ID>_<NAME>`.
- [ ] Per-customer DKIM selectors: empty `selectors` plus a pitfall, reported in the PR.
- [ ] `uv run pytest -q tests/esp` and the lint commands pass.
