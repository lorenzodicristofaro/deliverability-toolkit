# Contributing

Thank you for your interest. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Sign-off (DCO)

Contributions are accepted under the Developer Certificate of Origin. Sign off every commit:

```
git commit -s
```

This adds a `Signed-off-by: Your Name <you@example.com>` line, certifying the text below.
The project license is GNU AGPL-3.0-or-later (see [LICENSE](LICENSE)).

## Rules

- Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, ...).
- Tests are required. Parsers and checks need table-driven tests, including malformed input, with no network access in unit tests.
- Every user-facing string must use an i18n key, with both English and Italian entries. No hardcoded user-facing strings.

## Developer Certificate of Origin 1.1

Source: https://developercertificate.org/ (fetched 2026-11-04), reproduced verbatim.

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
