"""Organizational domain (RFC 7489 section 6.6.3) from the Public Suffix List.

Data source: the `publicsuffixlist` package (MPL-2.0), which ships the Mozilla Public Suffix List
(MPL-2.0) inside its wheel. Nothing is fetched at import or run time.
  package: https://pypi.org/project/publicsuffixlist/   version 1.1.2.20261106 (see uv.lock)
  list:    https://publicsuffix.org/list/                 licence: MPL-2.0, verified 2026-11-12 from
           https://github.com/publicsuffix/list/blob/main/LICENSE (maintainer accepts)
  verified_on: 2026-11-12
Manual update step: `uv lock --upgrade-package publicsuffixlist`, then run the tests and refresh
verified_on here and in seeds/public_suffix_source.yaml.

Private-section decision: the FULL list (ICANN plus private sections) is used, so private registry
boundaries are respected for DMARC. `blogspot.com` and `github.io` are suffixes here:
`foo.blogspot.com` has organizational domain `foo.blogspot.com`, and `blogspot.com` itself has
none (returns None). Tenants on shared platforms thus never inherit the platform's policy.
Unknown TLDs follow the PSL default rule `*` (the last label is the suffix).
"""

from __future__ import annotations

from functools import lru_cache

from publicsuffixlist import PublicSuffixList

from app.core.domain_names import InvalidDomainName, to_ascii_domain


@lru_cache(maxsize=1)
def _psl() -> PublicSuffixList:
    return PublicSuffixList(accept_unknown=True)


def organizational_domain(name: object) -> str | None:
    """Return the organizational domain (ASCII, lowercase) of `name`.

    Returns None when `name` is a single label or is itself a public suffix (no organizational
    domain exists). Raises InvalidDomainName for other malformed input (empty, oversized, bad
    IDNA, IP literal, ...)."""
    try:
        ascii_name = to_ascii_domain(name)
    except InvalidDomainName as exc:
        if exc.reason == "single_label":
            return None
        raise
    return _psl().privatesuffix(ascii_name)


def is_subdomain_of_org(name: object) -> bool:
    """True when `name` has an organizational domain and is a strict subdomain of it."""
    org = organizational_domain(name)
    return org is not None and to_ascii_domain(name) != org
