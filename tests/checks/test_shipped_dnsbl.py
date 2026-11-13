"""CI validation of the shipped `seeds/dnsbl.yaml` (M7-04). No network."""

from __future__ import annotations

import warnings
from datetime import date, timedelta

from app.checks.dnsbl_schema import DNSBL_FILE, read_dnsbl_lists


def test_shipped_lists_load_strictly() -> None:
    lists = read_dnsbl_lists(DNSBL_FILE)
    assert lists
    assert len({lst.zone for lst in lists}) == len(lists)
    assert len({lst.id for lst in lists}) == len(lists)


def test_shipped_lists_carry_provenance() -> None:
    for lst in read_dnsbl_lists(DNSBL_FILE):
        assert lst.verified_on <= date.today()
        assert lst.sources
        assert all(s.startswith("https://") for s in lst.sources)
        if not lst.verified:
            assert lst.unverified_fields


def test_stale_lists_warn() -> None:
    cutoff = date.today() - timedelta(days=365)
    stale = [(x.id, x.verified_on) for x in read_dnsbl_lists(DNSBL_FILE) if x.verified_on < cutoff]
    if stale:  # non-fatal by design
        warnings.warn(f"DNSBL lists verified more than 12 months ago: {stale}", stacklevel=1)
