"""CI validation of the shipped ESP profiles in `profiles/esp/` (ARCHITECTURE section 8).

Runs in the normal pytest jobs: every shipped file must pass the strict loader (passes while the
directory is empty), every notes key must exist in en and it, and a profile verified more than
12 months ago produces a warning, not a failure. No network.
"""

from __future__ import annotations

import json
import warnings
from datetime import date, timedelta

from app.esp.profile import PROFILES_DIR, read_esp_profiles

LOCALES = PROFILES_DIR.parents[1] / "locales"


def test_shipped_profiles_load() -> None:
    profiles = read_esp_profiles(PROFILES_DIR)
    assert [p.id for p in profiles] == sorted(p.id for p in profiles)


def test_shipped_notes_keys_exist_in_en_and_it() -> None:
    keys: set[str] = set()
    for p in read_esp_profiles(PROFILES_DIR):
        keys.update(pf.notes_key for pf in p.pitfalls)
        for rec in (p.return_path, p.tracking_domain):
            if rec is not None and rec.notes_key is not None:
                keys.add(rec.notes_key)
    for lang in ("en", "it"):
        catalogue = json.loads((LOCALES / f"{lang}.json").read_text(encoding="utf-8"))
        missing = sorted(keys - set(catalogue))
        assert not missing, f"notes keys missing from {lang}.json: {missing}"


def test_stale_profiles_warn() -> None:
    cutoff = date.today() - timedelta(days=365)
    stale = [
        (p.id, p.verified_on) for p in read_esp_profiles(PROFILES_DIR) if p.verified_on < cutoff
    ]
    if stale:  # non-fatal by design (ARCHITECTURE section 8)
        warnings.warn(f"ESP profiles verified more than 12 months ago: {stale}", stacklevel=1)


def test_dockerfile_copies_profiles() -> None:
    # PROFILES_DIR is <repo>/profiles/esp; the image must ship it at /app/profiles (WORKDIR /app).
    dockerfile = (PROFILES_DIR.parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "WORKDIR /app\n" in dockerfile
    assert "\nCOPY profiles ./profiles\n" in dockerfile


def test_mailup_dkim_txt_alternative() -> None:
    """M6-23, maintainer decision 2026-11-12: ml01+ml02 CNAMEs OR a TXT key at ml00. The only
    shipped alternative; any other profile gaining one needs its own decision or source."""
    profiles = {p.id: p for p in read_esp_profiles(PROFILES_DIR)}
    mailup = profiles["mailup"]
    assert [s.name for s in mailup.dkim_selectors] == ["ml01", "ml02"]
    assert [[(s.name, s.type) for s in alt] for alt in mailup.dkim_alternatives] == [
        [("ml00", "txt")]
    ]
    assert mailup.is_verified("dkim.alternatives.ml00")
    assert [p.id for p in profiles.values() if p.dkim_alternatives] == ["mailup"]
