"""The contributor template (docs/templates/esp-profile.example.yaml) passes the real loader."""

from __future__ import annotations

import shutil
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from app.esp.profile import (
    PROFILES_DIR,
    EspProfileError,
    _load_yaml,
    parse_esp_profile,
    read_esp_profiles,
)

TEMPLATE = Path(__file__).resolve().parents[2] / "docs" / "templates" / "esp-profile.example.yaml"


def test_template_loads_with_real_loader() -> None:
    p = parse_esp_profile(_load_yaml(TEMPLATE), "example-esp")
    assert p.id == "example-esp"
    assert p.status == "verified"
    pattern = p.dkim_selectors[0].target_pattern
    assert pattern is not None
    assert pattern.matches("s1.dkim.abc.esp.example.net")
    assert not pattern.matches("s1.dkim.a.b.esp.example.net")
    assert p.pitfalls and p.return_path and p.tracking_domain


def test_template_uses_reserved_example_domains_only() -> None:
    p = parse_esp_profile(_load_yaml(TEMPLATE), "example-esp")
    hosts = [urlsplit(u).hostname or "" for u in (p.homepage, *p.sources)]
    hosts += list(p.spf_includes)
    hosts += [str(s.target_pattern) for s in p.dkim_selectors if s.target_pattern]
    for h in hosts:
        assert any(
            h == d or h.endswith("." + d) for d in ("example.com", "example.net", "example.org")
        ), h


def test_template_is_not_a_shipped_profile() -> None:
    assert not (PROFILES_DIR / "example-esp.yaml").exists()


def test_template_rejected_under_another_file_name() -> None:
    with pytest.raises(EspProfileError):
        parse_esp_profile(_load_yaml(TEMPLATE), "other-esp")


def test_template_copied_into_a_profile_dir_loads(tmp_path: Path) -> None:
    shutil.copy(TEMPLATE, tmp_path / "example-esp.yaml")
    assert [p.id for p in read_esp_profiles(tmp_path)] == ["example-esp"]
