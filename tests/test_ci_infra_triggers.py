"""R1-27 (INFRA-05): ci-infra.yml must run on app/ and locales/ changes. Static, no network."""

from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci-infra.yml"
REQUIRED = ("app/**", "locales/**")


def trigger_paths(text: str, event: str) -> list[str] | None:
    """Return the `paths` list of a trigger event, or None when absent or malformed."""
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        return None
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    triggers = doc.get("on", doc.get(True))
    if not isinstance(triggers, dict):
        return None
    block = triggers.get(event)
    paths = block.get("paths") if isinstance(block, dict) else None
    return paths if isinstance(paths, list) else None


CASES = [
    ("both listed", "on:\n  push:\n    paths: [app/**, locales/**]\n", "push", True),
    ("app missing", "on:\n  push:\n    paths: [locales/**]\n", "push", False),
    ("locales missing", "on:\n  push:\n    paths: [app/**]\n", "push", False),
    ("no paths key", "on:\n  push:\n    branches: [dev]\n", "push", False),
    ("event absent", "on:\n  workflow_call:\n", "push", False),
    ("not a mapping", "- a\n- b\n", "push", False),
    ("on is a string", "on: push\n", "push", False),
    ("paths not a list", "on:\n  push:\n    paths: app/**\n", "push", False),
]


@pytest.mark.parametrize(("label", "text", "event", "expected"), CASES, ids=[c[0] for c in CASES])
def test_trigger_paths_parser(label: str, text: str, event: str, expected: bool) -> None:
    paths = trigger_paths(text, event)
    assert (paths is not None and all(p in paths for p in REQUIRED)) is expected


@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_ci_infra_runs_on_app_and_locales(event: str) -> None:
    paths = trigger_paths(WORKFLOW.read_text(encoding="utf-8"), event)
    assert paths is not None, f"ci-infra.yml has no {event} paths"
    for required in REQUIRED:
        assert required in paths, f"{event} paths miss {required}"
