"""INFRA-02: no workflow may grant itself write rights (R1-33). No network."""

from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
# (file name, job id) -> permission names that may be "write" there.
ALLOWED_WRITE = {("codeql.yml", "job"): {"security-events"}}


def _block_violations(block: object, where: str, allowed: set[str]) -> list[str]:
    if block is None:
        return []
    if isinstance(block, str):
        return [f"{where}: permissions '{block}'"] if "write" in block else []
    if not isinstance(block, dict):
        return [f"{where}: unreadable permissions block"]
    return [
        f"{where}: {name}: {value}"
        for name, value in block.items()
        if "write" in str(value) and name not in allowed
    ]


def check_permissions(file_name: str, text: str) -> list[str]:
    """Return the write grants found in a workflow's permissions blocks."""
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        return [f"{file_name}: not a mapping"]
    out = _block_violations(doc.get("permissions"), f"{file_name} workflow", set())
    jobs = doc.get("jobs")
    for job_id, job in (jobs if isinstance(jobs, dict) else {}).items():
        if isinstance(job, dict):
            allowed = ALLOWED_WRITE.get((file_name, "job"), set())
            out += _block_violations(job.get("permissions"), f"{file_name} job {job_id}", allowed)
    return out


CASES = [
    ("wf-level write", "ci.yml", "permissions:\n  contents: write\njobs: {}\n", 1),
    ("job-level write", "ci.yml", "jobs:\n  a:\n    permissions:\n      issues: write\n", 1),
    ("write-all string", "ci.yml", "permissions: write-all\njobs: {}\n", 1),
    ("job write-all string", "ci.yml", "jobs:\n  a:\n    permissions: write-all\n", 1),
    ("read-all", "ci.yml", "permissions: read-all\njobs: {}\n", 0),
    ("empty mapping", "ci.yml", "permissions: {}\njobs: {}\n", 0),
    ("no permissions", "ci.yml", "jobs:\n  a:\n    runs-on: x\n", 0),
    ("read only", "ci.yml", "permissions:\n  contents: read\njobs: {}\n", 0),
    (
        "codeql exception in codeql.yml",
        "codeql.yml",
        "permissions: {}\njobs:\n  a:\n    permissions:\n      security-events: write\n",
        0,
    ),
    (
        "codeql exception elsewhere",
        "ci.yml",
        "jobs:\n  a:\n    permissions:\n      security-events: write\n",
        1,
    ),
    (
        "codeql other write",
        "codeql.yml",
        "jobs:\n  a:\n    permissions:\n      contents: write\n",
        1,
    ),
    (
        "codeql wf-level security-events",
        "codeql.yml",
        "permissions:\n  security-events: write\njobs: {}\n",
        1,
    ),
    ("malformed: list", "ci.yml", "- a\n- b\n", 1),
    ("malformed: scalar permissions", "ci.yml", "permissions: 5\njobs: {}\n", 1),
]


@pytest.mark.parametrize(("label", "name", "text", "count"), CASES, ids=[c[0] for c in CASES])
def test_check_permissions(label: str, name: str, text: str, count: int) -> None:
    assert len(check_permissions(name, text)) == count


def test_real_workflows_grant_no_write() -> None:
    files = sorted(WORKFLOWS.glob("*.yml"))
    assert files, "no workflow files found"
    problems = [p for f in files for p in check_permissions(f.name, f.read_text())]
    assert problems == []
