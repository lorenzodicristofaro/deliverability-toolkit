"""Self-tests of the file-based CI sharding (M7-00b, tests/support/sharding.py). No network."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.support.sharding import (
    DEFAULT_WEIGHT,
    MAX_SHARDS,
    WEIGHTS_FILE,
    ShardError,
    assign,
    discover_test_files,
    is_test_file,
    load_weights,
    parse_shard,
    shard_of_files,
    weights_from_durations,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1/1", (1, 1)), ("1/4", (1, 4)), ("4/4", (4, 4)), (" 2/3 ", (2, 3)), ("64/64", (64, 64))],
)
def test_parse_shard_valid(value: str, expected: tuple[int, int]) -> None:
    assert parse_shard(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "1",
        "/4",
        "1/",
        "0/4",
        "5/4",
        "1/0",
        "-1/4",
        "1/-4",
        "a/b",
        "1.0/4",
        "1/4/4",
        "01/4",
        "1 / 4",
        "١/٤",  # non-ASCII digits
        f"1/{MAX_SHARDS + 1}",
        None,
        4,
    ],
)
def test_parse_shard_rejects_malformed(value: Any) -> None:
    with pytest.raises(ShardError):
        parse_shard(value)


WEIGHTS = {"a.py": 10.0, "b.py": 7.0, "c.py": 5.0, "d.py": 4.0, "e.py": 0.0, "f.py": 3.0}


@pytest.mark.parametrize("total", [1, 2, 3, 4, 6, 9])
def test_assign_is_a_partition(total: int) -> None:
    shards = assign(WEIGHTS, total)
    assert set(shards) == set(WEIGHTS)
    assert set(shards.values()) <= set(range(1, total + 1))
    # Deterministic, whatever order the weights come in.
    assert assign(dict(reversed(list(WEIGHTS.items()))), total) == shards


def test_assign_balances_by_weight() -> None:
    # Heaviest first to the least loaded shard: {a}, {b, f}, {c, d, e}.
    assert assign(WEIGHTS, 3) == {"a.py": 1, "b.py": 2, "c.py": 3, "d.py": 3, "f.py": 2, "e.py": 3}


@pytest.mark.parametrize("total", [0, -1])
def test_assign_rejects_no_shards(total: int) -> None:
    with pytest.raises(ShardError):
        assign(WEIGHTS, total)


def test_unknown_files_get_the_default_weight() -> None:
    shards = shard_of_files(["new.py", "x.py"], {"x.py": DEFAULT_WEIGHT * 10}, 2)
    assert shards == {"x.py": 1, "new.py": 2}


def test_load_weights_per_backend(tmp_path: Path) -> None:
    path = tmp_path / "w.json"
    path.write_text(json.dumps({"sqlite": {"a": 1.0, "b": 2.0}, "postgresql": {"b": 3.0}}))
    assert load_weights("sqlite", path) == {"a": 1.0, "b": 2.0}
    # A file measured only on SQLite runs nothing on PostgreSQL: weight 0, not the default.
    assert load_weights("postgresql", path) == {"a": 0.0, "b": 3.0}
    assert load_weights(None, path) == {"a": 1.0, "b": 5.0}


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("test_a.py", True),
        ("a_test.py", True),
        ("test_.py", True),
        ("conftest.py", False),
        ("sharding.py", False),
        ("test_a.pyc", False),
        ("test_a.txt", False),
        ("a_test.pyx", False),
        ("atest.py", False),
        ("Test_a.py", False),
        ("", False),
    ],
)
def test_is_test_file_matches_pytest_defaults(name: str, expected: bool) -> None:
    assert is_test_file(name) is expected


def test_both_test_file_patterns_land_in_exactly_one_shard(tmp_path: Path) -> None:
    for rel in ("tests/test_a.py", "tests/sub/b_test.py", "tests/sub/helper.py", "tests/c.txt"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("")
    (tmp_path / "tests/test_dir.py").mkdir()  # a directory, not a module
    files = discover_test_files(tmp_path)
    assert files == ["tests/sub/b_test.py", "tests/test_a.py"]
    for total in (1, 2, 3):
        shards = shard_of_files(files, {}, total)
        assert sorted(shards) == files


def test_weights_from_durations_ignores_other_lines() -> None:
    lines = [
        "0.50s call     tests/x/test_a.py::test_one[sqlite]",
        "0.25s setup    tests/x/test_a.py::test_one[sqlite]",
        "0.01s teardown tests/x/test_b.py::test_two",
        "1.00s call     tests/x/test_b.py::Test::test_three",
        "(12 durations < 0.005s hidden.)",
        "1.00s rerun    tests/x/test_c.py::test_four",
        "garbage",
        "",
        "abc call tests/x/test_c.py::test_five",
        "=== 3 passed in 1.00s ===",
    ]
    assert weights_from_durations(lines) == {"tests/x/test_a.py": 0.75, "tests/x/test_b.py": 1.01}


def test_weights_file_is_valid_and_names_existing_files() -> None:
    data = json.loads(WEIGHTS_FILE.read_text(encoding="utf-8"))
    assert set(data) == {"sqlite", "postgresql"}
    files = set(discover_test_files(ROOT))
    for backend, weights in data.items():
        assert weights, backend
        assert all(isinstance(v, float | int) and v >= 0 for v in weights.values()), backend
        # Stale entries are harmless for coverage but mean the weights need a refresh.
        assert set(weights) <= files, (backend, sorted(set(weights) - files))


def test_every_test_file_lands_in_exactly_one_shard() -> None:
    files = discover_test_files(ROOT)
    assert "tests/support/test_sharding.py" in files
    for backend in ("sqlite", "postgresql", None):
        shards = shard_of_files(files, load_weights(backend), 4)
        assert sorted(shards) == files
        assert set(shards.values()) == {1, 2, 3, 4}


@pytest.mark.parametrize("job", ["test-sqlite", "test-postgres"])
def test_ci_shards_match_the_shard_option(job: str) -> None:
    """Every shard index 1..N is a matrix entry, the command passes K/N with the same N, and the
    required check gathers every shard."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    shard_job = jobs[f"{job}-shard"]
    shards = shard_job["strategy"]["matrix"]["shard"]
    assert shard_job["strategy"]["fail-fast"] is False
    assert shards == list(range(1, len(shards) + 1))
    command = " ".join(step.get("run", "") for step in shard_job["steps"])
    assert f"--shard=${{{{ matrix.shard }}}}/{len(shards)}" in command
    assert '-m "$PYTEST_MARKERS"' in command
    gather = jobs[job]
    assert gather["needs"] == f"{job}-shard"
    assert gather["if"] == "always()"
    assert "timeout-minutes" in gather and "timeout-minutes" in shard_job
