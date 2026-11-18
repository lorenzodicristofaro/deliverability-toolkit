"""File-based test sharding for the CI matrix (M7-00b, docs/TESTING.md).

`--shard=K/N` keeps only the test files assigned to shard K of N; the others are not even
collected. The assignment is deterministic: every test file under tests/ gets its measured cost
from `shard_weights.json` (seconds per backend; unknown files get `DEFAULT_WEIGHT`), and the
files are dealt out heaviest first to the shard with the lowest total so far (ties: path order,
then the lowest shard). A whole file always lands in one shard, so module-scoped fixtures are
never duplicated, and the shards of one N are disjoint and together cover every file.

Regenerate the weights after large test changes (they only affect balance, never coverage):
run each backend with `--durations=0 --durations-min=0` and pass the outputs to
`uv run python -m tests.support.sharding sqlite.log postgresql.log`."""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

WEIGHTS_FILE = Path(__file__).with_name("shard_weights.json")
DEFAULT_WEIGHT = 1.0  # seconds; a new file counts as a small one until the weights are refreshed
MIN_WEIGHT = 0.05  # every file counts, so empty-looking files still spread out
MAX_SHARDS = 64
_SHARD = re.compile(r"([1-9][0-9]*)/([1-9][0-9]*)")
_DURATION = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)s (?:setup|call|teardown)\s+([^:\s]+\.py)::")


class ShardError(ValueError):
    """A malformed `--shard` value; the message is shown as a usage error."""


def parse_shard(value: str) -> tuple[int, int]:
    """`"K/N"` with 1 <= K <= N <= MAX_SHARDS, as (K, N)."""
    match = _SHARD.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        raise ShardError("--shard must be K/N, for example 2/4")
    index, total = int(match.group(1)), int(match.group(2))
    if total > MAX_SHARDS:
        raise ShardError(f"--shard: at most {MAX_SHARDS} shards")
    if index > total:
        raise ShardError("--shard: K must be between 1 and N")
    return index, total


def assign(weights: Mapping[str, float], total: int) -> dict[str, int]:
    """Map every file to a shard in 1..total (longest processing time first, deterministic)."""
    if total < 1:
        raise ShardError("--shard: N must be at least 1")
    loads = [0.0] * total
    result: dict[str, int] = {}
    for path in sorted(weights, key=lambda p: (-max(weights[p], MIN_WEIGHT), p)):
        shard = min(range(total), key=lambda i: (loads[i], i))
        loads[shard] += max(weights[path], MIN_WEIGHT)
        result[path] = shard + 1
    return result


def load_weights(backend: str | None, path: Path = WEIGHTS_FILE) -> dict[str, float]:
    """Seconds per test file for one backend, or both summed when no backend is selected. A file
    measured only on the other backend runs nothing on this one: weight 0 (MIN_WEIGHT applies)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    merged: dict[str, float] = defaultdict(float)
    for name in ("sqlite", "postgresql"):
        for file, seconds in data[name].items():
            merged[file] += float(seconds) if backend in (None, name) else 0.0
    return dict(merged)


def is_test_file(name: str) -> bool:
    """pytest's default `python_files`: `test_*.py` and `*_test.py`."""
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def discover_test_files(root: Path) -> list[str]:
    """Every test module under root/tests, as a POSIX path relative to root."""
    found = (p for p in (root / "tests").rglob("*.py") if p.is_file() and is_test_file(p.name))
    return sorted(p.relative_to(root).as_posix() for p in found)


def shard_of_files(
    files: Iterable[str], weights: Mapping[str, float], total: int
) -> dict[str, int]:
    """The shard of each file; files with no measured weight get DEFAULT_WEIGHT."""
    return assign({f: weights.get(f, DEFAULT_WEIGHT) for f in files}, total)


def weights_from_durations(lines: Iterable[str]) -> dict[str, float]:
    """Sum the `--durations=0 --durations-min=0` report per file (setup + call + teardown)."""
    totals: dict[str, float] = defaultdict(float)
    for line in lines:
        match = _DURATION.match(line)
        if match:
            totals[match.group(2)] += float(match.group(1))
    return {file: round(seconds, 2) for file, seconds in sorted(totals.items())}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m tests.support.sharding SQLITE_LOG POSTGRESQL_LOG", file=sys.stderr)
        return 2
    data = {
        backend: weights_from_durations(Path(log).read_text(encoding="utf-8").splitlines())
        for backend, log in zip(("sqlite", "postgresql"), argv, strict=True)
    }
    WEIGHTS_FILE.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
