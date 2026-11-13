"""Static check: every image reference in the Dockerfiles is pinned by digest (INFRA-04)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILES = [ROOT / "Dockerfile", ROOT / "docker" / "unbound" / "Dockerfile"]
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def image_refs(text: str) -> list[str]:
    """Image references of `FROM` and `COPY --from=<image>` lines (stage names excluded)."""
    stages: set[str] = set()
    refs: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        parts = line.split()
        if not parts:
            continue
        word = parts[0].upper()
        if word == "FROM":
            args = [p for p in parts[1:] if not p.startswith("--")]
            if args and args[0].lower() != "scratch" and args[0] not in stages:
                refs.append(args[0])
            if len(args) >= 3 and args[1].lower() == "as":
                stages.add(args[2])
        elif word == "COPY":
            for p in parts[1:]:
                if p.lower().startswith("--from="):
                    value = p.split("=", 1)[1]
                    if value and not value.isdigit() and value not in stages:
                        refs.append(value)
    return refs


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("FROM a:1@sha256:" + "0" * 64, ["a:1@sha256:" + "0" * 64]),
        ("FROM --platform=linux/amd64 a:1 AS b\nFROM b", ["a:1"]),
        ("COPY --from=x:2 /a /b", ["x:2"]),
        ("FROM a AS builder\nCOPY --from=builder /a /b", ["a"]),
        ("COPY --from=0 /a /b", []),
        ("FROM scratch", []),
        ("from lower:1", ["lower:1"]),
        ("# FROM commented:1", []),
        ("RUN echo FROM x", []),
        ("", []),
        ("FROM", []),
        ("COPY --from= /a /b", []),
    ],
)
def test_image_refs_parser(text: str, expected: list[str]) -> None:
    assert image_refs(text) == expected


@pytest.mark.parametrize(
    ("ref", "pinned"),
    [
        ("a:1@sha256:" + "a" * 64, True),
        ("a@sha256:" + "a" * 64, True),
        ("a:1", False),
        ("a:1@sha256:abc", False),
        ("a:1@sha256:" + "G" * 64, False),
        ("a:1@sha1:" + "a" * 40, False),
        ("a:1@sha256:" + "a" * 65, False),
        ("", False),
    ],
)
def test_digest_pattern(ref: str, pinned: bool) -> None:
    assert bool(DIGEST.search(ref)) is pinned


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_image_reference_is_digest_pinned(path: Path) -> None:
    refs = image_refs(path.read_text(encoding="utf-8"))
    assert refs, f"no image references found in {path}"
    unpinned = [r for r in refs if not DIGEST.search(r)]
    assert not unpinned, f"{path.name}: not pinned by @sha256: {unpinned}"


def test_app_dockerfile_syntax_frontend_is_pinned() -> None:
    first = (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()[0]
    assert first.startswith("# syntax=")
    assert DIGEST.search(first), first
