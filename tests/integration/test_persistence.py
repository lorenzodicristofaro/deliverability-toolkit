"""root.key persistence (A2): the named volume survives down/up without -v."""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from tests.integration.stack import Stack, run

pytestmark = pytest.mark.integration


@pytest.fixture
def own_stack() -> Iterator[Stack]:
    s = Stack()
    try:
        yield s
    finally:
        s.down(volumes=True)


def _state(s: Stack) -> list[tuple[str, str]]:
    """Per-key RFC 5011 state written by unbound (`;;lastchange=` = when the key became VALID)."""
    text = s.compose("exec", "-T", "unbound", "cat", "/var/lib/unbound/root.key").stdout
    return sorted(re.findall(r"id = (\d+) \(ksk\).*?;;lastchange=(\d+)", text))


def test_root_key_survives_down_up(own_stack: Stack) -> None:
    s = own_stack
    s.up()
    before = _state(s)
    assert {k for k, _ in before} >= {"38696"}, before  # seeded from the image, unbound-written
    s.down(volumes=False)  # removes container and networks, keeps the volume
    assert s.volume in run("docker", "volume", "ls", "-q").stdout.split()
    s.up()  # new container; a re-seed from the image would reset lastchange to "now"
    assert _state(s) == before
