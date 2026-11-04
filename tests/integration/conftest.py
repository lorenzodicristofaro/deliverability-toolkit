from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests.integration.stack import Stack


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/integration" in item.nodeid.replace("\\", "/"):
            item.add_marker(pytest.mark.integration)


@pytest.fixture(scope="session")
def stack() -> Iterator[Stack]:
    s = Stack()
    try:
        s.up()
        yield s
    finally:
        s.down(volumes=True)
