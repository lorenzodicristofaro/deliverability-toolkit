"""Check registry tests. No network."""

from __future__ import annotations

import pytest

from app.checks.models import CheckContext, CheckResult, Target
from app.checks.registry import CheckRegistry, DuplicateCheckError, load_builtin_checks


class _Stub:
    def __init__(self, id: str) -> None:
        self.id = id

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        raise AssertionError("not run")


def test_register_get_all_ids_sorted() -> None:
    reg = CheckRegistry()
    b, a = _Stub("b"), _Stub("a")
    reg.register(b)
    reg.register(a)
    assert reg.get("a") is a
    assert reg.all_ids() == ["a", "b"]


def test_empty_registry() -> None:
    assert CheckRegistry().all_ids() == []


def test_duplicate_id_raises() -> None:
    reg = CheckRegistry()
    reg.register(_Stub("spf"))
    with pytest.raises(DuplicateCheckError):
        reg.register(_Stub("spf"))
    assert reg.all_ids() == ["spf"]


@pytest.mark.parametrize("bad", ["", "missing", "SPF", None])
def test_get_unknown_raises_keyerror(bad: object) -> None:
    reg = CheckRegistry()
    reg.register(_Stub("spf"))
    with pytest.raises(KeyError):
        reg.get(bad)  # type: ignore[arg-type]


def test_load_builtin_checks_is_explicit_and_independent() -> None:
    first, second = load_builtin_checks(), load_builtin_checks()
    assert first is not second
    first.register(_Stub("x"))
    assert "x" not in second.all_ids()
    own = CheckRegistry()
    assert load_builtin_checks(own) is own
