"""R1-13 (AUTH-08): no synchronous DB/service call runs on the event loop in an `async def` handler.

An `async def` handler that calls the synchronous SQLAlchemy session (directly or through a
service) stalls every request and SSE stream of the process while a statement waits (PostgreSQL
latency, or SQLite waiting for a write lock). Such work must go through
`await run_in_threadpool(func, *args)`, where the function is passed as a reference, not called.

This is a static (AST) check: for every `async def` in the listed web modules, a call to a known
service/session method or to a known DB-touching helper is a violation. Nested `def` helpers are
not inspected (they are the sync part, meant for `run_in_threadpool`); nested `async def` are
checked on their own. No network, no database.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "app" / "web"
MODULES = (
    "domain_esps",
    "authentication",
    "custom_checks",
    "rules",
    "dkim_selectors",
    "dnsbl_lists",
)

# Methods of the admin/domain services and of the Session that touch the database.
SYNC_METHODS = frozenset(
    {
        "list_for_domain", "catalogue", "check_write", "check_manage", "check_read", "check_test",
        "assign", "remove", "create", "update", "delete", "get_rule", "get_check", "get_selector",
        "list_rules", "list_checks", "list_selectors", "prepare_test", "commit", "rollback",
        "execute", "scalars", "scalar", "flush",
    }
)  # fmt: skip
# `get` is also a dict method: only the domain service's `.service.get(...)` counts.
SERVICE_GET = "service"
# Module-level helpers that query (directly or via a service) and render.
SYNC_FUNCS = frozenset(
    {"_form_page", "_list_page", "_all_records", "_test_domains", "resolve_esp_run"}
)
# Explicit allow-list of (module, enclosing async function, called name). Keep empty unless a call
# is provably free of I/O; comment each entry with the reason.
ALLOWED: frozenset[tuple[str, str, str]] = frozenset()


def _own_calls(fn: ast.AsyncFunctionDef) -> list[ast.Call]:
    """Calls in `fn` itself: not inside nested functions (sync helpers or other coroutines)."""
    found: list[ast.Call] = []
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        if isinstance(node, ast.Call):
            found.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return found


def _called_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id if func.id in SYNC_FUNCS else None
    if isinstance(func, ast.Attribute):
        if func.attr in SYNC_METHODS:
            return func.attr
        if func.attr == "get" and ast.unparse(func.value).endswith(SERVICE_GET):
            return "service.get"
    return None


def violations(source: str, module: str) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for call in _own_calls(node):
            name = _called_name(call)
            if name is not None and (module, node.name, name) not in ALLOWED:
                found.append(f"{module}.{node.name}:{call.lineno} calls {name} on the event loop")
    return sorted(found)


@pytest.mark.parametrize("module", MODULES)
def test_async_handlers_do_not_call_sync_db_work(module: str) -> None:
    source = (ROOT / f"{module}.py").read_text(encoding="utf-8")
    assert violations(source, module) == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("async def h(service):\n    service.create(1)\n", 1),
        ("async def h(db):\n    db.rollback()\n", 1),
        ("async def h(web):\n    web.service.get(1)\n", 1),
        ("async def h():\n    _list_page()\n", 1),
        ("async def h(service):\n    await run_in_threadpool(service.create, 1)\n", 0),
        ("async def h(service):\n    def s():\n        service.create(1)\n    await go(s)\n", 0),
        ("async def h(d):\n    d.get('x')\n", 0),
        ("def h(service):\n    service.create(1)\n", 0),
    ],
)
def test_guard_detects_synthetic_violations(source: str, expected: int) -> None:
    assert len(violations(source, "m")) == expected
