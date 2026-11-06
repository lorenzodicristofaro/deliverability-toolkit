from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.checks import CheckResult, Finding, Target, derive_status, finding
from app.checks.models import Check, CheckContext

T0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class _StubResolver:
    identity = "stub"

    async def resolve(self, question: Any) -> Any:
        raise AssertionError("no network in unit tests")


def _res(findings: list[Finding], **kw: Any) -> CheckResult:
    return CheckResult.build(
        check_id="spf",
        target="example.com",
        evaluated=True,
        findings=findings,
        started_at=kw.pop("started_at", T0),
        duration_ms=kw.pop("duration_ms", 5),
        **kw,
    )


@pytest.mark.parametrize(
    ("sevs", "evaluated", "expected"),
    [
        ([], True, "ok"),
        ([], False, "error"),
        (["critical"], False, "error"),
        (["critical"], True, "fail"),
        (["high", "info"], True, "fail"),
        (["medium"], True, "warn"),
        (["low", "info"], True, "warn"),
        (["info"], True, "info"),
        (["info", "info"], True, "info"),
    ],
)
def test_derive_status(sevs: list[Any], evaluated: bool, expected: str) -> None:
    fs = [finding("SOME_CODE", s) for s in sevs]
    assert derive_status(fs, evaluated) == expected


@pytest.mark.parametrize(
    "code",
    ["", "A", "lower", "Mixed_Case", "1ABC", "_ABC", "AB-C", "AB C", "AB\n", "ÀBC"],
)
def test_invalid_codes(code: str) -> None:
    with pytest.raises(ValidationError):
        finding(code, "low")


@pytest.mark.parametrize("code", ["AB", "SPF_TOO_MANY_LOOKUPS", "A1_2"])
def test_valid_codes(code: str) -> None:
    assert finding(code, "low").code == code


def test_finding_keys() -> None:
    f = finding("SPF_X", "high", {"n": 11}, ["v=spf1"], docs_url="https://x.example")
    assert f.title_key == "finding.SPF_X.title"
    assert f.detail_key == "finding.SPF_X.detail"
    assert f.remediation_key == "finding.SPF_X.remediation"
    assert f.params == {"n": 11}
    assert f.evidence == ("v=spf1",)
    assert finding("SPF_X", "high", remediation=False).remediation_key is None


def test_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        finding("SPF_X", "bogus")  # type: ignore[arg-type]


def test_ordering_is_by_severity_and_stable() -> None:
    fs = [
        finding("A_INFO", "info"),
        finding("B_LOW", "low"),
        finding("C_CRIT", "critical"),
        finding("D_LOW", "low"),
        finding("E_HIGH", "high"),
        finding("F_CRIT", "critical"),
        finding("G_MED", "medium"),
    ]
    got = [f.code for f in _res(fs).findings]
    assert got == ["C_CRIT", "F_CRIT", "E_HIGH", "G_MED", "B_LOW", "D_LOW", "A_INFO"]


def test_json_round_trip_and_determinism() -> None:
    fs = [finding("A_INFO", "info"), finding("B_CRIT", "critical", {"k": 1})]
    r = _res(fs, started_at=datetime(2026, 1, 2, 5, 4, 5, tzinfo=timezone(timedelta(hours=2))))
    j = r.model_dump_json()
    assert '"started_at":"2026-01-02T03:04:05Z"' in j
    assert '"duration_ms":5' in j
    assert j.index("B_CRIT") < j.index("A_INFO")
    again = CheckResult.model_validate_json(j)
    assert again == r
    assert again.model_dump_json() == j


@pytest.mark.parametrize(
    "kw",
    [
        {"started_at": datetime(2026, 1, 1)},  # naive
        {"duration_ms": -1},
        {"duration_ms": "abc"},
        {"status": "great"},
    ],
)
def test_malformed_result(kw: dict[str, Any]) -> None:
    base: dict[str, Any] = {
        "check_id": "spf",
        "target": "example.com",
        "status": "ok",
        "started_at": T0,
        "duration_ms": 1,
    }
    base.update(kw)
    with pytest.raises(ValidationError):
        CheckResult(**base)


def test_target_and_context() -> None:
    assert Target(domain="example.com").options == ()
    with pytest.raises(ValidationError):
        Target(domain="")
    ctx = CheckContext(resolver=_StubResolver(), tenant_id="t", domain_id="d")  # type: ignore[arg-type]
    assert ctx.clock().tzinfo is not None
    assert "db" not in CheckContext.model_fields
    with pytest.raises(ValidationError):
        CheckContext(resolver=object())  # type: ignore[arg-type]


def test_check_protocol() -> None:
    class Dummy:
        id = "dummy"

        async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
            return _res([])

    assert isinstance(Dummy(), Check)


def test_target_immutable_hashable() -> None:
    t = Target(domain="example.com", options={"b": [1, 2], "a": {"x": 1}})
    assert hash(t) == hash(Target(domain="example.com", options={"a": {"x": 1}, "b": [1, 2]}))
    assert t == Target(domain="example.com", options={"a": {"x": 1}, "b": [1, 2]})
    with pytest.raises(ValidationError):
        t.domain = "other.com"  # type: ignore[misc]
    with pytest.raises(TypeError):
        t.options[0] = ("z", 1)  # type: ignore[index]
    assert len({t, Target(domain="example.com", options={"a": {"x": 1}, "b": [1, 2]})}) == 1


@pytest.mark.parametrize(
    ("status", "sevs", "ok"),
    [
        ("ok", ["critical"], False),
        ("ok", ["info"], False),
        ("fail", [], False),
        ("warn", ["high"], False),
        ("fail", ["critical"], True),
        ("ok", [], True),
        ("error", [], True),
        ("error", ["critical"], True),
    ],
)
def test_status_consistency(status: str, sevs: list[Any], ok: bool) -> None:
    kw: dict[str, Any] = {
        "check_id": "spf",
        "target": "e.com",
        "status": status,
        "findings": [finding("X_CODE", s) for s in sevs],
        "started_at": T0,
        "duration_ms": 1,
    }
    if ok:
        CheckResult(**kw)
    else:
        with pytest.raises(ValidationError):
            CheckResult(**kw)


def test_build_not_evaluated_is_error() -> None:
    r = CheckResult.build(
        check_id="spf",
        target="e.com",
        findings=[],
        evaluated=False,
        started_at=T0,
        duration_ms=1,
    )
    assert r.status == "error"


def test_result_frozen_and_readonly() -> None:
    r = _res([finding("A_B", "low", {"k": 1})], data={"a": 1})
    with pytest.raises(ValidationError):
        r.status = "ok"  # type: ignore[misc]
    with pytest.raises(TypeError):
        r.data["x"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        r.findings[0].params["x"] = 1  # type: ignore[index]


def test_json_key_order_canonical() -> None:
    a = _res(
        [finding("A_B", "low", {"b": 1, "a": {"y": 1, "x": 2}})],
        data={"b": 1, "a": [{"d": 1, "c": 2}]},
    )
    b = _res(
        [finding("A_B", "low", {"a": {"x": 2, "y": 1}, "b": 1})],
        data={"a": [{"c": 2, "d": 1}], "b": 1},
    )
    assert a.model_dump_json() == b.model_dump_json()
    assert (
        _res([], data={"b": 1, "a": 2}).model_dump_json()
        == _res([], data={"a": 2, "b": 1}).model_dump_json()
    )


def test_equal_severity_ordered_by_code() -> None:
    fs = [finding("Z_CODE", "low"), finding("A_CODE", "low"), finding("M_CODE", "high")]
    assert [f.code for f in _res(fs).findings] == ["M_CODE", "A_CODE", "Z_CODE"]
    assert _res(fs).model_dump_json() == _res(fs[::-1]).model_dump_json()


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        (None, True),
        ("https://example.com/x", True),
        ("http://example.com", True),
        ("javascript:alert(1)", False),
        ("ftp://example.com", False),
        ("//example.com", False),
        ("https://", False),
        ("", False),
        ("not a url", False),
    ],
)
def test_docs_url(url: str | None, ok: bool) -> None:
    if ok:
        assert finding("A_B", "low", docs_url=url).docs_url == url
    else:
        with pytest.raises(ValidationError):
            finding("A_B", "low", docs_url=url)
