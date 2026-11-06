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
    return CheckResult(
        check_id="spf",
        target="example.com",
        status="ok",
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
    assert f.evidence == ["v=spf1"]
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
    assert Target(domain="example.com").options == {}
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
