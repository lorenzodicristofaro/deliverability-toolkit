"""Check interface and result models (ARCHITECTURE.md section 3).

Conventions:
- Finding codes are stable public identifiers matching ``^[A-Z][A-Z0-9_]+$``.
- Each check module declares ``CODES: tuple[str, ...]`` listing every finding code it
  can emit. The i18n completeness test (M3-19) reads it and requires the keys
  ``finding.<CODE>.title``, ``finding.<CODE>.detail`` and ``finding.<CODE>.remediation``
  (the latter only when the finding carries a remediation) in en and it.
- Checks build findings only through :func:`finding`; keys are never hand-written.
- ``CheckResult`` JSON (``model_dump_json``) is the single wire format for API/CLI/UI.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, Self, runtime_checkable

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from app.dns.types import Resolver

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["ok", "warn", "fail", "info", "error"]

CODE_RE = re.compile(r"[A-Z][A-Z0-9_]+")
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Target(BaseModel):
    """What a check runs against."""

    model_config = ConfigDict(frozen=True)

    domain: str = Field(min_length=1)
    options: dict[str, Any] = Field(default_factory=dict)


class CheckContext(BaseModel):
    """Runtime dependencies for a check. No DB handle by design."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    resolver: Resolver
    clock: Callable[[], datetime] = _utc_now
    tenant_id: str | None = None
    domain_id: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    severity: Severity
    title_key: str
    detail_key: str
    remediation_key: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    docs_url: str | None = None

    @field_validator("code")
    @classmethod
    def _check_code(cls, v: str) -> str:
        if not CODE_RE.fullmatch(v):
            raise ValueError(f"invalid finding code: {v!r}")
        return v


def finding(
    code: str,
    severity: Severity,
    params: dict[str, Any] | None = None,
    evidence: Iterable[str] = (),
    remediation: bool = True,
    docs_url: str | None = None,
) -> Finding:
    """Build a Finding with i18n keys derived from ``code``."""
    return Finding(
        code=code,
        severity=severity,
        title_key=f"finding.{code}.title",
        detail_key=f"finding.{code}.detail",
        remediation_key=f"finding.{code}.remediation" if remediation else None,
        params=params or {},
        evidence=list(evidence),
        docs_url=docs_url,
    )


def derive_status(findings: Iterable[Finding], evaluated: bool) -> Status:
    if not evaluated:
        return "error"
    severities = {f.severity for f in findings}
    if severities & {"critical", "high"}:
        return "fail"
    if severities & {"medium", "low"}:
        return "warn"
    if severities:
        return "info"
    return "ok"


class CheckResult(BaseModel):
    check_id: str
    target: str
    status: Status
    findings: list[Finding] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime
    duration_ms: int

    @field_validator("started_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("started_at must be timezone-aware")
        return v.astimezone(UTC)

    @field_validator("duration_ms")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("duration_ms must be >= 0")
        return v

    @model_validator(mode="after")
    def _sort_findings(self) -> Self:
        # sorted() is stable: equal severities keep their emission order.
        self.findings = sorted(self.findings, key=lambda f: _SEVERITY_ORDER[f.severity])
        return self

    @field_serializer("started_at")
    def _ser_started_at(self, v: datetime) -> str:
        return v.astimezone(UTC).isoformat().replace("+00:00", "Z")


@runtime_checkable
class Check(Protocol):
    id: str

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult: ...
