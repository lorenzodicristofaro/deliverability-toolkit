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
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Literal, Protocol, Self, runtime_checkable
from urllib.parse import urlsplit

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


def _freeze(v: Any) -> Any:
    """Recursively turn dicts/lists into hashable, read-only equivalents."""
    if isinstance(v, Mapping):
        return tuple(sorted(((str(k), _freeze(x)) for k, x in v.items()), key=lambda kv: kv[0]))
    if isinstance(v, list | tuple):
        return tuple(_freeze(x) for x in v)
    return v


def _canonical(v: Any) -> Any:
    """Recursively sort dict keys so serialization is deterministic."""
    if isinstance(v, Mapping):
        return {str(k): _canonical(v[k]) for k in sorted(v, key=str)}
    if isinstance(v, list | tuple):
        return [_canonical(x) for x in v]
    return v


def _readonly(v: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(v))


class Target(BaseModel):
    """What a check runs against."""

    model_config = ConfigDict(frozen=True)

    domain: str = Field(min_length=1)
    # Immutable and hashable: sorted (key, value) pairs; a dict is accepted as input.
    options: tuple[tuple[str, Any], ...] = ()

    @field_validator("options", mode="before")
    @classmethod
    def _freeze_options(cls, v: Any) -> Any:
        if isinstance(v, Mapping | list | tuple):
            return _freeze(v)
        return v


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
    params: Mapping[str, Any] = Field(default_factory=dict)
    evidence: tuple[str, ...] = ()
    docs_url: str | None = None

    @field_validator("params")
    @classmethod
    def _params_readonly(cls, v: Mapping[str, Any]) -> Mapping[str, Any]:
        return _readonly(v)

    @field_serializer("params")
    def _ser_params(self, v: Mapping[str, Any]) -> dict[str, Any]:
        return _canonical(v)  # type: ignore[no-any-return]

    @field_validator("docs_url")
    @classmethod
    def _check_docs_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            parts = urlsplit(v)
        except ValueError as e:
            raise ValueError(f"invalid docs_url: {v!r}") from e
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("docs_url must be an http(s) URL")
        return v

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
        evidence=tuple(evidence),
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
    """Immutable result. ``status`` must agree with the findings.

    ``error`` may always be set (could not evaluate); any other status must equal
    ``derive_status(findings, True)``. Use :meth:`build` to derive it.
    """

    model_config = ConfigDict(frozen=True)

    check_id: str
    target: str
    status: Status
    findings: tuple[Finding, ...] = ()
    data: Mapping[str, Any] = Field(default_factory=dict)
    started_at: datetime
    duration_ms: int

    @classmethod
    def build(
        cls,
        *,
        check_id: str,
        target: str,
        findings: Iterable[Finding],
        evaluated: bool,
        started_at: datetime,
        duration_ms: int,
        data: Mapping[str, Any] | None = None,
    ) -> Self:
        fs = tuple(findings)
        return cls(
            check_id=check_id,
            target=target,
            status=derive_status(fs, evaluated),
            findings=fs,
            data=data or {},
            started_at=started_at,
            duration_ms=duration_ms,
        )

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

    @field_validator("findings")
    @classmethod
    def _sort_findings(cls, v: tuple[Finding, ...]) -> tuple[Finding, ...]:
        # sorted() is stable: ties on (severity, code) keep emission order.
        return tuple(sorted(v, key=lambda f: (_SEVERITY_ORDER[f.severity], f.code)))

    @field_validator("data")
    @classmethod
    def _data_readonly(cls, v: Mapping[str, Any]) -> Mapping[str, Any]:
        return _readonly(v)

    @model_validator(mode="after")
    def _status_consistent(self) -> Self:
        if self.status != "error" and self.status != derive_status(self.findings, True):
            raise ValueError(
                f"status {self.status!r} inconsistent with findings "
                f"(expected {derive_status(self.findings, True)!r})"
            )
        return self

    @field_serializer("data")
    def _ser_data(self, v: Mapping[str, Any]) -> dict[str, Any]:
        return _canonical(v)  # type: ignore[no-any-return]

    @field_serializer("started_at")
    def _ser_started_at(self, v: datetime) -> str:
        return v.astimezone(UTC).isoformat().replace("+00:00", "Z")


@runtime_checkable
class Check(Protocol):
    id: str

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult: ...
