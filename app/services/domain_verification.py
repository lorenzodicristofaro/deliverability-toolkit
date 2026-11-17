"""Domain ownership verification by DNS TXT (M7-21a, SPEC section 3).

Scheme (a project choice, not a vendor standard): the owner publishes a TXT record at
`_dt-verify.<domain>` whose value is exactly `dt-verify=<token>`.

- Start (`start`): `domain.verify` on the domain (owner/admin, deniable per user). Issues a token
  from `secrets` (TOKEN_BYTES random bytes, url-safe text) and stores only its SHA-256 hex and an
  expiry (`DOMAIN_VERIFY_TOKEN_TTL_HOURS`), replacing any previous token, so a re-issue
  invalidates the old one. The token is returned once, to be shown on the start response only;
  it is never stored, logged or put in a URL. The status is unchanged (a verified domain stays
  verified while a new challenge is pending).
- Verify now (`verify`): `domain.verify` again. With no pending token the outcome is
  `not_started` (or `verified` for an already verified domain), with an expired one `expired`
  (the token is kept; starting again replaces it); no DNS query in either case. Otherwise one TXT
  lookup at `_dt-verify.<domain>` through the resolver path of the checks
  (`app.checks.dnsutil.fetch_txt`: the character-strings of each record joined with no
  separator, records never merged). Each record that starts with `dt-verify=` has the rest
  hashed and compared with the stored hash with `hmac.compare_digest`; every record is compared.
  Outcomes:
  - a matching record: `verified` (status verified, `verified_at`, method `dns_txt`, token
    cleared), written by one conditional UPDATE that holds only while the domain still has the
    name and token that were checked (a rename or re-issue during the lookup wins: `not_found`);
  - an answer with no matching record, NXDOMAIN or NODATA: `not_found`, nothing changes;
  - any lookup that did not complete (timeout, SERVFAIL, REFUSED, truncated, malformed, network
    error, blocked, error) or a name too long to query: `error`, nothing changes, never
    verified. The DNS state is returned so the user is told why.
- Status (`status`): `domain.read` (whoever sees the domain sees whether it is verified; the
  token hash is never exposed).

Permissions are decided with `can()` before any repository write or DNS query; a domain that is
missing, foreign, malformed or not visible is `NotFound` (404), a visible one without
`domain.verify` is `Forbidden` (403), like `app.services.domains`. The database transaction is
ended before the DNS lookup (`prepare_verify` / `finish_verify`), so no connection is held during
it. Nothing about the token or the TXT values is logged.

Re-verification of verified domains is not done here (follow-up).

TODO(M10): write audit log entries for verification started / domain verified.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from sqlalchemy.orm import Session

from app.checks.dnsutil import TxtFetch, fetch_txt
from app.core.domain_names import InvalidDomainName
from app.core.permissions import Action, DomainResource, Principal, can
from app.core.tenancy import TenantContext
from app.dns.types import Resolver, ResultState
from app.repositories import repo_for
from app.repositories.domain import DomainRecord
from app.services.clock import Clock
from app.services.domains import Forbidden, NotFound

RECORD_LABEL: Final = "_dt-verify"
VALUE_PREFIX: Final = "dt-verify="
RECORD_TYPE: Final = "TXT"
TOKEN_BYTES: Final = 32  # 256 bits from `secrets`; the ticket asks for at least 128
METHOD_DNS_TXT: Final = "dns_txt"


class VerifyOutcome(StrEnum):
    verified = "verified"
    not_found = "not_found"
    expired = "expired"
    not_started = "not_started"
    error = "error"


def record_name(domain: str) -> str:
    return f"{RECORD_LABEL}.{domain}"


def hash_token(token: str) -> str:
    """SHA-256 hex of the token text. TXT text is latin-1 decoded and may hold anything; an
    unencodable character is replaced, which can never produce a token (url-safe alphabet)."""
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def matches(records: Sequence[str], token_hash: str) -> bool:
    """True if one TXT record (strings already joined) is exactly `dt-verify=<token>` for the
    token whose hash is `token_hash`. Every record is compared, in constant time per record."""
    found = False
    for value in records:
        if not value.startswith(VALUE_PREFIX):
            continue
        candidate = hash_token(value[len(VALUE_PREFIX) :])
        found = hmac.compare_digest(candidate, token_hash) or found
    return found


@dataclass(frozen=True, slots=True)
class VerificationState:
    """What the UI and API show. `pending`: a token was issued and has not expired."""

    domain_id: int
    status: str
    method: str | None
    verified_at: datetime | None
    token_expires_at: datetime | None
    record_name: str
    pending: bool

    @property
    def verified(self) -> bool:
        return self.status == "verified"

    @classmethod
    def of(cls, record: DomainRecord, now: datetime) -> VerificationState:
        expires = record.token_expires_at
        return cls(
            domain_id=record.id,
            status=record.verification_status,
            method=record.verification_method,
            verified_at=record.verified_at,
            token_expires_at=expires,
            record_name=record_name(record.name),
            pending=expires is not None and now < expires,
        )


@dataclass(frozen=True, slots=True)
class StartResult:
    """The record to publish. `record_value` holds the token: show it once, never log it."""

    state: VerificationState
    record_type: str
    record_name: str
    record_value: str

    def __repr__(self) -> str:  # never the token
        return f"StartResult(domain_id={self.state.domain_id}, record_name={self.record_name!r})"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    outcome: VerifyOutcome
    state: VerificationState
    dns_state: str | None = None  # the lookup state, for `error` and `not_found`


@dataclass(frozen=True, slots=True)
class VerifyPlan:
    """What the DNS step needs, read before the transaction ends. `token_hash` stays internal."""

    domain_id: int
    name: str
    token_hash: str

    def __repr__(self) -> str:
        return f"VerifyPlan(domain_id={self.domain_id})"


class DomainVerificationService:
    """One request's verification operations: `ctx` scopes the data, `principal` the rights."""

    def __init__(
        self,
        db: Session,
        ctx: TenantContext,
        principal: Principal,
        clock: Clock,
        token_ttl: timedelta,
    ) -> None:
        if token_ttl <= timedelta(0):
            raise ValueError("token_ttl must be positive")
        self._db = db
        self._ctx = ctx
        self._principal = principal
        self._clock = clock
        self._ttl = token_ttl
        self._domains = repo_for(ctx, db).domains

    def _resource(self, domain_id: int) -> DomainResource:
        return DomainResource(self._ctx.tenant_id, domain_id)

    def _visible(self, domain_id: object) -> DomainRecord:
        row = self._domains.get(domain_id)
        if row is None or not can(self._principal, Action.DOMAIN_READ, self._resource(row.id)):
            raise NotFound
        return DomainRecord.from_model(row)

    def _verifiable(self, domain_id: object) -> DomainRecord:
        record = self._visible(domain_id)
        if not can(self._principal, Action.DOMAIN_VERIFY, self._resource(record.id)):
            raise Forbidden
        return record

    def check_verify(self, domain_id: object) -> None:
        """Permission pre-check for routers (404 / 403), touching nothing."""
        self._verifiable(domain_id)

    def can_verify(self, domain_id: int) -> bool:
        return can(self._principal, Action.DOMAIN_VERIFY, self._resource(domain_id))

    def status(self, domain_id: object) -> VerificationState:
        return VerificationState.of(self._visible(domain_id), self._clock.now())

    def start(self, domain_id: object) -> StartResult:
        record = self._verifiable(domain_id)
        token = new_token()
        now = self._clock.now()
        row = self._domains.set_pending_token(record.id, hash_token(token), now + self._ttl)
        if row is None:  # deleted concurrently
            self._db.rollback()
            raise NotFound
        updated = DomainRecord.from_model(row)
        self._db.commit()
        return StartResult(
            state=VerificationState.of(updated, now),
            record_type=RECORD_TYPE,
            record_name=record_name(updated.name),
            record_value=VALUE_PREFIX + token,
        )

    def prepare_verify(self, domain_id: object) -> VerifyPlan | VerifyResult:
        """Authorize and read what the lookup needs; a result if no lookup is needed. Ends the
        transaction either way."""
        try:
            record = self._verifiable(domain_id)
            now = self._clock.now()
            state = VerificationState.of(record, now)
            token_hash = self._domains.pending_token_hash(record.id)
        finally:
            self._db.rollback()
        if token_hash is None:
            outcome = VerifyOutcome.verified if record.verified else VerifyOutcome.not_started
            return VerifyResult(outcome, state)
        if record.token_expires_at is None or now >= record.token_expires_at:
            return VerifyResult(VerifyOutcome.expired, state)
        return VerifyPlan(record.id, record.name, token_hash)

    def finish_verify(self, plan: VerifyPlan, fetched: TxtFetch | None) -> VerifyResult:
        """Record the outcome of the lookup (`None`: the name could not be queried)."""
        dns_state = "invalid_name" if fetched is None else str(fetched.state)
        if fetched is None or not fetched.evaluated:
            return VerifyResult(VerifyOutcome.error, self.status(plan.domain_id), dns_state)
        if fetched.state is ResultState.ok and matches(fetched.records, plan.token_hash):
            done = self._domains.mark_verified(
                plan.domain_id,
                name=plan.name,
                token_hash=plan.token_hash,
                method=METHOD_DNS_TXT,
                at=self._clock.now(),
            )
            if done:
                self._db.commit()
                return VerifyResult(VerifyOutcome.verified, self.status(plan.domain_id), dns_state)
            self._db.rollback()
        return VerifyResult(VerifyOutcome.not_found, self.status(plan.domain_id), dns_state)


async def lookup(resolver: Resolver, name: str) -> TxtFetch | None:
    """The TXT records at `_dt-verify.<name>`; None if that name cannot be queried (too long)."""
    try:
        return await fetch_txt(resolver, record_name(name))
    except InvalidDomainName:
        return None


async def verify(
    service: DomainVerificationService, resolver: Resolver, domain_id: object
) -> VerifyResult:
    """`prepare_verify`, the lookup with no transaction open, then `finish_verify`. Database work
    runs in worker threads so the event loop is never blocked."""
    planned = await asyncio.to_thread(service.prepare_verify, domain_id)
    if isinstance(planned, VerifyResult):
        return planned
    fetched = await lookup(resolver, planned.name)
    return await asyncio.to_thread(service.finish_verify, planned, fetched)
