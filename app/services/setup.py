"""First-run setup: one-time setup token and creation of the instance admin (M1-17, GM Q4a, Q6).

Setup is required while no user exists and the `instance_setup` singleton is not completed.

Setup token lifecycle:
- `issue_setup_token` makes a fresh random token (256 bits) and stores only its SHA-256 digest
  in the singleton row; the caller logs the token once. DECISION: a new token is issued at every
  process start while setup is pending, which replaces (invalidates) the previous one, so the
  most recent log always holds the valid token. This assumes a single web process, like the
  login throttle: several web workers would each issue their own token and only the last one
  stays valid.
- `verify_setup_token` compares digests with `hmac.compare_digest` (constant time).
- `complete_setup` clears the digest in the same conditional UPDATE that claims setup, and the
  CHECK `ck_instance_setup_token_cleared` keeps it cleared.

Single admin: the claim is `UPDATE instance_setup SET completed_at, token_hash = NULL
WHERE id = 1 AND completed_at IS NULL AND token_hash = :digest`, the FIRST write of the
transaction that creates the admin. The database serialises it, so of concurrent setups exactly
one gets rowcount 1; the others roll back and create nothing (see app.models.instance_setup).
The password is hashed before the transaction starts, so the write lock is held briefly.

Password policy (NIST SP 800-63B-4, section 3.1.1.2, read on 2026-11-05 at
https://pages.nist.gov/800-63-4/sp800-63b.html): a password used as a single-factor authenticator
SHALL be at least 15 characters; verifiers SHOULD permit at least 64 characters; no other
composition rules SHALL be imposed; each Unicode code point counts as one character. Here: 15 to
128 code points (the maximum bounds the argon2 input), no composition rules. The NFC
normalisation that section recommends is NOT applied, because login (app.services.auth) does
not normalise either; changing both together is a follow-up.

Blocklist (the same section requires comparing new passwords against a blocklist): an offline,
minimal check. Refused, case-insensitively and ignoring whitespace: a password equal to or
containing the email address, its local part (containment only from 4 characters on, so a
one-letter local part does not ban every password using that letter) or the application name;
and a password in the bundled list `password_lists/common_passwords.txt` (derived from a
SecLists list, MIT licence; source, commit and derivation are in the file header; the directory
is not called `data/`, which .gitignore reserves for runtime data). A breached-password corpus
(e.g. a k-anonymity lookup or an offline dump) is NOT included: follow-up.

Nothing here logs; no exception carries the token or the password. The caller commits for
`issue_setup_token`; `complete_setup` commits or rolls back itself.
"""

from __future__ import annotations

import enum
import hmac
import re
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any, cast

from argon2 import PasswordHasher
from pydantic import SecretStr
from sqlalchemy import CursorResult, exists, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.core.security import DEFAULT_HASHER, TOKEN_BYTES, hash_password, hash_session_token
from app.core.tenancy import TenantContext
from app.models import InstanceSetup, MembershipRole, Tenant, User
from app.models.instance_setup import SINGLETON_ID
from app.repositories import repo_for
from app.services.auth import IssuedSession, SessionPolicy, create_session, lookup_email

PASSWORD_MIN_LENGTH = 15
PASSWORD_MAX_LENGTH = 128
COMMON_PASSWORDS_FILE = Path(__file__).resolve().parent / "password_lists" / "common_passwords.txt"
_LOCAL_PART_MIN_CONTAINED = 4
TENANT_NAME_MAX_LENGTH = 200
_SLUG_MAX_LENGTH = 63
_TOKEN_LENGTH = 43  # secrets.token_urlsafe(32)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_DUMMY_DIGEST = "0" * 64

ERROR_EMAIL_INVALID = "setup.error.email_invalid"
ERROR_PASSWORD_SHORT = "setup.error.password_short"
ERROR_PASSWORD_LONG = "setup.error.password_long"
ERROR_PASSWORD_MISMATCH = "setup.error.password_mismatch"
ERROR_PASSWORD_COMMON = "setup.error.password_common"
ERROR_TENANT_NAME_INVALID = "setup.error.tenant_name_invalid"


class SetupOutcome(enum.Enum):
    COMPLETED = "completed"
    ALREADY_DONE = "already_done"  # a user exists or setup was claimed: /setup is a 404
    TOKEN_INVALID = "token_invalid"  # token replaced meanwhile (restart): ask again


@dataclass(frozen=True, slots=True)
class SetupInput:
    email: str  # normalised
    password: str
    tenant_name: str | None

    def __repr__(self) -> str:  # never show the password
        return f"SetupInput(email={self.email!r}, tenant_name={self.tenant_name!r})"


@dataclass(frozen=True, slots=True)
class SetupResult:
    outcome: SetupOutcome
    user_id: int | None = None
    tenant_id: int | None = None
    session: IssuedSession | None = None


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _has_forbidden_chars(value: str, categories: frozenset[str]) -> bool:
    return any(unicodedata.category(c) in categories for c in value)


# Control characters (NUL included) and lone surrogates break text columns (PostgreSQL refuses
# NUL). Emails get the same rule from `lookup_email`; format characters (Cf) are refused too.
_NAME_FORBIDDEN = frozenset({"Cc", "Cs"})
_EMAIL_EXTRA_FORBIDDEN = frozenset({"Cf"})


def setup_email(email: str) -> str | None:
    """The normalised admin email, or None if unusable (lookup_email rules: shape, at most
    MAX_EMAIL_LENGTH, no control character or surrogate; plus no format character)."""
    normalized = lookup_email(email)
    if normalized is None or _has_forbidden_chars(normalized, _EMAIL_EXTRA_FORBIDDEN):
        return None
    return normalized


@cache
def common_passwords() -> frozenset[str]:
    """The bundled blocklist (casefolded entries; comment lines skipped). Read once.
    A missing or unreadable file raises (OSError, UnicodeDecodeError); a file without entries
    raises RuntimeError. Startup calls this, so the app fails closed instead of serving setup
    without the blocklist."""
    lines = COMMON_PASSWORDS_FILE.read_text(encoding="utf-8").splitlines()
    entries = frozenset(line for line in lines if line and not line.startswith("#"))
    if not entries:
        raise RuntimeError("the bundled common-password list has no entries")
    return entries


def _squash(value: str) -> str:
    return "".join(value.casefold().split())


def is_blocklisted(password: str, *, email: str, app_name: str) -> bool:
    """True if the password is common or derived from the email or the application name."""
    candidate = _squash(password)
    if password.casefold() in common_passwords() or candidate in common_passwords():
        return True
    local = _squash(email.rpartition("@")[0])
    if candidate == local:
        return True
    contained = [_squash(email), _squash(app_name)]
    if len(local) >= _LOCAL_PART_MIN_CONTAINED:
        contained.append(local)
    return any(term and term in candidate for term in contained)


# --- state ----------------------------------------------------------------------------------------


def setup_required(db: Session) -> bool:
    """True while no user exists and the setup has not been completed."""
    if db.scalar(select(exists().where(User.id.is_not(None)))):
        return False
    completed = db.scalar(
        select(InstanceSetup.completed_at).where(InstanceSetup.id == SINGLETON_ID)
    )
    return completed is None


def issue_setup_token(db: Session, *, now: datetime | None = None) -> str | None:
    """A new one-time token (only its digest is stored, replacing any previous one), or None if
    setup is not required. Flushes; the caller commits and logs the token once."""
    if not setup_required(db):
        return None
    token = secrets.token_urlsafe(TOKEN_BYTES)
    digest = hash_session_token(token)
    current = now or _utcnow()
    row = db.scalars(select(InstanceSetup).where(InstanceSetup.id == SINGLETON_ID)).one_or_none()
    if row is None:
        db.add(InstanceSetup(id=SINGLETON_ID, token_hash=digest, token_issued_at=current))
    else:
        row.token_hash = digest
        row.token_issued_at = current
    db.flush()
    return token


def _token_digest(token: object) -> str | None:
    if not isinstance(token, str) or len(token) != _TOKEN_LENGTH or not _TOKEN_RE.fullmatch(token):
        return None
    return hash_session_token(token)


def verify_setup_token(db: Session, token: object) -> bool:
    """True if `token` matches the stored digest of a pending setup (constant-time compare)."""
    stored = db.scalar(
        select(InstanceSetup.token_hash).where(
            InstanceSetup.id == SINGLETON_ID, InstanceSetup.completed_at.is_(None)
        )
    )
    digest = _token_digest(token)
    matches = hmac.compare_digest(
        (stored or _DUMMY_DIGEST).encode("ascii"), (digest or _DUMMY_DIGEST).encode("ascii")
    )
    return matches and stored is not None and digest is not None


# --- validation -----------------------------------------------------------------------------------


def validate_setup_form(
    email: str, password: str, confirm: str, tenant_name: str, *, app_name: str
) -> tuple[SetupInput | None, list[str]]:
    """The validated input, or None and the i18n keys of every error. No DB access."""
    errors: list[str] = []
    normalized = setup_email(email)
    if normalized is None:
        errors.append(ERROR_EMAIL_INVALID)
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(ERROR_PASSWORD_SHORT)
    elif len(password) > PASSWORD_MAX_LENGTH:
        errors.append(ERROR_PASSWORD_LONG)
    elif is_blocklisted(password, email=normalized or email, app_name=app_name):
        errors.append(ERROR_PASSWORD_COMMON)
    if not hmac.compare_digest(password.encode("utf-8"), confirm.encode("utf-8")):
        errors.append(ERROR_PASSWORD_MISMATCH)
    name = tenant_name.strip()
    if len(name) > TENANT_NAME_MAX_LENGTH or _has_forbidden_chars(name, _NAME_FORBIDDEN):
        errors.append(ERROR_TENANT_NAME_INVALID)
    if errors or normalized is None:
        return None, errors
    return SetupInput(normalized, password, name or None), []


def slugify(name: str) -> str:
    """ASCII slug for a tenant name (lowercase letters, digits, single hyphens); "tenant" if
    nothing usable remains."""
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")[:_SLUG_MAX_LENGTH]
    return slug.strip("-") or "tenant"


def _free_slug(db: Session, name: str) -> str:
    base = slugify(name)
    candidate, n = base, 1
    while db.scalar(select(exists().where(Tenant.slug == candidate))):
        n += 1
        suffix = f"-{n}"
        candidate = base[: _SLUG_MAX_LENGTH - len(suffix)].rstrip("-") + suffix
    return candidate


# --- completion -----------------------------------------------------------------------------------


def claim_setup(db: Session, digest: str, *, now: datetime) -> bool:
    """The atomic claim (first write of the setup transaction): True for exactly one caller."""
    result = db.execute(
        update(InstanceSetup)
        .where(
            InstanceSetup.id == SINGLETON_ID,
            InstanceSetup.completed_at.is_(None),
            InstanceSetup.token_hash == digest,
        )
        .values(completed_at=now, token_hash=None)
        .execution_options(synchronize_session=False)
    )
    return bool(cast(CursorResult[Any], result).rowcount)


def complete_setup(
    db: Session,
    data: SetupInput,
    token: object,
    *,
    secret_key: SecretStr,
    policy: SessionPolicy,
    hasher: PasswordHasher = DEFAULT_HASHER,
    now: datetime | None = None,
) -> SetupResult:
    """Create the instance admin, the optional first tenant (admin as owner) and a session, in
    one transaction guarded by `claim_setup`. Commits on success, rolls back otherwise."""
    current = now or _utcnow()
    digest = _token_digest(token)
    if digest is None:
        return SetupResult(SetupOutcome.TOKEN_INVALID)
    password_hash = hash_password(data.password, hasher)  # before the write transaction
    db.rollback()  # start clean: the claim must be the first write
    try:
        if not claim_setup(db, digest, now=current):
            db.rollback()
            done = not setup_required(db)
            return SetupResult(SetupOutcome.ALREADY_DONE if done else SetupOutcome.TOKEN_INVALID)
        if db.scalar(select(exists().where(User.id.is_not(None)))):
            db.rollback()  # a user was created by other means: setup is over
            return SetupResult(SetupOutcome.ALREADY_DONE)
        user = User(
            email=data.email, password_hash=password_hash, is_instance_admin=True, is_active=True
        )
        db.add(user)
        db.flush()
        db.execute(
            update(InstanceSetup)
            .where(InstanceSetup.id == SINGLETON_ID)
            .values(admin_user_id=user.id)
            .execution_options(synchronize_session=False)
        )
        tenant_id: int | None = None
        if data.tenant_name is not None:
            tenant = Tenant(name=data.tenant_name, slug=_free_slug(db, data.tenant_name))
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            memberships = repo_for(TenantContext(tenant_id, user.id), db).memberships
            memberships.add(memberships.model(user_id=user.id, role=MembershipRole.OWNER))
        issued = create_session(
            db, user, secret_key, active_tenant_id=tenant_id, policy=policy, now=current
        )
        db.commit()
    except (IntegrityError, OperationalError):
        # A concurrent setup won (constraint or lock timeout): nothing of ours is kept.
        db.rollback()
        done = not setup_required(db)
        return SetupResult(SetupOutcome.ALREADY_DONE if done else SetupOutcome.TOKEN_INVALID)
    return SetupResult(SetupOutcome.COMPLETED, user.id, tenant_id, issued)
