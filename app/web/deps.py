"""Request dependencies: DB session, authenticated session, principal, TenantContext, `require`
(M1-15).

Fail closed everywhere:
- No session, a tampered/revoked/expired cookie or an inactive user -> anonymous (`current_session`
  then answers 401, or a 303 to /login for browser page loads).
- The session's `active_tenant_id` is honoured only while the user holds a membership there
  (UserMembershipsRepository, which also ignores inactive users); otherwise the request has NO
  TenantContext and `tenant_ctx` answers 404.
- Client viewers get the DomainAccess grants of their active-tenant membership loaded here
  (M1-19), so `can()` sees their assigned domains; no rows -> no domains.
- `require(action, resource)` evaluates `app.core.permissions.can()`; any denial is a 404, so a
  resource of another tenant is indistinguishable from a missing one (ARCHITECTURE section 4).

Tenant data is reached only through `app.repositories` (repo_for / UserMembershipsRepository).
The `users` and `sessions` tables are user-owned (no tenant_id) and are read directly.

The DB session factory is created lazily from Settings on first use and cached on `app.state`
(`session_factory`, `db_engine`); tests may set `app.state.session_factory` themselves.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import quote

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.db import create_session_factory, engine_from_settings
from app.core.i18n import t
from app.core.permissions import Action, Principal, Resource, TenantResource, can
from app.core.security import SESSION_COOKIE_NAME
from app.core.tenancy import TenantContext
from app.models import MembershipRole, User
from app.repositories import (
    DomainAccessRepository,
    UserMembershipsRepository,
    principal_from_models,
    repo_for,
)
from app.services.auth import SessionPolicy, resolve_session
from app.web.templating import app_settings, request_language, safe_next

AUTH_REQUIRED_KEY = "auth.required"
LOGIN_PATH = "/login"

_factory_lock = threading.Lock()


def get_settings(request: Request) -> Settings:
    return app_settings(request)


def _session_factory(request: Request) -> sessionmaker[Session]:
    state = request.app.state
    factory = getattr(state, "session_factory", None)
    if factory is None:
        with _factory_lock:
            factory = getattr(state, "session_factory", None)
            if factory is None:
                engine = engine_from_settings(app_settings(request))
                factory = create_session_factory(engine)
                state.db_engine = engine
                state.session_factory = factory
    return factory


def get_db(request: Request) -> Iterator[Session]:
    """One Session per request. Writers commit explicitly; anything uncommitted is rolled back."""
    db = _session_factory(request)()
    try:
        yield db
    finally:
        db.close()


SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[Session, Depends(get_db)]


@dataclass(frozen=True, slots=True)
class AuthSession:
    """The live session of the request. `active_tenant_id` is None unless the user holds an
    active membership in the session's tenant (validated on every request)."""

    session_id: int
    user: User
    active_tenant_id: int | None
    principal: Principal


def _build(db: Session, user: User, session_id: int, tenant_id: int | None) -> AuthSession:
    anonymous_tenant = AuthSession(
        session_id, user, None, principal_from_models(user, [], [], None)
    )
    if tenant_id is None:
        return anonymous_tenant
    if UserMembershipsRepository(db, user.id).get_for_tenant(tenant_id) is None:
        return anonymous_tenant  # stale or foreign active_tenant_id: no TenantContext
    ctx = TenantContext(tenant_id=tenant_id, principal=user.id)
    repos = repo_for(ctx, db)
    membership = repos.memberships.get_by_user(user.id)
    if membership is None:
        return anonymous_tenant
    principal = principal_from_models(user, [membership], [], tenant_id)
    if membership.role == MembershipRole.CLIENT_VIEWER:
        principal = _with_assigned_domains(principal, tenant_id, repos.domain_access, user.id)
    return AuthSession(session_id, user, tenant_id, principal)


def _with_assigned_domains(
    principal: Principal, tenant_id: int, access: DomainAccessRepository, user_id: int
) -> Principal:
    """`principal` with the DomainAccess grants of its (single) active-tenant membership loaded.
    Only domain-restricted roles need them; no rows -> no domains (fail closed)."""
    grants = [m for m in principal.memberships if m.tenant_id == tenant_id]
    if len(grants) != 1:
        return principal
    loaded = dataclasses.replace(grants[0], domain_ids=access.domain_ids_for_user(user_id))
    return dataclasses.replace(principal, memberships=(loaded,))


def optional_session(request: Request, db: DbDep, settings: SettingsDep) -> AuthSession | None:
    """The request's live session, or None (anonymous)."""
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie is None:
        return None
    resolved = resolve_session(
        db, cookie, settings.secret_key, policy=SessionPolicy.from_settings(settings)
    )
    if resolved is None:
        return None
    db.commit()  # persist the refreshed last_seen_at (idle expiry)
    user = db.scalars(select(User).where(User.id == resolved.user_id)).one_or_none()
    if user is None or user.is_active is not True:
        return None
    return _build(db, user, resolved.session_id, resolved.active_tenant_id)


def _login_required(request: Request) -> HTTPException:
    if request.method in ("GET", "HEAD") and "text/html" in request.headers.get("accept", ""):
        path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        location = f"{LOGIN_PATH}?next={quote(safe_next(path), safe='')}"
        return HTTPException(status_code=303, headers={"Location": location})
    lang = request_language(request.scope)
    return HTTPException(status_code=401, detail=t(AUTH_REQUIRED_KEY, lang))


def current_session(
    request: Request, auth: Annotated[AuthSession | None, Depends(optional_session)]
) -> AuthSession:
    """The live session; anonymous -> 401 (API) or 303 to /login?next=... (browser GET)."""
    if auth is None:
        raise _login_required(request)
    return auth


CurrentSession = Annotated[AuthSession, Depends(current_session)]


def current_principal(auth: CurrentSession) -> Principal:
    return auth.principal


def tenant_ctx(auth: CurrentSession) -> TenantContext:
    """TenantContext of the validated active tenant; 404 when there is none."""
    if auth.active_tenant_id is None:
        raise HTTPException(status_code=404)
    return TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)


ResourceSpec = Resource | Callable[[AuthSession, Request], Resource | None]


def active_tenant(auth: AuthSession, _request: Request) -> Resource | None:
    """The active tenant as a permission resource (None without one)."""
    return None if auth.active_tenant_id is None else TenantResource(auth.active_tenant_id)


def require(action: Action, resource: ResourceSpec = active_tenant) -> Callable[..., Principal]:
    """Dependency factory: the principal if `can(principal, action, resource)`, else 404.
    `resource` is a fixed Resource or a callable building one from the session and request."""

    def dependency(request: Request, auth: CurrentSession) -> Principal:
        target = resource(auth, request) if callable(resource) else resource
        if target is None or not can(auth.principal, action, target):
            raise HTTPException(status_code=404)
        return auth.principal

    return dependency
