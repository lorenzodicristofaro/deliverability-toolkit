"""``check`` command (M3-18): a tenant-less free check on a domain NAME.

Trust boundary: shell access to the instance. No TenantContext, no permission check, and a tenant
domain is never loaded. The only database read is the instance's DNSBL list enablement (M7-05c),
when `dnsbl` runs: the configured database (DATABASE_URL) is opened for that one query. If it
cannot be read (no configuration, no schema, driver error), a localized notice goes to stderr and
only the lists enabled by default run, so a restrictive list is never queried by accident.
The same runner as the API (``app.services.checks``) produces the results; ``--format json``
prints exactly ``CheckResult.model_dump_json()`` (one object for one check id, an array in
request order otherwise).

Exit codes: 0 all ok/info, 1 any warn/fail, 2 any ``error`` (could not evaluate), 64 usage error.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from typing import Annotated

import typer
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError

from app.checks.dkim import DkimCheck
from app.checks.dkim_selectors import list_selectors
from app.checks.dnsbl import DnsblCheck
from app.checks.finding_text import display_params
from app.checks.models import CheckContext, CheckResult
from app.checks.registry import CheckRegistry
from app.cli._text import visible
from app.core import i18n
from app.core.config import ConfigError, Settings
from app.core.db import create_session_factory, engine_from_settings
from app.core.i18n import t
from app.dns.cache import CachingResolver
from app.dns.factory import build_resolver
from app.dns.types import Resolver
from app.models.dnsbl_enablement import DnsblListEnablement
from app.services.checks import (
    InvalidTarget,
    UnknownCheck,
    default_registry,
    run_checks,
    with_dnsbl_enabled,
)
from app.services.dnsbl_admin import enabled_list_ids

EXIT_OK = 0
EXIT_WARN = 1
EXIT_ERROR = 2
EXIT_USAGE = 64

FORMATS = ("text", "json")


def _default_resolver() -> Resolver:
    """Same env config as the app (RESOLVER_MODE/RESOLVER_ADDRS), trusted operator config."""
    return CachingResolver(build_resolver(Settings()))


# The seam tests replace (the API's equivalent is the ``dns_backend`` dependency).
resolver_factory: Callable[[], Resolver] = _default_resolver

DNSBL_ENABLEMENT_NOTICE_KEY = "cli.check.notice.dnsbl_enablement_unavailable"


def _database_enabled_dnsbl() -> frozenset[str] | None:
    """The instance's enabled DNSBL list ids from the configured database; None if unreadable.
    Logs nothing and prints nothing: the caller prints the localized notice."""
    try:
        engine = engine_from_settings(Settings())
    except (ConfigError, SQLAlchemyError, ImportError, ValueError):
        return None
    try:
        with create_session_factory(engine)() as db:
            if not inspect(db.connection()).has_table(DnsblListEnablement.__tablename__):
                return None
            return enabled_list_ids(db)
    except SQLAlchemyError:
        return None
    finally:
        engine.dispose()


# The seam tests replace: the instance DNSBL enablement, or None when it cannot be read.
dnsbl_enablement_loader: Callable[[], frozenset[str] | None] = _database_enabled_dnsbl


def exit_code(results: Sequence[CheckResult]) -> int:
    statuses = {r.status for r in results}
    if "error" in statuses:
        return EXIT_ERROR
    if statuses & {"warn", "fail"}:
        return EXIT_WARN
    return EXIT_OK


def render_json(results: Sequence[CheckResult], *, single: bool) -> str:
    """Byte-equal to ``model_dump_json()`` per result; array elements joined without spaces."""
    if single:
        return results[0].model_dump_json()
    return "[" + ",".join(r.model_dump_json() for r in results) + "]"


def render_text(results: Sequence[CheckResult], lang: str) -> str:
    lines: list[str] = []
    for r in results:
        status = t(f"cli.check.status.{r.status}", lang)
        lines.append(t("cli.check.heading", lang, check=r.check_id, target=r.target, status=status))
        if not r.findings:
            lines.append("  " + t("cli.check.no_findings", lang))
        for f in r.findings:
            params = {
                k: visible(v) if isinstance(v, str) else v
                for k, v in display_params(f.code, f.params, lang).items()
            }
            sev = t(f"cli.check.severity.{f.severity}", lang)
            lines.append(f"  [{sev}] {t(f.title_key, lang, **params)}")
            lines.append("    " + t(f.detail_key, lang, **params))
            if f.remediation_key:
                lines.append(
                    "    " + t("cli.check.fix", lang, text=t(f.remediation_key, lang, **params))
                )
            if f.evidence:
                lines.append(
                    "    "
                    + t("cli.check.evidence", lang, text="; ".join(visible(e) for e in f.evidence))
                )
        lines.append("")
    lines.append(t("cli.check.summary", lang, count=len(results), code=exit_code(results)))
    return "\n".join(lines)


def _registry_with_selectors(extra: Sequence[str]) -> CheckRegistry:
    """The built-in registry, with dkim probing the seed plus ad-hoc selectors (this run only)."""
    base = default_registry()
    reg = CheckRegistry()
    for check_id in base.all_ids():
        if check_id == DkimCheck.id:
            names = tuple(dict.fromkeys([*(s.name for s in list_selectors()), *extra]))
            reg.register(DkimCheck(selectors=names))
        else:
            reg.register(base.get(check_id))
    return reg


def _fail(msg_key: str, code: int, lang: str = i18n.DEFAULT_LANGUAGE, **params: str) -> typer.Exit:
    typer.echo(t(msg_key, lang, **params), err=True)
    return typer.Exit(code)


def check_command(
    domain: Annotated[str, typer.Argument(help=t("cli.check.arg.domain"))],
    only: Annotated[str | None, typer.Option("--only", help=t("cli.check.opt.only"))] = None,
    fmt: Annotated[
        str, typer.Option("--format", help=t("cli.check.opt.format"), show_default=False)
    ] = "text",
    lang: Annotated[
        str, typer.Option("--lang", help=t("cli.check.opt.lang"), show_default=False)
    ] = i18n.DEFAULT_LANGUAGE,
    selector: Annotated[
        list[str] | None, typer.Option("--selector", help=t("cli.check.opt.selector"))
    ] = None,
) -> None:
    if lang not in i18n.SUPPORTED_LANGUAGES:
        raise _fail("cli.check.error.invalid_lang", EXIT_USAGE)
    if fmt not in FORMATS:
        raise _fail("cli.check.error.invalid_format", EXIT_USAGE, lang)
    extra = list(selector or [])
    registry = _registry_with_selectors(extra)
    if only is None:
        ids = registry.all_ids()
    else:
        ids = [p.strip() for p in only.split(",")]
        if len(set(ids)) != len(ids):  # the API rejects duplicate ids too
            raise _fail("cli.check.error.duplicate_check", EXIT_USAGE, lang)
    if extra and DkimCheck.id not in ids:
        raise _fail("cli.check.error.selector_needs_dkim", EXIT_USAGE, lang)
    single = only is not None and len(ids) == 1
    try:
        resolver = resolver_factory()
    except ConfigError as e:
        raise _fail("cli.check.error.config", EXIT_ERROR, lang, setting=e.key) from None
    if DnsblCheck.id in ids:
        enabled = dnsbl_enablement_loader()
        if enabled is None:
            typer.echo(t(DNSBL_ENABLEMENT_NOTICE_KEY, lang), err=True)
        registry = with_dnsbl_enabled(registry, enabled or frozenset())
    ctx = CheckContext(resolver=resolver)
    try:
        results = asyncio.run(run_checks(ids, domain, ctx, registry=registry, allow_ip=True))
    except UnknownCheck as e:
        raise _fail("cli.check.error.unknown_check", EXIT_USAGE, lang, check=e.check_id) from None
    except InvalidTarget:
        raise _fail("cli.check.error.invalid_domain", EXIT_USAGE, lang) from None
    out = render_json(results, single=single) if fmt == "json" else render_text(results, lang)
    typer.echo(out)
    raise typer.Exit(exit_code(results))
