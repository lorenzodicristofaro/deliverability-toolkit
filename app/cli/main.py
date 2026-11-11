"""CLI entry (M3-18): ``python -m app.cli check example.com`` or the ``dtk`` script.

Click reports usage errors with exit code 2, which this CLI reserves for "could not evaluate";
usage errors are remapped to 64 here and print a translated generic message (never the input).
"""

from __future__ import annotations

from typing import Any

import typer
from typer import _click as click
from typer.core import TyperGroup

from app.cli.analyze import analyze_command
from app.cli.check import EXIT_USAGE, check_command
from app.cli.content import content_command
from app.core.i18n import t


class _UsageGroup(TyperGroup):
    def main(self, *args: Any, **kwargs: Any) -> Any:
        standalone = kwargs.pop("standalone_mode", True)
        try:
            result = super().main(*args, **{**kwargs, "standalone_mode": False})
            code = result if isinstance(result, int) else 0
        except click.exceptions.UsageError:
            typer.echo(t("cli.check.error.usage"), err=True)
            code = EXIT_USAGE
        except typer.Exit as e:
            code = e.exit_code
        except typer.Abort:
            code = 130
        if standalone:
            raise SystemExit(code)
        return code


app = typer.Typer(
    cls=_UsageGroup,
    help=t("cli.check.app_help"),
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode=None,
)


@app.callback()
def _root() -> None:
    """Keeps `check` a named subcommand (more will follow)."""


app.command("check", help=t("cli.check.help"))(check_command)
app.command("analyze", help=t("cli.analyze.help"))(analyze_command)
app.command("content", help=t("cli.content.help"))(content_command)


def main() -> None:
    app()
