"""
Raven CLI entry point.

Install: pip install -e .
Usage:   raven --help

Commands:
    raven provider set <provider> [--key KEY] [--model MODEL]
    raven provider save <name>
    raven provider load <name>
    raven provider list
    raven provider providers
    raven model set <model>           # supports provider:model shorthand
    raven model list
    raven model status
"""

from __future__ import annotations

import typer

from raven.cli.commands.provider import app as provider_app
from raven.cli.commands.model import app as model_app
from raven.cli.commands.prompt import app as prompt_app
from raven.cli.commands.approval import app as approval_app
from raven.cli.commands.redteam import app as redteam_app
from raven.cli.commands.train import app as train_app

# ---------------------------------------------------------------------------
# ASCII banner (logo/ascii/ascii-art.txt)
# ---------------------------------------------------------------------------

BANNER = r"""
       &&&&&&&&&&&&
     &&&&&&X x&&&&&&&&&&
   &&&&&&&&&x$&&&&&&&&&&&
   &&&&&&&&&&&&&&&&&&&&&&&&&&& &&&&&&&  &&&&&&&&   &&& &&&&&&& &&&&&&&&&&&&&&&&&
  &&&&&&&&&&&&&&&&    &&    && &&   &&&&&&&   &&&  &&& &&     &&&&   &&&   &&
 &&&&&&&&&&&&&&&&&    &&&&&&&& &&&&&&& &&      &&  &&& &&&&&& &&           &&
 &&&&&&&&&&&&&&&&&&&& &&&&&&   &&&&&&  &&&     &&  &&& &&     &&&     &&   &&
 &&&&&&&&&&&&&&&&&&&&&&&       &&   &&  &&&&&&&&&&&&&  &&&&&&& &&&&&&&&    &&
 &&&&&&&&&&&&&&&&&&&&&&&&&     &&   &&&&&&&&&&&  &&& &&&&&&&&&&  &&&   &&& &&&&&&&&&&  &&&      &&&
&&&&&&&&&&&&&&&&&&&&&&&&&&&&        &&&&&&&&&&&&     &&&&&   &&&      &&&  &&&&&&&&&&  &&&&     &&&
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&       &&&      &&&    &&& &&&  &&&     &&&   &&          &&&&&    &&&
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&     &&&     &&&&   &&&  &&&   &&&    &&&   &&&&&&&&&   && &&&&  &&&
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&   &&&&&&&&&&&   &&&    &&&   &&&  &&&    &&&&&&&&&   &&  &&&& &&&
  &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& &&&   &&&&    &&&&&&&&&&&   && &&&     &&          &&    &&&&&&
   &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&    &&&&  &&&      &&&   &&&&&&     &&          &&     &&&&&
    &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&     &&&&&&&        &&&   &&&&      &&&&&&&&&&  &&      &&&&
      &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
         &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
            &&&&&&&&&&&&&&&&&&&&&&&&&&&&&
             &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
              &&&&&  &&&&  &&&&&&&&&&&&&&&&&&
             &&&&   &&&&      &&&&&&&&&&&&&&&&&
           &&&&    &&&&        &&&&&&&&&&&&&&&&&
      &&&&&&&&&&&&&&&&&&         &&&&&&&&&&&&&&
      &&&&&&  &&&&&&&&&&&               &&&&&&&&&
"""


def _print_banner() -> None:
    typer.echo(BANNER)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="raven",
    help="Project Raven — Autonomous Defense System CLI",
    no_args_is_help=True,
    add_completion=True,
)

app.add_typer(provider_app, name="provider")
app.add_typer(model_app, name="model")
app.add_typer(prompt_app, name="prompt")
app.add_typer(approval_app, name="approval")
app.add_typer(redteam_app, name="redteam")
app.add_typer(train_app, name="train")


@app.command("version")
def version():
    """Print the Raven version and banner."""
    from importlib.metadata import version as pkg_version, PackageNotFoundError

    _print_banner()
    try:
        v = pkg_version("project-raven")
    except PackageNotFoundError:
        v = "0.1.0-dev"
    typer.echo(f"  Project Raven  v{v}")
    typer.echo("  Autonomous Defense System — Multi-Provider AI\n")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Project Raven — Autonomous Defense System CLI."""
    if ctx.invoked_subcommand is None:
        _print_banner()
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()
