"""
`raven prompt` command group.

Usage:
    raven prompt show               # print active system prompt
    raven prompt set "You are..."   # set raw text as system prompt
    raven prompt load               # reload from RAVEN_SYSTEM_PROMPT.md (default)
    raven prompt load /path/to/file # load from a custom file
    raven prompt clear              # remove system prompt
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from raven.ai.registry import ProviderRegistry

app = typer.Typer(name="prompt", help="Manage the AI system prompt.", no_args_is_help=True)


def _registry() -> ProviderRegistry:
    return ProviderRegistry.get_instance()


@app.command("show")
def prompt_show():
    """Print the currently active system prompt."""
    prompt = _registry().get_system_prompt()
    if not prompt:
        typer.echo("No system prompt set.")
        return
    typer.echo(f"─── System Prompt ({len(prompt)} chars) ───\n")
    typer.echo(prompt)
    typer.echo("\n─────────────────────────────────────")


@app.command("set")
def prompt_set(
    text: str = typer.Argument(..., help="System prompt text"),
):
    """Set the system prompt to a raw string."""
    _registry().set_system_prompt(text)
    typer.echo(f"✓ System prompt set ({len(text)} chars)")


@app.command("load")
def prompt_load(
    path: str = typer.Argument("RAVEN_SYSTEM_PROMPT.md", help="Path to .md or .txt file"),
):
    """Load the system prompt from a file.

    For .md files, the content of the first fenced code block is extracted.
    Defaults to RAVEN_SYSTEM_PROMPT.md in the current directory.
    """
    try:
        prompt = _registry().load_system_prompt_from_file(path)
    except FileNotFoundError as e:
        typer.echo(f"[error] {e}", err=True)
        raise typer.Exit(1)
    typer.echo(f"✓ Loaded system prompt from '{path}' ({len(prompt)} chars)")


@app.command("clear")
def prompt_clear(
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Clear the active system prompt."""
    if not confirm:
        typer.confirm("Clear the system prompt?", abort=True)
    _registry().set_system_prompt("")
    typer.echo("✓ System prompt cleared")
