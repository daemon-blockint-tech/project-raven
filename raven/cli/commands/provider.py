"""
`raven provider` command group.

Usage:
    raven provider set openrouter --key sk-or-abc123
    raven provider set openrouter --key sk-or-... --model nous-hermes-2-mixtral-8x7b
    raven provider status
    raven provider list
    raven provider save work-profile
    raven provider load work-profile
    raven provider delete work-profile
    raven provider providers          # list all supported providers
"""

from __future__ import annotations

from typing import Optional

import typer

from raven.ai.base import SUPPORTED_PROVIDERS
from raven.ai.registry import ProviderRegistry

app = typer.Typer(name="provider", help="Manage AI provider and profiles.", no_args_is_help=True)


def _registry() -> ProviderRegistry:
    return ProviderRegistry.get_instance()


@app.command("set")
def provider_set(
    provider: str = typer.Argument(..., help="Provider name: lmstudio|openai|openrouter|anthropic|ollama|opencode|nous"),
    key: str = typer.Option("", "--key", "-k", help="API key for cloud providers"),
    model: str = typer.Option("", "--model", "-m", help="Model name (or provider:model shorthand)"),
    base_url: str = typer.Option("", "--base-url", "-u", help="Override base URL"),
):
    """Switch the active AI provider (persists for current session)."""
    try:
        client = _registry().switch(
            provider=provider,
            model=model,
            api_key=key,
            base_url=base_url,
        )
    except ValueError as e:
        typer.echo(f"[error] {e}", err=True)
        raise typer.Exit(1)

    status = _registry().status()
    typer.echo(f"✓ Provider: {status['provider']}")
    typer.echo(f"  Model:    {status['model']}")
    typer.echo(f"  API key:  {'set' if status['has_api_key'] else 'not set'}")
    reachable = client.is_available()
    typer.echo(f"  Status:   {'✓ reachable' if reachable else '✗ unreachable (check key/URL)'}")


@app.command("status")
def provider_status():
    """Show current provider, model, and connection status."""
    st = _registry().status()
    typer.echo(f"Provider:    {st['provider']}")
    typer.echo(f"Model:       {st['model']}")
    typer.echo(f"Base URL:    {st['base_url'] or '(default)'}")
    typer.echo(f"API key:     {'set' if st['has_api_key'] else 'not set'}")
    typer.echo(f"Description: {st['description']}")
    typer.echo(f"Available:   {'✓' if st['available'] else '✗'}")
    if st["profiles"]:
        typer.echo(f"Profiles:    {', '.join(st['profiles'])}")


@app.command("list")
def provider_list():
    """List all saved profiles."""
    profiles = _registry().list_profiles()
    if not profiles:
        typer.echo("No saved profiles. Use `raven provider save <name>` to create one.")
        return
    typer.echo("Saved profiles:")
    for p in profiles:
        typer.echo(f"  • {p}")


@app.command("save")
def provider_save(
    name: str = typer.Argument(..., help="Profile name"),
):
    """Save the current provider configuration as a named profile."""
    path = _registry().save_profile(name)
    typer.echo(f"✓ Saved profile '{name}' → {path}")


@app.command("load")
def provider_load(
    name: str = typer.Argument(..., help="Profile name to load"),
):
    """Load a saved profile and switch to it."""
    try:
        client = _registry().load_profile(name)
    except FileNotFoundError as e:
        typer.echo(f"[error] {e}", err=True)
        raise typer.Exit(1)
    st = _registry().status()
    typer.echo(f"✓ Loaded profile '{name}'")
    typer.echo(f"  Provider: {st['provider']}")
    typer.echo(f"  Model:    {st['model']}")
    reachable = client.is_available()
    typer.echo(f"  Status:   {'✓ reachable' if reachable else '✗ unreachable'}")


@app.command("delete")
def provider_delete(
    name: str = typer.Argument(..., help="Profile name to delete"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Delete a saved profile."""
    if not confirm:
        typer.confirm(f"Delete profile '{name}'?", abort=True)
    deleted = _registry().delete_profile(name)
    if deleted:
        typer.echo(f"✓ Deleted profile '{name}'")
    else:
        typer.echo(f"[error] Profile not found: {name!r}", err=True)
        raise typer.Exit(1)


@app.command("providers")
def list_providers():
    """List all supported AI providers."""
    typer.echo("Supported providers:\n")
    for info in SUPPORTED_PROVIDERS.values():
        key_label = "API key required" if info.needs_api_key else "no key (local)"
        typer.echo(f"  {info.name:<12} — {info.description}")
        typer.echo(f"             {key_label}")
        if info.example_models:
            typer.echo(f"             Models: {', '.join(info.example_models[:3])}")
        typer.echo()
