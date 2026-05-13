"""
`raven model` command group.

Usage:
    raven model set gpt-4o
    raven model set openrouter:nous-hermes-2-mixtral-8x7b   # provider:model shorthand
    raven model list                                         # list models for active provider
    raven model status                                       # show current model
"""

from __future__ import annotations

import typer

from raven.ai.base import parse_provider_model
from raven.ai.registry import ProviderRegistry

app = typer.Typer(name="model", help="Manage AI model selection.", no_args_is_help=True)


def _registry() -> ProviderRegistry:
    return ProviderRegistry.get_instance()


@app.command("set")
def model_set(
    model: str = typer.Argument(
        ...,
        help="Model name or 'provider:model' shorthand, e.g. openrouter:nous-hermes-2-mixtral-8x7b",
    ),
):
    """Change the active model (keeps current provider and API key).

    Use 'provider:model' shorthand to switch provider and model in one command.
    """
    registry = _registry()
    if ":" in model:
        inferred_provider, bare_model = parse_provider_model(model)
        if inferred_provider:
            try:
                client = registry.switch(provider=inferred_provider, model=bare_model)
            except ValueError as e:
                typer.echo(f"[error] {e}", err=True)
                raise typer.Exit(1)
            typer.echo(f"✓ Switched to {inferred_provider}:{bare_model}")
        else:
            client = registry.set_model(bare_model)
            typer.echo(f"✓ Model set to {bare_model}")
    else:
        client = registry.set_model(model)
        typer.echo(f"✓ Model set to {model}")

    st = registry.status()
    reachable = client.is_available()
    typer.echo(f"  Provider: {st['provider']}")
    typer.echo(f"  Model:    {st['model']}")
    typer.echo(f"  Status:   {'✓ reachable' if reachable else '✗ unreachable'}")


@app.command("status")
def model_status():
    """Show the currently selected model and provider."""
    st = _registry().status()
    typer.echo(f"Provider: {st['provider']}")
    typer.echo(f"Model:    {st['model']}")
    typer.echo(f"Status:   {'✓ available' if st['available'] else '✗ unavailable'}")


@app.command("list")
def model_list():
    """List models available from the active provider (requires connectivity)."""
    client = _registry().get_client()
    typer.echo(f"Fetching models from {client.provider_name}…")
    try:
        models = client.list_loaded_models()
    except Exception as e:
        typer.echo(f"[error] Could not fetch models: {e}", err=True)
        raise typer.Exit(1)
    if not models:
        typer.echo("No models returned (provider may not support model listing).")
        return
    typer.echo(f"\nAvailable models ({len(models)}):")
    for m in models:
        typer.echo(f"  • {m}")
