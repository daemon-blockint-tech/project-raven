"""
`raven tui` — launch the claude-code-style interactive TUI.

Usage:
    raven tui                                # default agent + tools
    raven tui --model anthropic/claude-3.5-sonnet
    raven tui --no-tools                     # disable built-in security tools
    raven tui --no-splash                    # skip the splash banner
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="tui",
    help="Launch the interactive claude-code-style TUI.",
    invoke_without_command=True,
)


@app.callback(invoke_without_command=True)
def tui_main(
    ctx: typer.Context,
    model: str = typer.Option("", "--model", "-m", help="Override model"),
    no_tools: bool = typer.Option(False, "--no-tools", help="Disable built-in security tools"),
    no_splash: bool = typer.Option(False, "--no-splash", help="Skip splash banner"),
    max_steps: int = typer.Option(8, "--max-steps", help="Max agent loop steps per turn"),
):
    """Launch the interactive TUI (default action when running `raven tui`)."""
    if ctx.invoked_subcommand is not None:
        return

    from raven.ai.openrouter_agent import OpenRouterAgent
    from raven.ai.registry import ProviderRegistry
    from raven.cli.tui import RavenTUI

    registry = ProviderRegistry.get_instance()
    cfg = registry._config

    agent = OpenRouterAgent(
        api_key=cfg.api_key,
        model=model or cfg.model or "openrouter/auto",
        instructions=(
            "You are Project Raven, an advanced AI security analyst. "
            "Use available tools to investigate targets, search exploits, "
            "and provide actionable threat intelligence. Be concise and direct."
        ),
        max_steps=max_steps,
        temperature=cfg.temperature,
        max_tokens=cfg.max_tokens,
        timeout=cfg.timeout,
    )

    if not no_tools:
        agent.register_security_defaults()

    try:
        from importlib.metadata import version as pkg_version, PackageNotFoundError
        try:
            v = pkg_version("project-raven")
        except PackageNotFoundError:
            v = "0.2.0-dev"
    except ImportError:
        v = "0.2.0-dev"

    RavenTUI(agent, version=v, show_splash=not no_splash).run()
