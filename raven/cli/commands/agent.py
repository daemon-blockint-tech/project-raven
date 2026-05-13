"""
`raven agent` command group.

Usage:
    raven agent chat                          # interactive REPL with OpenRouterAgent
    raven agent chat --model anthropic/claude-3.5-sonnet
    raven agent chat --no-tools               # disable built-in security tools
    raven agent tools                         # list registered tools
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="agent",
    help="OpenRouter agentic loop — interactive chat with tool calling.",
    no_args_is_help=True,
)


def _build_agent(model: str, no_tools: bool):
    from raven.ai.openrouter_agent import OpenRouterAgent
    from raven.ai.registry import ProviderRegistry

    registry = ProviderRegistry.get_instance()
    status = registry.status()
    cfg = registry._config

    agent = OpenRouterAgent(
        api_key=cfg.api_key,
        model=model or cfg.model or "openrouter/auto",
        instructions=(
            "You are Project Raven, an advanced AI security analyst. "
            "Use available tools to investigate targets, search exploits, "
            "and provide actionable threat intelligence."
        ),
        temperature=cfg.temperature,
        max_tokens=cfg.max_tokens,
        timeout=cfg.timeout,
    )

    if not no_tools:
        agent.register_security_defaults()

    return agent


@app.command("chat")
def agent_chat(
    model: str = typer.Option("", "--model", "-m", help="Override model (e.g. anthropic/claude-3.5-sonnet)"),
    no_tools: bool = typer.Option(False, "--no-tools", help="Disable built-in security tools"),
    clear: bool = typer.Option(False, "--clear", help="Clear history between turns"),
    max_steps: int = typer.Option(8, "--max-steps", help="Max agent loop steps per turn"),
):
    """Start an interactive chat session with the OpenRouter agent."""
    agent = _build_agent(model, no_tools)
    agent.max_steps = max_steps

    # Hooks for live output
    agent.on_stream_delta = lambda d: typer.echo(d, nl=False)
    agent.on_tool_call = lambda name, args: typer.echo(
        f"\n[tool] {name}({', '.join(f'{k}={v!r}' for k,v in args.items())})", err=True
    )
    agent.on_error = lambda e: typer.echo(f"\n[error] {e}", err=True)

    tools_label = "none" if no_tools else ", ".join(agent._tools.keys())
    typer.echo(f"Project Raven Agent  [model: {agent.model}]")
    typer.echo(f"Tools: {tools_label}")
    typer.echo("Type your message. Empty line to quit.\n")

    while True:
        try:
            user_input = typer.prompt("You")
        except (EOFError, KeyboardInterrupt):
            typer.echo("\nBye.")
            break

        if not user_input.strip():
            break

        if clear:
            agent.clear_history()

        typer.echo("Raven: ", nl=False)
        try:
            result = agent.send(user_input)
            typer.echo()  # newline after streamed output
            typer.echo(f"  [{result.steps} step(s)]", err=True)
        except Exception as exc:
            typer.echo(f"\n[error] {exc}", err=True)


@app.command("tools")
def agent_tools(
    model: str = typer.Option("", "--model", "-m", help="Model (affects tool listing only)"),
):
    """List all tools registered in the security agent."""
    agent = _build_agent(model, no_tools=False)
    typer.echo("Registered security tools:\n")
    for name, tool in agent._tools.items():
        typer.echo(f"  {name}")
        typer.echo(f"    {tool.description}")
        props = tool.parameters.get("properties", {})
        if props:
            typer.echo(f"    params: {', '.join(props.keys())}")
        typer.echo()
