"""`raven approval` — manage the approval gate (mode, allowlist, decisions).

Note: CLI mutates the same in-process gate singleton — useful for tests and
single-process deployments. In multi-replica K8s, use the REST API instead.
"""

from __future__ import annotations

import typer

from raven.approval.gate import approval_gate
from raven.approval.models import ApprovalMode
from raven.approval.store import allowlist_store

app = typer.Typer(name="approval", help="Manage the dangerous-command approval gate.", no_args_is_help=True)


@app.command("mode")
def cmd_mode(
    mode: str = typer.Argument(..., help="manual | smart | off"),
):
    """Set the active approval mode."""
    try:
        m = ApprovalMode(mode)
    except ValueError:
        typer.echo(f"[error] mode must be one of: {[m.value for m in ApprovalMode]}", err=True)
        raise typer.Exit(1)
    approval_gate().set_mode(m)
    typer.echo(f"✓ approval mode set to {m.value}")


@app.command("status")
def cmd_status():
    """Show current mode + permanent allowlist."""
    gate = approval_gate()
    typer.echo(f"Mode:    {gate.mode.value}")
    typer.echo(f"Timeout: {gate.timeout_seconds}s")
    patterns = allowlist_store().list()
    typer.echo(f"Allowlist ({len(patterns)}):")
    for p in patterns:
        typer.echo(f"  • {p}")


@app.command("allow")
def cmd_allow(
    pattern: str = typer.Argument(..., help="Regex pattern to add to the permanent allowlist"),
):
    """Permanently allow a regex pattern."""
    allowlist_store().add(pattern)
    typer.echo(f"✓ allowlisted: {pattern}")


@app.command("forget")
def cmd_forget(pattern: str = typer.Argument(...)):
    """Remove a pattern from the permanent allowlist."""
    removed = allowlist_store().remove(pattern)
    if not removed:
        typer.echo(f"[warn] pattern not found: {pattern}", err=True)
        raise typer.Exit(1)
    typer.echo(f"✓ removed: {pattern}")


@app.command("test")
def cmd_test(command: str = typer.Argument(..., help="Command string to test against the gate")):
    """Dry-run a command through the gate (no actual execution)."""
    decision = approval_gate().check(command, actor="cli")
    typer.echo(f"verdict:     {decision.verdict.value}")
    typer.echo(f"mode:        {decision.mode.value}")
    if decision.matched_description:
        typer.echo(f"matched:     {decision.matched_description}")
    if decision.severity:
        typer.echo(f"severity:    {decision.severity}")
    if decision.reason:
        typer.echo(f"reason:      {decision.reason}")
    if decision.request_id:
        typer.echo(f"request_id:  {decision.request_id}")
