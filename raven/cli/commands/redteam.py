"""`raven redteam` — scan, decode, hardness-test, and (gated) offensive godmode."""

from __future__ import annotations

import json
import sys

import typer

from raven.redteam.detector import JailbreakDetector
from raven.redteam.normalizer import ParseltongueNormaliser

app = typer.Typer(name="redteam", help="Defensive jailbreak tools + gated offensive godmode.",
                  no_args_is_help=True)


@app.command("scan")
def cmd_scan(
    text: str = typer.Argument(None, help="Prompt to scan; reads stdin if omitted"),
):
    """Run JailbreakDetector against a prompt. Useful for triaging suspicious input."""
    if text is None:
        text = sys.stdin.read()
    result = JailbreakDetector().scan(text)
    typer.echo(json.dumps(result.model_dump(), indent=2))


@app.command("decode")
def cmd_decode(
    text: str = typer.Argument(None, help="Obfuscated text to decode; reads stdin if omitted"),
    tier: str = typer.Option(ParseltongueNormaliser.HEAVY, "--tier",
                              help="light | standard | heavy"),
):
    """Run Parseltongue normalisation on text."""
    if text is None:
        text = sys.stdin.read()
    result = ParseltongueNormaliser(tier=tier).normalise(text)
    typer.echo(json.dumps({
        "original": result.original,
        "normalised": result.normalised,
        "changed": result.changed,
        "techniques_detected": result.techniques_detected,
    }, indent=2))


@app.command("hardness")
def cmd_hardness():
    """Run the canary suite against the active AI provider."""
    from raven.redteam.hardness_test import ProviderHardnessTest
    report = ProviderHardnessTest().run()
    typer.echo(json.dumps(report.model_dump(), indent=2))


@app.command("godmode")
def cmd_godmode(
    sandbox_session_id: str = typer.Option(..., "--session", help="Sandbox session id"),
    token: str = typer.Option(..., "--token", help="Offensive session token from settings"),
    question: str = typer.Option(
        "Briefly describe OWASP A1 Injection.",
        "--question",
    ),
):
    """OffensiveGodmode (gated). Runs synthesised strategies against the active provider."""
    from raven.redteam.offensive import OffensiveGodmode
    result = OffensiveGodmode().run(
        canary_question=question,
        sandbox_session_id=sandbox_session_id,
        authorization_token=token,
    )
    typer.echo(json.dumps(result.model_dump(), indent=2))
    if not result.enabled:
        raise typer.Exit(1)
