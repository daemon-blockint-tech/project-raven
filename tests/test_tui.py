"""Tests for Raven TUI."""
from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------

def test_splash_banner_renders():
    from raven.cli.tui.widgets import splash_banner
    banner = splash_banner("1.2.3")
    # rich Group is renderable
    assert banner is not None
    # Should contain version text somewhere
    from rich.console import Console
    from io import StringIO
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=120).print(banner)
    out = buf.getvalue()
    assert "1.2.3" in out
    assert "Project Raven" in out


def test_welcome_message():
    from raven.cli.tui.widgets import welcome_message
    msg = welcome_message("openrouter/auto", "openrouter", 4)
    from rich.console import Console
    from io import StringIO
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=120).print(msg)
    out = buf.getvalue()
    assert "openrouter/auto" in out
    assert "4" in out
    assert "/help" in out


def test_status_bar_format():
    from raven.cli.tui.widgets import status_bar
    s = status_bar("foo/bar", "openrouter", steps=3, tokens=1234)
    assert "foo/bar" in s
    assert "openrouter" in s
    assert "3 steps" in s
    assert "1,234 tokens" in s


def test_status_bar_singular_step():
    from raven.cli.tui.widgets import status_bar
    s = status_bar("m", "p", steps=1)
    assert "1 step " in s + " "  # not "1 steps"


def test_tool_call_line():
    from raven.cli.tui.widgets import tool_call_line
    line = tool_call_line("whois_lookup", {"target": "example.com"})
    from rich.console import Console
    from io import StringIO
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=120).print(line)
    out = buf.getvalue()
    assert "whois_lookup" in out
    assert "example.com" in out


def test_tool_result_line_success():
    from raven.cli.tui.widgets import tool_result_line
    r = tool_result_line("nmap_scan", success=True, duration=0.42, preview="22/tcp open")
    from rich.console import Console
    from io import StringIO
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=120).print(r)
    out = buf.getvalue()
    assert "nmap_scan" in out
    assert "0.42s" in out


def test_agent_response_panel():
    from raven.cli.tui.widgets import agent_response_panel
    p = agent_response_panel("# Hello\n\nThis is **bold**.")
    assert p is not None


# ---------------------------------------------------------------------------
# Slash commands
# ---------------------------------------------------------------------------

def _make_fake_tui():
    """Build a fake TUI object with the minimal attrs slash commands need."""
    from rich.console import Console
    tui = MagicMock()
    tui.console = Console(file=__import__("io").StringIO(), force_terminal=False, width=120)
    tui._steps_total = 5

    # Fake agent
    agent = MagicMock()
    agent.model = "openrouter/auto"
    agent._tools = {
        "whois_lookup": MagicMock(
            description="WHOIS lookup",
            parameters={"properties": {"target": {"type": "string"}}},
        ),
    }
    agent._history = []
    agent.get_messages = MagicMock(return_value=[])
    agent.clear_history = MagicMock()
    agent._client_config = {"ai_model": "openrouter/auto"}
    tui.agent = agent
    return tui


def test_slash_dispatch_unknown():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    result = dispatch(tui, "/nonexistent")
    assert result is None


def test_slash_exit():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    assert dispatch(tui, "/exit") == "exit"
    assert dispatch(tui, "/quit") == "exit"
    assert dispatch(tui, "/q") == "exit"


def test_slash_help():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    assert dispatch(tui, "/help") is None
    assert dispatch(tui, "/?") is None


def test_slash_clear():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    tui.console.clear = MagicMock()
    dispatch(tui, "/clear")
    tui.agent.clear_history.assert_called_once()


def test_slash_model_no_args_shows_current():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    dispatch(tui, "/model")
    # No exception → success


def test_slash_model_switch():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    dispatch(tui, "/model anthropic/claude-3.5-sonnet")
    assert tui.agent.model == "anthropic/claude-3.5-sonnet"


def test_slash_tools_lists():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    dispatch(tui, "/tools")


def test_slash_save_load_roundtrip(tmp_path, monkeypatch):
    from raven.cli.tui.slash_commands import dispatch
    from raven.ai.openrouter_agent import AgentMessage

    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

    tui = _make_fake_tui()
    tui.agent.get_messages = MagicMock(return_value=[
        AgentMessage(role="user", content="hi"),
        AgentMessage(role="assistant", content="hello"),
    ])
    tui.agent.model = "openrouter/auto"

    dispatch(tui, "/save mysession")
    saved = tmp_path / ".raven" / "tui_sessions" / "mysession.json"
    assert saved.exists()
    data = json.loads(saved.read_text())
    assert data["model"] == "openrouter/auto"
    assert len(data["messages"]) == 2

    # Load
    dispatch(tui, "/load mysession")
    tui.agent.clear_history.assert_called()


def test_slash_run_unknown_tool():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    dispatch(tui, "/run nonexistent_tool method")


def test_slash_run_bad_args():
    from raven.cli.tui.slash_commands import dispatch
    tui = _make_fake_tui()
    dispatch(tui, "/run whois lookup notavalidkv")
    dispatch(tui, "/run")  # missing args


# ---------------------------------------------------------------------------
# App construction (smoke test — does not run the REPL)
# ---------------------------------------------------------------------------

def test_tui_construction():
    from raven.ai.openrouter_agent import OpenRouterAgent
    from raven.cli.tui import RavenTUI

    agent = OpenRouterAgent(api_key="test", model="openrouter/auto")
    tui = RavenTUI(agent, version="1.0", show_splash=False)
    assert tui.agent is agent
    assert tui.version == "1.0"
    assert callable(agent.on_tool_call)
    assert callable(agent.on_tool_result)


def test_tui_bottom_toolbar():
    from raven.ai.openrouter_agent import OpenRouterAgent
    from raven.cli.tui import RavenTUI

    agent = OpenRouterAgent(api_key="test", model="openrouter/auto")
    tui = RavenTUI(agent, show_splash=False)
    tui._steps_total = 2
    bar = tui._bottom_toolbar()
    assert "openrouter/auto" in bar
    assert "2 steps" in bar
