"""Tests for OpenRouterAgent multi-step agentic loop."""
import json
import pytest
from unittest.mock import MagicMock, patch


def _make_agent(api_key="sk-or-test"):
    from raven.ai.openrouter_agent import OpenRouterAgent
    return OpenRouterAgent(
        api_key=api_key,
        model="openrouter/auto",
        instructions="You are a test agent.",
        max_steps=4,
    )


def _mock_response(content="Hello!", tool_calls=None):
    from raven.ai.base import AIResponse
    return AIResponse(
        content=content,
        model="openrouter/auto",
        tool_calls=tool_calls,
        finish_reason="stop",
        provider="openrouter",
    )


# ---------------------------------------------------------------------------
# Basic send
# ---------------------------------------------------------------------------

def test_send_simple_response():
    """Agent returns assistant content on a no-tool response."""
    agent = _make_agent()

    with patch("raven.ai.factory.create_client_from_config") as mock_factory:
        mock_client = MagicMock()
        mock_client.chat.return_value = _mock_response("World!")
        mock_factory.return_value = mock_client

        result = agent.send("Hello")

    assert result.content == "World!"
    assert result.steps == 1
    assert len(result.messages) == 2  # user + assistant


def test_send_builds_history():
    agent = _make_agent()

    with patch("raven.ai.factory.create_client_from_config") as mock_factory:
        mock_client = MagicMock()
        mock_client.chat.return_value = _mock_response("A1")
        mock_factory.return_value = mock_client
        agent.send("Q1")

        mock_client.chat.return_value = _mock_response("A2")
        agent.send("Q2")

    msgs = agent.get_messages()
    assert len(msgs) == 4
    assert msgs[0].role == "user"
    assert msgs[1].role == "assistant"


def test_clear_history():
    agent = _make_agent()
    with patch("raven.ai.factory.create_client_from_config") as mock_factory:
        mock_client = MagicMock()
        mock_client.chat.return_value = _mock_response("Hi")
        mock_factory.return_value = mock_client
        agent.send("Hey")

    agent.clear_history()
    assert agent.get_messages() == []


# ---------------------------------------------------------------------------
# Tool registration & decorator
# ---------------------------------------------------------------------------

def test_tool_decorator_registers():
    agent = _make_agent()

    @agent.tool("echo", "Echo back the input",
                {"type": "object", "properties": {"msg": {"type": "string"}}, "required": ["msg"]})
    def echo(msg: str) -> str:
        return msg

    assert "echo" in agent._tools
    assert agent._tools["echo"].description == "Echo back the input"


def test_tool_execute():
    agent = _make_agent()

    @agent.tool("add", "Add two numbers",
                {"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}, "required": ["a", "b"]})
    def add(a: int, b: int) -> int:
        return a + b

    result = agent._execute_tool("add", {"a": 3, "b": 4})
    assert result == 7


def test_unknown_tool_returns_error():
    agent = _make_agent()
    result = agent._execute_tool("nonexistent", {})
    assert "error" in result


# ---------------------------------------------------------------------------
# Multi-step tool calling loop
# ---------------------------------------------------------------------------

def test_tool_call_loop():
    """Agent executes a tool call and loops back for final answer."""
    from raven.ai.base import AIResponse

    agent = _make_agent()

    @agent.tool("ping", "Ping", {"type": "object", "properties": {}, "required": []})
    def ping() -> str:
        return "pong"

    tool_call_resp = AIResponse(
        content="",
        model="openrouter/auto",
        tool_calls=[{
            "id": "call_1",
            "type": "function",
            "function": {"name": "ping", "arguments": "{}"},
        }],
        finish_reason="tool_calls",
        provider="openrouter",
    )
    final_resp = _mock_response("Done! Ping returned pong.")

    with patch("raven.ai.factory.create_client_from_config") as mock_factory:
        mock_client = MagicMock()
        mock_client.chat.side_effect = [tool_call_resp, final_resp]
        mock_factory.return_value = mock_client

        result = agent.send("Run ping")

    assert result.steps == 2
    assert "pong" in str(result.messages) or result.content == "Done! Ping returned pong."


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

def test_on_tool_call_hook_fires():
    from raven.ai.base import AIResponse

    agent = _make_agent()
    calls = []
    agent.on_tool_call = lambda name, args: calls.append((name, args))

    @agent.tool("noop", "No-op", {"type": "object", "properties": {}, "required": []})
    def noop():
        return "ok"

    tool_resp = AIResponse(
        content="",
        model="openrouter/auto",
        tool_calls=[{"id": "c1", "type": "function", "function": {"name": "noop", "arguments": "{}"}}],
        finish_reason="tool_calls",
        provider="openrouter",
    )
    final_resp = _mock_response("done")

    with patch("raven.ai.factory.create_client_from_config") as mock_factory:
        mock_client = MagicMock()
        mock_client.chat.side_effect = [tool_resp, final_resp]
        mock_factory.return_value = mock_client
        agent.send("go")

    assert len(calls) == 1
    assert calls[0][0] == "noop"


def test_on_stream_delta_hook():
    agent = _make_agent()
    deltas = []
    agent.on_stream_delta = lambda d: deltas.append(d)

    with patch("raven.ai.factory.create_client_from_config") as mock_factory:
        mock_client = MagicMock()
        mock_client.chat.return_value = _mock_response("Hello!")
        mock_factory.return_value = mock_client
        agent.send("Hi")

    assert "Hello!" in deltas


# ---------------------------------------------------------------------------
# Security defaults
# ---------------------------------------------------------------------------

def test_register_security_defaults():
    agent = _make_agent()
    agent.register_security_defaults()
    assert "whois_lookup" in agent._tools
    assert "searchsploit" in agent._tools
    assert "nmap_scan" in agent._tools
    assert "yara_scan" in agent._tools


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def test_infer_parameters():
    from raven.ai.openrouter_agent import _infer_parameters

    def my_fn(host: str, port: int = 80):
        pass

    schema = _infer_parameters(my_fn)
    assert schema["type"] == "object"
    assert "host" in schema["properties"]
    assert schema["properties"]["host"]["type"] == "string"
    assert "host" in schema["required"]
    assert "port" not in schema["required"]


def test_safe_json_loads_bad_json():
    from raven.ai.openrouter_agent import _safe_json_loads
    result = _safe_json_loads("not json")
    assert "raw" in result


def test_tool_schema_shape():
    from raven.ai.openrouter_agent import AgentTool
    t = AgentTool(
        name="test",
        description="A test tool",
        parameters={"type": "object", "properties": {}, "required": []},
        execute=lambda: None,
    )
    schema = t.to_openai_schema()
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "test"
