"""OpenRouter Agentic Loop for Project Raven.

Implements a multi-step agent with tool-calling, streaming, hooks/callbacks,
and conversation history — adapted from the OpenRouter SKILL.md pattern
(https://openrouter.ai/skills/create-agent/SKILL.md) in pure Python.

The agent uses the existing OpenAICompatClient under the hood so
no additional HTTP dependency is introduced.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional

log = logging.getLogger(__name__)


@dataclass
class AgentMessage:
    role: str
    content: str
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None


@dataclass
class AgentTool:
    name: str
    description: str
    parameters: Dict[str, Any]
    execute: Callable[..., Any]

    def to_openai_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class AgentResult:
    content: str
    steps: int
    messages: List[AgentMessage]
    model: str = ""
    finish_reason: str = "stop"


class OpenRouterAgent:
    """Multi-step OpenRouter agent with tool calling and lifecycle hooks.

    Hooks (all optional callables):
      on_thinking_start()
      on_thinking_end()
      on_stream_delta(delta: str)
      on_stream_end(full_text: str)
      on_tool_call(name: str, args: dict)
      on_tool_result(name: str, result: Any)
      on_error(exc: Exception)
      on_step(step: int, response: Any)
    """

    DEFAULT_MAX_STEPS = 8

    def __init__(
        self,
        api_key: str = "",
        model: str = "openrouter/auto",
        instructions: str = "You are a helpful AI assistant.",
        max_steps: int = DEFAULT_MAX_STEPS,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        timeout: int = 120,
        http_referer: str = "https://raven.local",
        app_title: str = "Project Raven",
    ) -> None:
        self._api_key = api_key
        self.model = model
        self.instructions = instructions
        self.max_steps = max_steps
        self._tools: Dict[str, AgentTool] = {}
        self._history: List[AgentMessage] = []

        self._client_config: Dict[str, Any] = {
            "ai_provider": "openrouter",
            "ai_model": model,
            "ai_api_key": api_key,
            "ai_temperature": temperature,
            "ai_max_tokens": max_tokens,
            "ai_timeout": timeout,
            "openrouter_http_referer": http_referer,
            "openrouter_title": app_title,
        }

        self.on_thinking_start: Optional[Callable[[], None]] = None
        self.on_thinking_end: Optional[Callable[[], None]] = None
        self.on_stream_delta: Optional[Callable[[str], None]] = None
        self.on_stream_end: Optional[Callable[[str], None]] = None
        self.on_tool_call: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.on_tool_result: Optional[Callable[[str, Any], None]] = None
        self.on_error: Optional[Callable[[Exception], None]] = None
        self.on_step: Optional[Callable[[int, Any], None]] = None

    def register_tool(self, agent_tool: AgentTool) -> None:
        self._tools[agent_tool.name] = agent_tool

    def tool(
        self,
        name: str,
        description: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to register a function as an agent tool."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            schema = parameters or _infer_parameters(fn)
            self.register_tool(AgentTool(
                name=name,
                description=description,
                parameters=schema,
                execute=fn,
            ))
            return fn
        return decorator

    def get_messages(self) -> List[AgentMessage]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()

    def set_instructions(self, instructions: str) -> None:
        self.instructions = instructions

    def send(self, content: str) -> AgentResult:
        """Send a user message and run the multi-step agent loop."""
        from raven.ai.base import AIMessage
        from raven.ai.factory import create_client_from_config

        client = create_client_from_config(self._client_config)

        self._history.append(AgentMessage(role="user", content=content))

        if self.on_thinking_start:
            self.on_thinking_start()

        tools_schema = [t.to_openai_schema() for t in self._tools.values()] or None
        final_text = ""
        steps = 0

        try:
            for step in range(self.max_steps):
                steps = step + 1
                ai_messages = self._build_ai_messages()

                resp = client.chat(ai_messages, tools=tools_schema)

                if self.on_step:
                    self.on_step(steps, resp)

                if resp.content:
                    final_text = resp.content
                    if self.on_stream_delta:
                        self.on_stream_delta(resp.content)
                    if self.on_stream_end:
                        self.on_stream_end(resp.content)

                if not resp.tool_calls:
                    self._history.append(AgentMessage(role="assistant", content=resp.content))
                    break

                self._history.append(AgentMessage(
                    role="assistant",
                    content=resp.content or "",
                    tool_calls=resp.tool_calls,
                ))

                for tc in resp.tool_calls:
                    tool_name, call_id, raw_args = _parse_tool_call(tc)
                    args = _safe_json_loads(raw_args)

                    if self.on_tool_call:
                        self.on_tool_call(tool_name, args)

                    result = self._execute_tool(tool_name, args)

                    if self.on_tool_result:
                        self.on_tool_result(tool_name, result)

                    self._history.append(AgentMessage(
                        role="tool",
                        content=json.dumps(result) if not isinstance(result, str) else result,
                        tool_call_id=call_id,
                        name=tool_name,
                    ))
            else:
                log.warning("OpenRouterAgent reached max_steps=%d", self.max_steps)

        except Exception as exc:
            if self.on_error:
                self.on_error(exc)
            raise
        finally:
            if self.on_thinking_end:
                self.on_thinking_end()

        return AgentResult(
            content=final_text,
            steps=steps,
            messages=list(self._history),
            model=self.model,
        )

    def send_stream(self, content: str) -> Iterator[str]:
        """Send and yield token deltas (single-step, no tools)."""
        from raven.ai.base import AIMessage
        from raven.ai.factory import create_client_from_config

        client = create_client_from_config(self._client_config)
        self._history.append(AgentMessage(role="user", content=content))
        ai_messages = self._build_ai_messages()
        full_text = ""

        for delta in client.chat_stream(ai_messages):
            full_text += delta
            if self.on_stream_delta:
                self.on_stream_delta(delta)
            yield delta

        if self.on_stream_end:
            self.on_stream_end(full_text)
        self._history.append(AgentMessage(role="assistant", content=full_text))

    def _build_ai_messages(self):
        from raven.ai.base import AIMessage
        msgs = []
        if self.instructions:
            msgs.append(AIMessage(role="system", content=self.instructions))
        for m in self._history:
            msgs.append(AIMessage(role=m.role, content=m.content or ""))
        return msgs

    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            return {"error": f"unknown tool: {name!r}"}
        try:
            return tool.execute(**args)
        except Exception as exc:
            log.error("Tool %r raised: %s", name, exc)
            return {"error": str(exc)}

    def register_security_defaults(self) -> None:
        """Register standard Raven security tools into this agent."""

        @self.tool(
            "whois_lookup",
            "Query WHOIS data for a domain or IP address",
            {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
        )
        def _whois(target: str) -> Dict[str, Any]:
            from raven.tools.whois_client import WhoisClient
            return WhoisClient().query(target)

        @self.tool(
            "searchsploit",
            "Search Exploit-DB for public exploits matching a keyword or CVE",
            {"type": "object", "properties": {
                "query": {"type": "string"},
                "cve": {"type": "string", "default": ""},
            }, "required": ["query"]},
        )
        def _searchsploit(query: str, cve: str = "") -> Dict[str, Any]:
            from raven.tools.exploitdb import SearchsploitAdapter
            a = SearchsploitAdapter()
            result = a.search_cve(cve) if cve else a.search_keyword(query)
            return result.to_dict()

        @self.tool(
            "nmap_scan",
            "Run an Nmap port scan against a host or CIDR range",
            {"type": "object", "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string", "default": "1-1024"},
            }, "required": ["target"]},
        )
        def _nmap(target: str, ports: str = "1-1024") -> Dict[str, Any]:
            from raven.tools.nmap_scanner import NmapScanner
            return NmapScanner({}).scan(target, ports=ports)

        @self.tool(
            "yara_scan",
            "Scan a file or directory with YARA rules",
            {"type": "object", "properties": {
                "rules_path": {"type": "string"},
                "target_path": {"type": "string"},
            }, "required": ["rules_path", "target_path"]},
        )
        def _yara(rules_path: str, target_path: str) -> Dict[str, Any]:
            from raven.tools.yara_scan import YaraScanner
            return YaraScanner().scan(rules_path=rules_path, target_path=target_path).to_dict()

        @self.tool(
            "solana_audit",
            "Run ARES-v3 deterministic static audit on a Solana smart contract source directory. "
            "Detects 12 vulnerability classes: type-cosplay, ownership-check, signer-authorization, "
            "arbitrary-cpi, reentrancy-risk, arithmetic-overflow, and more. Zero API cost.",
            {"type": "object", "properties": {
                "target": {"type": "string", "description": "Path to Solana program source directory"},
                "fmt":    {"type": "string", "default": "json", "description": "Output format: json, md, html"},
                "policy": {"type": "string", "default": "", "description": "Optional ares.toml policy path"},
            }, "required": ["target"]},
        )
        def _ares(target: str, fmt: str = "json", policy: str = "") -> Dict[str, Any]:
            from raven.tools.ares import AresAdapter
            return AresAdapter().scan(target, fmt=fmt, policy=policy).to_dict()

        @self.tool(
            "ebpf_ghidra_status",
            "Check whether Ghidra and the Solana eBPF processor extension are installed. "
            "The extension enables decompilation of compiled Solana .so programs.",
            {"type": "object", "properties": {}, "required": []},
        )
        def _ebpf_status() -> Dict[str, Any]:
            from raven.tools.ebpf_ghidra import EBPFGhidraSetup
            return EBPFGhidraSetup().setup_status().to_dict()


def _parse_tool_call(tc: Dict[str, Any]):
    fn = tc.get("function", {})
    return fn.get("name", ""), tc.get("id", ""), fn.get("arguments", "{}")


def _safe_json_loads(raw: str) -> Dict[str, Any]:
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"raw": raw}


def _infer_parameters(fn: Callable[..., Any]) -> Dict[str, Any]:
    import inspect
    sig = inspect.signature(fn)
    props: Dict[str, Any] = {}
    required: List[str] = []
    type_map = {str: "string", int: "integer", float: "number", bool: "boolean"}
    for pname, param in sig.parameters.items():
        if pname == "self":
            continue
        json_type = type_map.get(param.annotation, "string")
        props[pname] = {"type": json_type}
        if param.default is inspect.Parameter.empty:
            required.append(pname)
    return {"type": "object", "properties": props, "required": required}
