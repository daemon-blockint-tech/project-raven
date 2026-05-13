"""MCP (Model Context Protocol) server registry.

Project Raven can talk to external MCP servers — currently used for
disassembler backends ([GhidraMCP](https://github.com/13bm/GhidraMCP),
[radare2-mcp](https://github.com/radareorg/radare2-mcp)) so the AI side
of Raven can drive interactive reversing sessions the same way Cursor or
Claude Code can.

This module exposes a lightweight registry; full MCP client implementation
is intentionally out-of-scope here — operators wire Raven into an MCP
host via the same config the upstream agents use. We track *what* is
configured so the planner can route work appropriately.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MCPServer:
    """Declarative MCP server registration."""

    name: str
    transport: str         # "stdio" | "http" | "sse"
    command: Optional[str] = None      # for stdio
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None          # for http / sse
    env: Dict[str, str] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Default registry — operators can extend via `MCPRegistry.register(...)` or
# YAML config. These match the upstream README snippets.
DEFAULT_SERVERS: List[MCPServer] = [
    MCPServer(
        name="ghidra-mcp",
        transport="stdio",
        command="python",
        args=["-m", "ghidra_mcp.server"],
        capabilities=[
            "list_functions",
            "decompile_function",
            "list_imports",
            "list_strings",
            "follow_xref",
        ],
        description="13bm/GhidraMCP — Ghidra MCP backend for headless reverse engineering",
    ),
    MCPServer(
        name="radare2-mcp",
        transport="stdio",
        command="r2-mcp",   # provided by radareorg/radare2-mcp
        args=[],
        capabilities=[
            "open_binary",
            "analyze",
            "list_functions",
            "decompile_function",
            "search_string",
            "search_bytes",
        ],
        description="radareorg/radare2-mcp — radare2 MCP backend",
    ),
]


class MCPRegistry:
    """In-memory MCP server registry. Lookups by name, list by capability."""

    def __init__(self, servers: Optional[List[MCPServer]] = None) -> None:
        self._servers: Dict[str, MCPServer] = {
            s.name: s for s in (servers or DEFAULT_SERVERS)
        }

    def register(self, server: MCPServer) -> MCPServer:
        self._servers[server.name] = server
        return server

    def get(self, name: str) -> Optional[MCPServer]:
        return self._servers.get(name)

    def list(self) -> List[MCPServer]:
        return list(self._servers.values())

    def find_capability(self, capability: str) -> List[MCPServer]:
        return [s for s in self._servers.values() if capability in s.capabilities]

    def to_dict(self) -> Dict[str, Any]:
        return {name: s.to_dict() for name, s in self._servers.items()}


# Module-level singleton
_singleton: Optional[MCPRegistry] = None


def registry() -> MCPRegistry:
    global _singleton
    if _singleton is None:
        _singleton = MCPRegistry()
    return _singleton


def reset_registry() -> None:
    global _singleton
    _singleton = None
