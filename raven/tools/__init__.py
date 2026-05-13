"""Security tool orchestration layer.

All adapters are lazy-loaded via ``__getattr__`` so importing one tool does
not pay the import cost of the rest. New tools are uniformly built on
:class:`ToolAdapter` (see ``adapter_base.py``).
"""

from typing import Any

__all__ = [
    # Adapter base
    "ToolAdapter",
    "ToolResult",
    # Legacy native integrations
    "SSHManager",
    "BashExecutor",
    "NmapScanner",
    "MetasploitIntegration",
    "NucleiScanner",
    "EmpireClient",
    "GhidraAnalyzer",
    # New subprocess adapters
    "ProjectDiscoverySuite",
    "SubfinderAdapter",
    "NaabuAdapter",
    "HttpxAdapter",
    "InteractshAdapter",
    "SearchsploitAdapter",
    "ReconNgAdapter",
    "YaraScanner",
    "JadxAdapter",
    "Radare2Adapter",
    "FridaAdapter",
    "VolatilityAdapter",
    "CyberchefAdapter",
    # Legacy aliases (re-export shims)
    "ExploitDBClient",
    "RadareClient",
    "FridaHook",
    "VolatilityAnalyzer",
    "ReconNgClient",
    "JadxAnalyzer",
    "CyberChefClient",
    "X64DbgClient",
    # MCP server registry
    "MCPRegistry",
    "MCPServer",
    "mcp_registry",
]


_module_map = {
    # Adapter base
    "ToolAdapter": ".adapter_base",
    "ToolResult": ".adapter_base",
    # Legacy native integrations
    "SSHManager": ".ssh_manager",
    "BashExecutor": ".bash_executor",
    "NmapScanner": ".nmap_scanner",
    "MetasploitIntegration": ".metasploit_integration",
    "NucleiScanner": ".nuclei_scanner",
    "EmpireClient": ".empire_client",
    "GhidraAnalyzer": ".ghidra_analyzer",
    # New adapters
    "ProjectDiscoverySuite": ".projectdiscovery",
    "SubfinderAdapter": ".projectdiscovery",
    "NaabuAdapter": ".projectdiscovery",
    "HttpxAdapter": ".projectdiscovery",
    "InteractshAdapter": ".projectdiscovery",
    "SearchsploitAdapter": ".exploitdb",
    "ReconNgAdapter": ".recon_ng",
    "YaraScanner": ".yara_scan",
    "JadxAdapter": ".jadx",
    "Radare2Adapter": ".radare2",
    "FridaAdapter": ".frida",
    "VolatilityAdapter": ".volatility",
    "CyberchefAdapter": ".cyberchef",
    # Legacy shims
    "ExploitDBClient": ".exploitdb_client",
    "RadareClient": ".radare_client",
    "FridaHook": ".frida_hook",
    "VolatilityAnalyzer": ".volatility_analyzer",
    "ReconNgClient": ".recon_ng_client",
    "JadxAnalyzer": ".jadx_analyzer",
    "CyberChefClient": ".cyberchef_client",
    "X64DbgClient": ".x64dbg_client",
    # MCP
    "MCPRegistry": ".mcp_registry",
    "MCPServer": ".mcp_registry",
}


def mcp_registry():
    """Return the singleton MCP server registry."""
    from raven.tools.mcp_registry import registry
    return registry()


def __getattr__(name: str) -> Any:
    if name in _module_map:
        import importlib

        module = importlib.import_module(_module_map[name], package=__name__)
        obj = getattr(module, name)
        globals()[name] = obj
        return obj
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
