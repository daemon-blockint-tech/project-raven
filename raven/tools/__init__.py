"""Security tool orchestration layer"""

__all__ = [
    "SSHManager",
    "BashExecutor",
    "NmapScanner",
    "MetasploitIntegration",
    "NucleiScanner",
    "EmpireClient",
    "GhidraAnalyzer",
]

_module_map = {
    "SSHManager":            ".ssh_manager",
    "BashExecutor":          ".bash_executor",
    "NmapScanner":           ".nmap_scanner",
    "MetasploitIntegration": ".metasploit_integration",
    "NucleiScanner":         ".nuclei_scanner",
    "EmpireClient":          ".empire_client",
    "GhidraAnalyzer":        ".ghidra_analyzer",
}


def __getattr__(name: str):
    if name in _module_map:
        import importlib
        module = importlib.import_module(_module_map[name], package=__name__)
        obj = getattr(module, name)
        globals()[name] = obj
        return obj
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
