"""
`raven tools` command group.

Usage:
    raven tools list                          # availability matrix
    raven tools whois example.com             # run whois lookup
    raven tools searchsploit --query apache   # search exploits
    raven tools run <name> <method> [KEY=VAL] # generic method dispatch
"""

from __future__ import annotations

import json
from typing import List

import typer

app = typer.Typer(
    name="tools",
    help="Invoke external security tool adapters.",
    no_args_is_help=True,
)


@app.command("list")
def tools_list():
    """Show availability status of all registered tool adapters."""
    from raven.tools import (
        SubfinderAdapter, NaabuAdapter, HttpxAdapter,
        SearchsploitAdapter, ReconNgAdapter, YaraScanner,
        JadxAdapter, Radare2Adapter, FridaAdapter,
        VolatilityAdapter, CyberchefAdapter,
    )
    from raven.tools.whois_client import WhoisClient

    adapters = {
        "subfinder":   SubfinderAdapter,
        "naabu":       NaabuAdapter,
        "httpx":       HttpxAdapter,
        "exploitdb":   SearchsploitAdapter,
        "recon-ng":    ReconNgAdapter,
        "yara":        YaraScanner,
        "jadx":        JadxAdapter,
        "radare2":     Radare2Adapter,
        "frida":       FridaAdapter,
        "volatility":  VolatilityAdapter,
        "cyberchef":   CyberchefAdapter,
        "whois":       WhoisClient,
    }

    typer.echo(f"{'Tool':<14} {'Status':<10} {'Install hint'}")
    typer.echo("-" * 60)
    for name, cls in adapters.items():
        try:
            inst = cls()
            ok = inst.is_available()
            hint = getattr(inst, "install_hint", "")
            status = "✓ ready" if ok else "✗ missing"
            typer.echo(f"{name:<14} {status:<10} {hint if not ok else ''}")
        except Exception as exc:
            typer.echo(f"{name:<14} {'✗ error':<10} {exc}")


@app.command("whois")
def tools_whois(
    target: str = typer.Argument(..., help="Domain or IP to look up"),
    json_out: bool = typer.Option(False, "--json", help="Output raw JSON"),
):
    """Run a WHOIS lookup for a domain or IP."""
    from raven.tools.whois_client import WhoisClient
    result = WhoisClient().lookup(target)
    if json_out:
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if result.success and result.parsed:
            for k, v in result.parsed.items():
                typer.echo(f"  {k}: {v}")
        elif result.error:
            typer.echo(f"[error] {result.error}", err=True)
            raise typer.Exit(1)
        else:
            typer.echo(result.stdout)


@app.command("searchsploit")
def tools_searchsploit(
    query: str = typer.Option("", "--query", "-q", help="Keyword search"),
    cve: str = typer.Option("", "--cve", "-c", help="CVE ID e.g. CVE-2021-44228"),
    json_out: bool = typer.Option(False, "--json", help="Output raw JSON"),
):
    """Search Exploit-DB via searchsploit."""
    from raven.tools.exploitdb import SearchsploitAdapter
    if not query and not cve:
        typer.echo("[error] Provide --query or --cve", err=True)
        raise typer.Exit(1)
    adapter = SearchsploitAdapter()
    result = adapter.search_cve(cve) if cve else adapter.search_keyword(query)
    if json_out:
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if result.success:
            data = result.parsed or {}
            exploits = data.get("RESULTS_EXPLOIT", [])
            if not exploits:
                typer.echo("No exploits found.")
            for e in exploits:
                typer.echo(f"  [{e.get('EDB-ID','?')}] {e.get('Title','')}")
                typer.echo(f"       {e.get('Path','')}")
        else:
            typer.echo(f"[error] {result.error}", err=True)
            raise typer.Exit(1)


@app.command("ares")
def tools_ares(
    target: str = typer.Argument(..., help="Path to Solana program source directory"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json, md, html"),
    policy: str = typer.Option("", "--policy", help="Path to ares.toml policy config"),
    use_llm: bool = typer.Option(False, "--llm", help="Enable LLM-as-Judge enrichment"),
    output: str = typer.Option("", "--output", "-o", help="Write report to file"),
):
    """Run ARES-v3 deterministic static audit on a Solana smart contract."""
    from raven.tools.ares import AresAdapter
    adapter = AresAdapter()
    if not adapter.is_available():
        typer.echo(f"[error] ares binary not found.\n{adapter.install_hint}", err=True)
        raise typer.Exit(1)
    result = adapter.scan(target, fmt=fmt, policy=policy, use_llm=use_llm, output=output)
    if fmt == "json":
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if result.success:
            typer.echo(result.stdout)
        else:
            typer.echo(f"[error] {result.error}", err=True)
            raise typer.Exit(1)


@app.command("ebpf-ghidra")
def tools_ebpf_ghidra():
    """Check Ghidra + Solana eBPF extension installation status."""
    from raven.tools.ebpf_ghidra import EBPFGhidraSetup, INSTALL_HINT
    setup = EBPFGhidraSetup()
    result = setup.setup_status()
    typer.echo(json.dumps(result.to_dict(), indent=2))
    if not result.success:
        typer.echo(f"\nInstall instructions:\n{INSTALL_HINT}", err=True)
        raise typer.Exit(1)
    typer.echo("\n[✓] Ghidra + Solana eBPF extension ready.")


@app.command("run")
def tools_run(
    name: str = typer.Argument(..., help="Tool name e.g. whois, yara, jadx"),
    method: str = typer.Argument(..., help="Method to call e.g. lookup, scan"),
    kwargs: List[str] = typer.Argument(None, help="KEY=VALUE arguments"),
    json_out: bool = typer.Option(True, "--json/--no-json", help="Output as JSON"),
):
    """Generic tool method dispatcher.

    Example:
        raven tools run whois lookup target=example.com
        raven tools run yara scan rules_path=/tmp/rules target_path=/tmp/sample
    """
    # Parse KEY=VALUE pairs
    kw = {}
    for pair in (kwargs or []):
        if "=" not in pair:
            typer.echo(f"[error] expected KEY=VALUE, got: {pair!r}", err=True)
            raise typer.Exit(1)
        k, _, v = pair.partition("=")
        kw[k.strip()] = v.strip()

    # Resolve adapter
    _adapter_map = {
        "subfinder":   "raven.tools.projectdiscovery:SubfinderAdapter",
        "naabu":       "raven.tools.projectdiscovery:NaabuAdapter",
        "httpx":       "raven.tools.projectdiscovery:HttpxAdapter",
        "interactsh":  "raven.tools.projectdiscovery:InteractshAdapter",
        "exploitdb":   "raven.tools.exploitdb:SearchsploitAdapter",
        "recon_ng":    "raven.tools.recon_ng:ReconNgAdapter",
        "yara":        "raven.tools.yara_scan:YaraScanner",
        "jadx":        "raven.tools.jadx:JadxAdapter",
        "radare2":     "raven.tools.radare2:Radare2Adapter",
        "frida":       "raven.tools.frida:FridaAdapter",
        "volatility":  "raven.tools.volatility:VolatilityAdapter",
        "cyberchef":   "raven.tools.cyberchef:CyberchefAdapter",
        "whois":       "raven.tools.whois_client:WhoisClient",
        "ares":        "raven.tools.ares:AresAdapter",
        "ebpf_ghidra": "raven.tools.ebpf_ghidra:EBPFGhidraSetup",
    }

    spec = _adapter_map.get(name)
    if not spec:
        typer.echo(f"[error] Unknown tool: {name!r}. Available: {', '.join(_adapter_map)}", err=True)
        raise typer.Exit(1)

    import importlib
    mod_path, cls_name = spec.split(":")
    cls = getattr(importlib.import_module(mod_path), cls_name)
    instance = cls()

    fn = getattr(instance, method, None)
    if fn is None or not callable(fn):
        typer.echo(f"[error] {name!r} has no method {method!r}", err=True)
        raise typer.Exit(1)

    try:
        result = fn(**kw)
    except TypeError as exc:
        typer.echo(f"[error] bad arguments: {exc}", err=True)
        raise typer.Exit(1)

    if json_out:
        if hasattr(result, "to_dict"):
            typer.echo(json.dumps(result.to_dict(), indent=2))
        else:
            typer.echo(json.dumps(result, indent=2, default=str))
    else:
        typer.echo(str(result))
