"""Slash-command dispatcher for the Raven TUI.

Each handler takes ``(tui, args: List[str])`` and returns either:
  * ``None``       — handled, continue REPL
  * ``"exit"``     — exit the TUI
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from rich.table import Table


@dataclass
class SlashCommand:
    name: str
    summary: str
    handler: Callable[[Any, List[str]], Optional[str]]
    aliases: tuple = ()


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _cmd_help(tui, args):
    table = Table(title="Slash Commands", show_header=True, header_style="bold magenta")
    table.add_column("Command", style="cyan", no_wrap=True)
    table.add_column("Description")
    for cmd in REGISTRY.values():
        if cmd.aliases:
            name = f"/{cmd.name}  ({', '.join('/' + a for a in cmd.aliases)})"
        else:
            name = f"/{cmd.name}"
        table.add_row(name, cmd.summary)
    tui.console.print(table)
    return None


def _cmd_clear(tui, args):
    tui.agent.clear_history()
    tui.console.clear()
    tui._steps_total = 0
    tui.console.print("[dim]✓ Conversation cleared.[/]")
    return None


def _cmd_history(tui, args):
    msgs = tui.agent.get_messages()
    if not msgs:
        tui.console.print("[dim]No history yet.[/]")
        return None
    for m in msgs:
        role_color = {"user": "cyan", "assistant": "#a78bfa", "tool": "yellow"}.get(m.role, "white")
        tui.console.print(f"[bold {role_color}]{m.role}[/]: {m.content[:200]}")
    return None


def _cmd_model(tui, args):
    if not args:
        tui.console.print(f"[dim]Current model:[/] [bold]{tui.agent.model}[/]")
        return None
    new_model = args[0]
    tui.agent.model = new_model
    tui.agent._client_config["ai_model"] = new_model
    tui.console.print(f"[green]✓[/] Switched to model: [bold]{new_model}[/]")
    return None


def _cmd_provider(tui, args):
    from raven.ai.registry import ProviderRegistry
    if not args:
        st = ProviderRegistry.get_instance().status()
        tui.console.print(f"[dim]Current provider:[/] [bold]{st['provider']}[/]  model: {st['model']}")
        return None
    try:
        ProviderRegistry.get_instance().switch(provider=args[0])
        tui.console.print(f"[green]✓[/] Switched to provider: [bold]{args[0]}[/]")
    except ValueError as e:
        tui.console.print(f"[red]✗[/] {e}")
    return None


def _cmd_tools(tui, args):
    table = Table(title="Agent Tools", show_header=True, header_style="bold magenta")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Params", style="dim")
    for name, t in tui.agent._tools.items():
        props = list(t.parameters.get("properties", {}).keys())
        table.add_row(name, t.description, ", ".join(props))
    tui.console.print(table)
    return None


def _cmd_run(tui, args):
    """Invoke a tool method directly, bypassing the LLM.

    Usage: /run <tool> <method> KEY=VAL ...
    """
    if len(args) < 2:
        tui.console.print("[red]Usage: /run <tool> <method> KEY=VAL …[/]")
        return None

    name, method, *kvs = args
    kw = {}
    for pair in kvs:
        if "=" not in pair:
            tui.console.print(f"[red]Bad arg: {pair!r} (expected KEY=VALUE)[/]")
            return None
        k, _, v = pair.partition("=")
        kw[k.strip()] = v.strip()

    _map = {
        "whois":      "raven.tools.whois_client:WhoisClient",
        "ares":       "raven.tools.ares:AresAdapter",
        "ebpf_ghidra":"raven.tools.ebpf_ghidra:EBPFGhidraSetup",
        "exploitdb":  "raven.tools.exploitdb:SearchsploitAdapter",
        "yara":       "raven.tools.yara_scan:YaraScanner",
        "subfinder":  "raven.tools.projectdiscovery:SubfinderAdapter",
        "naabu":      "raven.tools.projectdiscovery:NaabuAdapter",
        "httpx":      "raven.tools.projectdiscovery:HttpxAdapter",
        "radare2":    "raven.tools.radare2:Radare2Adapter",
        "volatility": "raven.tools.volatility:VolatilityAdapter",
        "cyberchef":  "raven.tools.cyberchef:CyberchefAdapter",
        "jadx":       "raven.tools.jadx:JadxAdapter",
        "frida":      "raven.tools.frida:FridaAdapter",
        "recon_ng":   "raven.tools.recon_ng:ReconNgAdapter",
    }

    spec = _map.get(name)
    if not spec:
        tui.console.print(f"[red]Unknown tool: {name!r}.  Try /tools.[/]")
        return None

    import importlib
    mod, cls = spec.split(":")
    try:
        adapter = getattr(importlib.import_module(mod), cls)()
        fn = getattr(adapter, method, None)
        if not callable(fn):
            tui.console.print(f"[red]{name!r} has no method {method!r}[/]")
            return None
        result = fn(**kw)
        if hasattr(result, "to_dict"):
            result = result.to_dict()
        tui.console.print_json(data=result, default=str)
    except Exception as exc:
        tui.console.print(f"[red]✗ {type(exc).__name__}: {exc}[/]")
    return None


def _cmd_save(tui, args):
    if not args:
        tui.console.print("[red]Usage: /save <name>[/]")
        return None
    from pathlib import Path
    name = args[0]
    folder = Path.home() / ".raven" / "tui_sessions"
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / f"{name}.json"
    payload = {
        "model": tui.agent.model,
        "messages": [
            {"role": m.role, "content": m.content}
            for m in tui.agent.get_messages()
        ],
    }
    out.write_text(json.dumps(payload, indent=2))
    tui.console.print(f"[green]✓[/] Saved session → [dim]{out}[/]")
    return None


def _cmd_load(tui, args):
    if not args:
        tui.console.print("[red]Usage: /load <name>[/]")
        return None
    from pathlib import Path
    from raven.ai.openrouter_agent import AgentMessage
    name = args[0]
    path = Path.home() / ".raven" / "tui_sessions" / f"{name}.json"
    if not path.exists():
        tui.console.print(f"[red]No session named {name!r}.[/]")
        return None
    data = json.loads(path.read_text())
    tui.agent.clear_history()
    for m in data.get("messages", []):
        tui.agent._history.append(AgentMessage(role=m["role"], content=m["content"]))
    tui.console.print(f"[green]✓[/] Loaded {len(data['messages'])} messages from [dim]{path}[/]")
    return None


def _cmd_exit(tui, args):
    return "exit"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

REGISTRY: Dict[str, SlashCommand] = {
    "help":     SlashCommand("help",     "Show this list of slash commands.", _cmd_help, aliases=("?",)),
    "clear":    SlashCommand("clear",    "Clear conversation history + screen.", _cmd_clear),
    "history":  SlashCommand("history",  "Print conversation transcript.", _cmd_history),
    "model":    SlashCommand("model",    "Show or switch the model (/model <name>).", _cmd_model),
    "provider": SlashCommand("provider", "Show or switch provider (/provider <name>).", _cmd_provider),
    "tools":    SlashCommand("tools",    "List registered agent tools.", _cmd_tools),
    "run":      SlashCommand("run",      "Invoke a tool directly (/run <tool> <method> K=V).", _cmd_run),
    "save":     SlashCommand("save",     "Save current session (/save <name>).", _cmd_save),
    "load":     SlashCommand("load",     "Load a saved session (/load <name>).", _cmd_load),
    "exit":     SlashCommand("exit",     "Exit the TUI.", _cmd_exit, aliases=("quit", "q")),
}


# Build alias index
_ALIASES: Dict[str, str] = {}
for _cmd in REGISTRY.values():
    for _a in _cmd.aliases:
        _ALIASES[_a] = _cmd.name


def dispatch(tui, raw: str) -> Optional[str]:
    """Parse and execute a slash-command string. Returns ``"exit"`` to quit."""
    raw = raw.lstrip("/").strip()
    if not raw:
        return None
    try:
        parts = shlex.split(raw)
    except ValueError:
        parts = raw.split()
    head, *rest = parts
    name = _ALIASES.get(head, head)
    cmd = REGISTRY.get(name)
    if cmd is None:
        tui.console.print(f"[red]Unknown command:[/] /{head}.  Try /help.")
        return None
    return cmd.handler(tui, rest)
