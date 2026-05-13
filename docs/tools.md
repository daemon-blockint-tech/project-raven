# External Security Tools

Raven integrates 18+ external security tools through a unified subprocess-adapter framework rooted at `raven/tools/adapter_base.py`.

## Adapter framework

Every tool inherits from `ToolAdapter` and returns a uniform `ToolResult` envelope:

```python
@dataclass
class ToolResult:
    tool: str
    success: bool
    target: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    execution_time: float = 0.0
    parsed: Any = None        # tool-specific structured output
    error: Optional[str] = None
    cmd: str = ""
```

Two safety nets sit in front of every `_run()` call:

1. **`is_safe_arg`** — rejects any argument containing shell metacharacters (`;` `|` `&` `>` `<` `` ` `` `$()` `\n`). Allowed: alnum, dot, slash, colon, dash, underscore, comma, equals, at, plus, percent, tilde, brackets, hash.
2. **Timeout + graceful errors** — `subprocess.TimeoutExpired` and `FileNotFoundError` become structured `ToolResult` failures with an `install_hint`, never an unhandled exception.

Every invocation increments `raven_tool_invocations_total{tool, outcome}`.

## Integrated tools

| Tool | Adapter | Method examples | Source |
|---|---|---|---|
| Subfinder | `SubfinderAdapter` | `enumerate(domain)` | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| Naabu | `NaabuAdapter` | `scan(target, ports, rate)` | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) |
| httpx | `HttpxAdapter` | `probe(targets)` | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| Interactsh | `InteractshAdapter` | `generate_payloads(count)` | [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) |
| Exploit-DB | `SearchsploitAdapter` | `search(query)` · `by_cve(cve)` · `get_path(edb_id)` | [exploit-database/exploitdb](https://gitlab.com/exploit-database/exploitdb) |
| recon-ng | `ReconNgAdapter` | `run_module(name, options, workspace)` | [pkg-security-team/recon-ng](https://salsa.debian.org/pkg-security-team/recon-ng) |
| YARA | `YaraScanner` | `scan_with_rules(rules, target)` (Python module or CLI fallback) | [VirusTotal/yara](https://github.com/VirusTotal/yara) |
| Jadx | `JadxAdapter` | `decompile(apk_or_dex)` | [kalilinux/jadx](https://gitlab.com/kalilinux/packages/jadx) |
| radare2 | `Radare2Adapter` | `analyze(bin)` · `functions(bin)` · `decompile(bin, fn)` (uses `pdg` via r2ghidra if installed) | [radareorg/radare2](https://github.com/radareorg/radare2) |
| Frida | `FridaAdapter` | `list_devices()` · `trace_apis(process, patterns, duration)` | [frida/frida](https://github.com/frida/frida) |
| Volatility 3 | `VolatilityAdapter` | `run_plugin(image, plugin, args)` (plugin allowlisted) | [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) |
| CyberChef | `CyberchefAdapter` | `bake(input, recipe)` · `magic(input)` (HTTP to `cyberchef-server`) | [gchq/CyberChef](https://github.com/gchq/CyberChef) |
| Shodan | (existing) `ShodanClient` | `search`, `enrich_threat_indicator` | [achillean/shodan-python](https://github.com/achillean/shodan-python) |
| Metasploit | (existing) `MetasploitIntegration` | RPC | [kalilinux/metasploit-framework](https://gitlab.com/kalilinux/packages/metasploit-framework) |
| Nuclei | (existing) `NucleiScanner` | CLI | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| Ghidra | (existing) `GhidraAnalyzer` + MCP | analyzeHeadless | [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) |
| nmap | (existing) `NmapScanner` | python-nmap | upstream nmap |
| Empire | (existing) `EmpireClient` | REST | [BC-SECURITY/Empire](https://github.com/BC-SECURITY/Empire) |

### Tools requiring host-side install

Most adapters call binaries on `PATH`. The expected install paths (or pip packages) ship in each adapter's `install_hint` attribute and are surfaced in failure messages when the binary is missing — so a 500 from Raven points the operator straight at the fix.

### x64dbg (Windows-only)

Stubbed at `raven/tools/x64dbg_client.py` — operators running Windows targets connect Raven to an x64dbg instance via the upstream MCP/HTTP bridge. No subprocess adapter ships because Raven is Linux-first.

## MCP server registry

`raven/tools/mcp_registry.py` declares known MCP backends so the planner can route reverse-engineering work to the right server:

| Server | Transport | Capabilities |
|---|---|---|
| `ghidra-mcp` ([13bm/GhidraMCP](https://github.com/13bm/GhidraMCP)) | stdio | `decompile_function`, `list_functions`, `list_imports`, `list_strings`, `follow_xref` |
| `radare2-mcp` ([radareorg/radare2-mcp](https://github.com/radareorg/radare2-mcp)) | stdio | `open_binary`, `analyze`, `decompile_function`, `search_string`, `search_bytes` |

Operators can register additional servers via `mcp_registry().register(MCPServer(...))`.

## REST endpoints

```
GET  /tools                 availability matrix (every adapter)
GET  /tools/mcp             list MCP servers + capability index
POST /tools/{name}/run      {"method": "...", "kwargs": {...}}     (operator + audited)
```

Example:

```bash
curl -X POST localhost:8000/tools/subfinder/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"method":"enumerate","kwargs":{"domain":"example.com"}}'
```

## Design inspirations

| Source | Used for |
|---|---|
| [ProjectDiscovery/pd-agent](https://github.com/projectdiscovery/pd-agent) | Subprocess + JSONL parse + result-upload pattern |
| [mrphrazer/agentic-malware-analysis](https://github.com/mrphrazer/agentic-malware-analysis) | Multi-phase orchestrator + MCP backend selection + bundled YARA rules |
