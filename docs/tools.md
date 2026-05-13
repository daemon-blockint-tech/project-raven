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
| **ARES-v3** | `AresAdapter` | `scan(target)` · `benchmark()` · `list_classes()` | [daemon-blockint-tech/ARES-v3](https://github.com/daemon-blockint-tech/ARES-v3) |
| **eBPF-for-Ghidra** | `EBPFGhidraSetup` | `setup_status()` · `analyze_solana_so(path)` | [blastrock/Solana-eBPF-for-Ghidra](https://github.com/blastrock/Solana-eBPF-for-Ghidra) |

---

## Solana smart contract auditing

### ARES-v3

ARES-v3 is a deterministic static analysis framework for Solana smart contracts. It runs a 4-phase pipeline — regex extraction → AST parsing → taint analysis → deterministic judge — achieving **97% micro-averaged recall** and **0.94 F1** across 20 benchmark protocols with **zero API cost** and sub-5-second scans.

**Vulnerability classes detected:**

| Class | Description |
|---|---|
| `type-cosplay` | Account discriminator not validated → wrong account type accepted |
| `ownership-check` | Missing `owner == program_id` guard |
| `has-one-constraint` | Missing Anchor `has_one` constraint |
| `seeds-constraint` | PDA seeds not validated |
| `signer-authorization` | Missing `Signer` check → any caller accepted |
| `arbitrary-cpi` | `invoke()` without `program_id` validation |
| `initialization-frontrunning` | `init` accounts with predictable PDA can be front-run |
| `reentrancy-risk` | CPI back into the program before state write |
| `duplicate-mutable-accounts` | Same account passed twice as mutable |
| `arithmetic-overflow` | Unchecked integer arithmetic |
| `close-account` | Account closed without zeroing data |
| `account-reloading` | Stale account state after CPI |

**Install:**

```bash
git clone https://github.com/daemon-blockint-tech/ARES-v3
cd ARES-v3
cargo install --path crates/ares-cli
```

**Usage via Raven:**

```bash
# CLI
raven tools ares ./my_anchor_program
raven tools ares ./my_program --format md --output report.md
raven tools ares ./my_program --llm   # enable LLM-as-Judge

# REST API
curl -X POST /tools/ares/call \
  -d '{"method":"scan","kwargs":{"target":"./my_program","fmt":"json"}}'

# Agent (auto-selects tool when asked to audit a Solana program)
# Tool name: solana_audit
```

**Optional LLM-as-Judge:**

```bash
ares llm setup --provider openai --api-key sk-...
# or via Raven:
raven tools run ares setup_llm provider=openai api_key=sk-...
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `ARES_BINARY` | `ares` | Binary name / path |
| `ARES_TIMEOUT` | `120` | Max seconds per scan |
| `ARES_POLICY_FILE` | _(empty)_ | Default `ares.toml` policy path |

---

### Solana eBPF-for-Ghidra

A Ghidra processor module (Java + Sleigh) that adds support for decompiling compiled Solana programs (`.so` BPF ELF files). Pairs with the existing `GhidraAnalyzer` adapter.

**What it enables:**
- Load a compiled Solana `.so` into Ghidra and get full decompiled output
- Navigate the sBPF instruction set with type-annotated pseudo-C
- Use all Ghidra analysis passes (data-flow, call graph, symbol recovery) on Solana programs

**Install (Option A — Gradle build):**

```bash
git clone https://github.com/blastrock/Solana-eBPF-for-Ghidra
cd Solana-eBPF-for-Ghidra
GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle
# Then in Ghidra: File → Install Extensions → select the built .zip
```

**Install (Option B — pre-built release):**

Download from https://github.com/blastrock/Solana-eBPF-for-Ghidra/releases and install via `File → Install Extensions`.

**Check status via Raven:**

```bash
# CLI
raven tools ebpf-ghidra

# REST
curl /tools/ebpf_ghidra/call -d '{"method":"setup_status","kwargs":{}}'

# Agent tool name: ebpf_ghidra_status
```

**Decompile a Solana program:**

```bash
# REST
curl -X POST /tools/ebpf_ghidra/call \
  -d '{"method":"analyze_solana_so","kwargs":{"binary_path":"./program.so"}}'
```

**Known limitations (upstream):**
- Functions with >5 parameters may not decompile correctly (see `data/languages/eBPFSol.cspec`)
- Rebasing after import can misalign relocations — specify base address at import time

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

## ARES-v3 (Solana Static Auditor)

ARES-v3 is a deterministic static analyzer for Solana smart contracts (Anchor & Solitaire). It detects 12 critical vulnerability classes via AST parsing and taint analysis.

### Installation

Strategy A is used (installed natively on the host):
```bash
git clone https://github.com/daemon-blockint-tech/ARES-v3
cd ARES-v3
cargo install --path crates/ares-cli
```

*Note: For Docker deployments, a multi-stage Rust build can be used (adds ~1.5 GB), but native installation keeps the image lightweight.*

### Usage

**REST API:**
```bash
curl -X POST localhost:8000/tools/ares/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"method":"scan","kwargs":{"target":"./path/to/solana/program", "fmt":"json"}}'
```

**CLI:**
```bash
raven tools ares ./path/to/program           # json output
raven tools ares ./path/to/program --format md  # markdown
```

**TUI:**
```
/run ares scan target=./path/to/program
```

### Vulnerability Catalogue
- `type-cosplay`
- `ownership-check`
- `has-one-constraint`
- `seeds-constraint`
- `signer-authorization`
- `arbitrary-cpi`
- `initialization-frontrunning`
- `reentrancy-risk`
- `duplicate-mutable-accounts`
- `arithmetic-overflow`
- `close-account`
- `account-reloading`

---

## Solana-eBPF-for-Ghidra

A Ghidra processor module that enables decompression and decompilation of compiled Solana `.so` programs.

### Installation

1. Clone and build the extension:
```bash
git clone https://github.com/blastrock/Solana-eBPF-for-Ghidra
cd Solana-eBPF-for-Ghidra
GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle
```
2. In Ghidra, go to **File → Install Extensions**, click the plus icon, and select the `.zip` file generated in `dist/`.

### Usage

The `EBPFGhidraSetup` tool adapter validates the installation and wraps `analyzeHeadless` for Solana programs:

**CLI:**
```bash
raven tools ebpf-ghidra
```
**API:**
```bash
curl -X POST localhost:8000/tools/ebpf_ghidra/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"method":"analyze_solana_so","kwargs":{"binary_path":"./target/deploy/program.so"}}'
```
