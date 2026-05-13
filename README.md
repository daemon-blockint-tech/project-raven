<p align="center">
  <img src="logo/project-raven-logo-white.svg" alt="Project Raven" width="480" />
</p>

<p align="center">
  <strong>Autonomous Defense System — Multi-Provider AI · Zero-Day Detection · Proactive Threat Hunting</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/FastAPI-0.109-009688?style=flat-square" />
  <img src="https://img.shields.io/badge/AI-multi--provider-purple?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
</p>

---

## Overview

Project Raven transforms reactive security into proactive threat hunting by combining a
**runtime-switchable multi-provider AI layer**, ML anomaly detection, and automated kill-chain
planning. Run fully on-premise with LM Studio or Ollama — or swap to OpenAI, Anthropic,
OpenRouter, or Nous Research with a single command. No restart required.

## Key Features

- **Multi-Provider AI** — switch between LM Studio, OpenAI, Anthropic, OpenRouter, Ollama, Nous at runtime via CLI or REST API
- **Named Profiles** — save/load provider+model+key configurations as named profiles (`raven provider save work`)
- **Multi-Model LLM Orchestration** — three specialist models via `ModelOrchestrator`, role-routed by task type
- **LLM-Driven Threat Hunting** — hypothesis generation and kill-chain re-planning powered by any provider
- **Zero-Day Detection** — ensemble ML (IsolationForest + RandomForest) for novel attack patterns
- **Automated Kill-Chain Planning** — Incalmo-style declarative planning with MITRE ATT&CK alignment
- **Human-in-the-Loop** — approval gates before destructive stages (exploitation, lateral movement, exfiltration)
- **Tool Orchestration** — SSH, Bash, Nmap, Metasploit, Nuclei, Empire C2, Ghidra, Shodan
- **Automated Mitigation** — containment and remediation workflows

## AI Provider Support

Switch providers without restarting the server. Supports `provider:model` shorthand (inspired by Hermes Agent).

| Provider | Key Required | Example Models |
|---|---|---|
| `lmstudio` | ❌ local | `ibm/granite-4-micro`, `nvidia/nemotron-3-nano-4b` |
| `ollama` | ❌ local | `llama3.2`, `mistral`, `deepseek-r1` |
| `openai` | ✅ | `gpt-4o`, `gpt-4o-mini`, `o3-mini` |
| `openrouter` | ✅ | `nous/hermes-2-mixtral-8x7b`, `google/gemini-2.5-pro`, 300+ |
| `anthropic` | ✅ | `claude-opus-4-5`, `claude-3-5-sonnet-20241022` |
| `nous` | ✅ | `nous-hermes-2-mixtral-8x7b`, `hermes-3-llama-3.1-405b` |
| `opencode` | ✅ | — |

### Switching providers at runtime

```bash
# CLI
raven provider set openrouter --key sk-or-abc123 --model nous-hermes-2-mixtral-8x7b
raven model set anthropic:claude-3-5-sonnet-20241022   # provider:model shorthand
raven provider save work-profile
raven provider load work-profile

# REST API (server already running — no restart)
curl -X POST localhost:8000/ai/provider \
  -H "Content-Type: application/json" \
  -d '{"provider": "openrouter", "api_key": "sk-or-...", "model": "nous/hermes-2-mixtral-8x7b"}'

curl -X POST localhost:8000/ai/model \
  -d '{"model": "anthropic:claude-3-5-sonnet-20241022"}'
```

## LM Studio Model Setup (local default)

Raven orchestrates three specialist models on a single LM Studio instance (port 1234):

| Role | Model | Memory | Used For |
|------|-------|--------|----------|
| FAST | `ibm/granite-4-micro` | ~2.5 GB | JSON hypothesis generation, CVE lookup |
| REASON | `nvidia/nemotron-3-nano-4b` | ~3.5 GB | Kill-chain planning, complex analysis |
| VISION | `zai-org/glm-4.6v-flash` | ~5 GB | Screenshot / image evidence (on-demand) |

FAST and REASON stay resident. VISION is loaded on-demand and swaps out REASON temporarily.
Total budget fits within 16 GB unified memory (Apple M-series or equivalent).

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system design.

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install core dependencies
pip install -r requirements.txt

# Install CLI + Anthropic SDK (optional)
pip install -e ".[ai]"

# Copy and configure environment
cp .env.example .env
# Edit .env — set AI_PROVIDER and AI_API_KEY (or leave as lmstudio for local)
```

### Optional tool dependencies

| Tool | Purpose | Install |
|------|---------|---------|
| [LM Studio](https://lmstudio.ai) | Local LLM inference | Download installer |
| [Ollama](https://ollama.com) | Local model runner | `brew install ollama` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vuln scanning | `brew install nuclei` |
| [Empire](https://github.com/BC-SECURITY/Empire) | Post-exploitation C2 | See Empire docs |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Binary analysis | Download + JDK 21 |

## Quick Start

```bash
# Option A: Local (LM Studio — no API key)
# 1. Start LM Studio → load granite-4-micro and nemotron-3-nano-4b
# 2. Start Raven
uvicorn raven.api.main:app --host 0.0.0.0 --port 8000

# Option B: Cloud provider
uvicorn raven.api.main:app --host 0.0.0.0 --port 8000 &
raven provider set openrouter --key sk-or-... --model nous/hermes-2-mixtral-8x7b

# Check active provider
curl http://localhost:8000/ai/provider

# Check model orchestrator status
curl http://localhost:8000/ai/models/status

# Run a kill-chain exercise (requires HITL approval for destructive stages)
curl -X POST http://localhost:8000/hunt/killchain \
  -H "Content-Type: application/json" \
  -d '{"objective": "assess lateral movement risk", "target_network": "192.168.1.0/24"}'

# Approve / reject a pending destructive task
curl -X POST http://localhost:8000/hunt/killchain/approve
curl -X POST http://localhost:8000/hunt/killchain/reject
```

## Project Structure

```
raven/
├── ai/
│   ├── base.py            # BaseAIClient ABC + AIMessage + AIResponse + SUPPORTED_PROVIDERS
│   ├── factory.py         # create_client_from_config() — routes to correct adapter
│   ├── registry.py        # ProviderRegistry singleton — hot-swap + named profiles
│   ├── model_orchestrator.py  # Multi-role LM Studio orchestrator (FAST/REASON/VISION)
│   ├── lmstudio_client.py # Backward-compat re-export shim
│   └── providers/
│       ├── lmstudio.py         # LM Studio native v1 API + OpenAI-compat fallback
│       ├── openai_compat.py    # OpenAI / OpenRouter / Ollama / Nous / OpenCode
│       └── anthropic_provider.py  # Anthropic native SDK
├── api/              # FastAPI endpoints (includes /ai/provider runtime switch)
├── cli/
│   ├── main.py            # `raven` CLI entry point (typer)
│   └── commands/
│       ├── provider.py    # raven provider set/save/load/list/delete/providers
│       └── model.py       # raven model set/list/status
├── core/             # ThreatDetector, AnomalyDetector, BehavioralProfiler
├── hunters/          # HypothesisGenerator, AutomatedInvestigator, KillChainPlanner
├── ml/               # ZeroDayDetector, BehavioralAnalyzer, CVEMatcher, ...
├── tools/            # SSH, Bash, Nmap, Metasploit, Nuclei, Empire, Ghidra, Shodan
├── mitigation/       # ContainmentActions, RemediationEngine, ResponseOrchestrator
├── monitoring/       # MetricsCollector, AlertManager, DashboardAPI
└── config/           # Settings and environment (pydantic-settings)
deployment/
├── lmstudio.service  # systemd unit for LM Studio daemon
└── raven.service     # systemd unit for Raven API
```

## API Endpoints

### AI Provider (runtime switch)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/ai/provider` | Active provider status |
| `POST` | `/ai/provider` | **Hot-swap provider** (no restart) |
| `POST` | `/ai/model` | Change model (`provider:model` shorthand supported) |
| `GET` | `/ai/providers` | List all supported providers |
| `GET` | `/ai/provider/profiles` | List saved profiles |
| `POST` | `/ai/provider/profiles/{name}` | Save current config as profile |
| `PUT` | `/ai/provider/profiles/{name}` | Load a saved profile |
| `DELETE` | `/ai/provider/profiles/{name}` | Delete a profile |

### Threat Hunting & Analysis

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/ai/status` | Active provider reachability + loaded models |
| `GET` | `/ai/models/status` | Specialist model roles (FAST/REASON/VISION) |
| `POST` | `/ai/analyze` | Code security analysis via active LLM |
| `POST` | `/ai/hypothesis` | Generate threat hunting hypothesis |
| `POST` | `/ai/validate` | Validate vulnerability finding |
| `POST` | `/hunt` | Run threat hunting session |
| `POST` | `/hunt/killchain` | Start autonomous kill-chain exercise |
| `POST` | `/hunt/killchain/approve` | Approve pending HITL task |
| `POST` | `/hunt/killchain/reject` | Reject pending HITL task |
| `POST` | `/investigate/target` | Set SSH investigation target |
| `GET` | `/metrics` | Prometheus-compatible metrics |
| `GET` | `/alerts` | Active security alerts |

## License

MIT License — see [LICENSE](LICENSE) for details.