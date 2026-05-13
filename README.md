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

Raven is built around **Compositional Defense Pipelines (CDP)** — an architectural primitive in which every LLM-emitted finding must be grounded in a deterministic tool oracle, a classical-ML detector, or an explicitly scored hypothesis. See [`docs/methodology.md`](docs/methodology.md) for the concise summary or the full [**Whitepaper**](docs/Whitepaper/README.md) for the formal grammar, grounding theorem, and empirical evaluation.

## Key Features

**AI layer**
- **Multi-provider AI** — LM Studio / OpenAI / Anthropic / OpenRouter / Ollama / Nous / Tinker, swap at runtime via CLI or REST
- **Named profiles** — save/load provider + model + key configurations (`raven provider save work`)
- **Three-role orchestrator** — FAST / REASON / VISION models, routed by task type
- **System prompt manager** — load `RAVEN_SYSTEM_PROMPT.md` once, auto-injected into every call

**Defensive AI primitives (Hermes Agent-inspired)**
- **Approval gate** — `manual` / `smart` / `off` modes for destructive actions, with an `UNRECOVERABLE_BLOCKLIST` floor that *nothing* can bypass (not YOLO, not admin)
- **Smart triage** — auxiliary LLM (`ModelOrchestrator.FAST`) auto-approves benign commands, escalates ambiguous ones
- **Jailbreak detector** — 8 attack families fingerprinted on every `/ai/*` inbound; `Parseltongue` decodes 33 obfuscation techniques first
- **Provider hardness test** — score the active provider's jailbreak resistance 0–10
- **Offensive Godmode** — triple-gated red-team capability (default off, admin+token+sandbox required)

**Threat hunting & detection**
- **LLM-driven hypothesis generation** — variant analysis + precondition reasoning + algorithm-semantic mining (Anthropic 0-days techniques)
- **Zero-day detection** — IsolationForest + RandomForest ensemble for novel patterns
- **Kill-chain planning** — Incalmo-style declarative tasks aligned to MITRE ATT&CK
- **Human-in-the-loop** — approval gates on exploitation, lateral movement, exfiltration, privilege escalation, post-exploitation

**Self-improvement (Tinker)**
- **Continual learning loop** — mine audit log + CyberGym + kill-chain → JSONL → managed LoRA fine-tune → A/B test → auto-promote
- **5 dataset builders** with PII scrubbing (`from_audit_log` / `from_cybergym` / `from_killchain` / `from_redteam` / `distillation`)
- **A/B router** — Bernoulli traffic split, auto-promote at 95% win rate, auto-rollback on regression
- **Mock-friendly** — runs offline via `MockTinkerClient` until Tinker beta access lands

**Production hardening**
- **JWT auth + 3-tier RBAC** (viewer / operator / admin), Argon2id passwords, refresh-token rotation, revocation list
- **Audit log** — every authenticated mutation recorded with actor, request ID, latency, status
- **Structured logs + OTel tracing + Prometheus metrics** (`/metrics` exposition + 20+ counters/gauges/histograms)
- **Helm chart** with HPA (3–12 replicas), PodDisruptionBudget, NetworkPolicy, ServiceMonitor, non-root + read-only rootfs
- **Prod safety guard** refuses to start with default `SECRET_KEY`, `APPROVAL_MODE=off`, wildcard CORS, or `OFFENSIVE_REDTEAM_ENABLED` without a session token

**Tool orchestration (20+ adapters under unified `ToolAdapter` interface)**
- **Smart-contract auditing** — **ARES-v3** (deterministic Solana static auditor, 97 % recall) · **Solana-eBPF-for-Ghidra** (compiled `.so` decompilation)
- **Binary analysis** — Ghidra (analyzeHeadless), radare2 (+ r2ghidra), jadx, Frida, Volatility 3
- **Malware** — YARA family signatures
- **Recon** — subfinder · naabu · httpx · interactsh · nuclei · recon-ng · whois · Shodan
- **Exploitation** — Metasploit · Empire C2 · searchsploit
- **Network** — Nmap, **strict SSH** (`RejectPolicy` + known_hosts), **safe Bash** (`shell=False` default)
- **Data ops** — CyberChef

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
| `tinker` | ✅ | Raven-trained LoRA fine-tunes (Llama-3.1, Qwen-2.5) |

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
# 1. Configure (minimum: a strong SECRET_KEY)
cp .env.example .env
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
echo "BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -base64 24)" >> .env

# 2. Local AI (LM Studio) — load granite-4-micro + nemotron-3-nano-4b, then:
uvicorn raven.api.main:app --host 0.0.0.0 --port 8000

# 3. Login → grab access token
TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"$BOOTSTRAP_ADMIN_PASSWORD\"}" \
  | jq -r .access_token)

# 4. Run a kill-chain exercise (HITL-gated)
curl -X POST localhost:8000/hunt/killchain \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"objective":"assess lateral movement risk","target_network":"192.168.1.0/24"}'

# 5. Test provider hardness
curl -X POST localhost:8000/redteam/hardness \
  -H "Authorization: Bearer $TOKEN" -d '{}'

# 6. Train a Raven-specialist model (offline mock by default)
raven train dataset-build --source audit --out data/audit.jsonl
raven train job-start --recipe distill --dataset-id <id>
raven train model-eval <model_id>
raven train model-promote <model_id>
```

For production deployment via Helm on Kubernetes see [DEPLOYMENT.md](DEPLOYMENT.md).

## Project Structure

```
raven/
├── ai/                   Multi-provider AI runtime
│   ├── base.py             BaseAIClient ABC + SUPPORTED_PROVIDERS
│   ├── factory.py          create_client_from_config() router
│   ├── registry.py         ProviderRegistry singleton — hot-swap + profiles
│   ├── model_orchestrator.py  FAST / REASON / VISION role routing
│   └── providers/          lmstudio · openai_compat · anthropic · tinker
├── auth/                 JWT + RBAC (viewer/operator/admin) + Argon2id
├── approval/             Hermes-style approval gate + UNRECOVERABLE_BLOCKLIST
├── redteam/              Jailbreak detector + Parseltongue + hardness + gated godmode
├── training/             Tinker continual-learning subsystem
│   ├── client.py           Real Tinker SDK + MockTinkerClient
│   ├── datasets/           5 builders with PII scrubbing
│   ├── jobs/               DistillJob · SFTJob · CodeRLJob
│   ├── registry.py         ModelVersion + TrainingJob + ABTestRun store
│   ├── abtest.py           Bernoulli router + auto-promote/rollback
│   └── eval.py             Hardness + canary + CyberGym smoke
├── audit/                Mutation audit log + middleware (X-Request-ID)
├── observability/        structlog + OpenTelemetry + Prometheus metrics
├── api/                  FastAPI app + routers per subsystem
├── cli/                  `raven` Typer CLI (provider/model/prompt/approval/redteam/train)
├── core/                 ThreatDetector + AnomalyDetector + BehavioralProfiler
├── hunters/              Hypothesis + Investigation + KillChainPlanner (Incalmo)
├── ml/                   ZeroDayDetector + VariantAnalyzer (ZeroDayBench)
├── tools/                SSH (RejectPolicy) · Bash (no shell) · Nmap · Nuclei · Empire · Ghidra · Shodan
├── mitigation/           Containment + Remediation + ResponseOrchestrator
└── config/               Pydantic-settings with prod-mode safety guard
deployment/
├── helm/raven/             Helm chart (HPA + PDB + NetworkPolicy + ServiceMonitor)
├── lmstudio.service        systemd unit for local dev
└── raven.service           systemd unit for local dev
docs/
├── approval-and-redteam.md
├── training.md
├── benchmark.md          (planned — CyberGym integration)
└── runbooks/
```

## API Endpoints

All mutating routes require JWT bearer + role. Read routes accept any authenticated user.

### Authentication

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/auth/login` | — | username + password → access + refresh tokens |
| `POST` | `/auth/refresh` | — | refresh token → new pair |
| `POST` | `/auth/logout` | viewer | revoke refresh token |
| `GET` | `/auth/me` | viewer | current user info |

### AI provider runtime switching

| Method | Path | Role |
|---|---|---|
| `GET`/`POST` | `/ai/provider` | viewer / admin |
| `POST` | `/ai/model` | admin |
| `GET`/`POST`/`PUT`/`DELETE` | `/ai/provider/profiles[/{name}]` | viewer / admin |
| `GET`/`POST`/`DELETE` | `/ai/system-prompt` | viewer / admin |

### Threat hunting

| Method | Path | Role |
|---|---|---|
| `POST` | `/analyze` `/hunt` `/hunt/variant` `/hunt/code` `/investigate/target` | operator |
| `POST` | `/hunt/killchain` | operator |
| `POST` | `/hunt/killchain/approve` `/hunt/killchain/reject` | admin |
| `POST` | `/mitigate` | operator |

### Approval gate (Hermes-style)

| Method | Path | Role |
|---|---|---|
| `GET`/`PATCH` | `/approval/mode` | viewer / admin |
| `GET` | `/approval/decisions` | viewer |
| `POST` | `/approval/decisions/{id}/{approve,deny}` | operator |
| `GET`/`POST`/`DELETE` | `/approval/allowlist[/{pattern}]` | viewer / admin |

### Red-team

| Method | Path | Role |
|---|---|---|
| `POST` | `/redteam/scan` `/redteam/decode` | operator |
| `POST` | `/redteam/hardness` | admin |
| `POST` | `/redteam/godmode` | admin + `X-Raven-Authorization-Token` |

### Training (Tinker)

| Method | Path | Role |
|---|---|---|
| `GET` | `/training/tinker/status` `/training/datasets` `/training/jobs` `/training/models` | viewer |
| `POST` | `/training/datasets` `/training/jobs[/{id}/cancel|finalize]` | admin |
| `POST` | `/training/models/{id}/{eval,promote,rollback}` | admin |
| `POST`/`GET` | `/training/abtest[/{id}/{record,stop}]` | admin / viewer |

### Operational

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` `/health/ready` `/health/startup` | K8s probes |
| `GET` | `/metrics` | Prometheus exposition |
| `GET` | `/audit/log` | Recent mutation audit entries (admin) |

## CLI

```bash
raven version
raven provider {set|status|list|save|load|delete|providers}
raven model {set|list|status}
raven prompt {show|set|load|clear}
raven approval {mode|status|allow|forget|test}
raven redteam {scan|decode|hardness|godmode}
raven train {status|dataset-build|dataset-list|job-start|job-status|job-list|
             model-list|model-eval|model-promote|model-rollback}
```

## Security

| Hardening | Reference |
|---|---|
| Default `SECRET_KEY` refused in **every** environment | `_enforce_secret_key_floor` |
| `APPROVAL_MODE=off` (YOLO) refused in prod | `_enforce_prod_safety` |
| Wildcard CORS refused in prod | `_enforce_prod_safety` |
| `pickle`/`joblib` model loading gated by `ALLOW_PICKLE_MODELS` + `MODEL_PATH` jail | `raven/core/anomaly_detector.py`, `raven/ml/zero_day_detector.py` |
| `BashExecutor` defaults to `shell=False`; opt-in `allow_shell=True` | `raven/tools/bash_executor.py` |
| Patch IDs regex-validated + `shlex.quote`-wrapped | `raven/mitigation/remediation_engine.py` |
| PIDs coerced to positive `int` | `raven/mitigation/containment_actions.py` |
| SSH `paramiko.RejectPolicy` + operator-supplied `known_hosts` | `raven/tools/ssh_manager.py` |
| Provider `base_url` allowlist | `raven/api/main.py` |
| Scan paths jailed to `SCAN_ROOT` | `raven/api/main.py` |
| Jailbreak detector on every `/ai/*` inbound | `raven/redteam/middleware.py` |

Security policy + threat model: [SECURITY.md](SECURITY.md).
Vulnerability disclosures: see `.windsurf/automation-memory/project-raven---flagged-vulnerabilities.json`.

## License

MIT License — see [LICENSE](LICENSE) for details.
