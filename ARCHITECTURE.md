<p align="center">
  <img src="logo/project-raven-logo-white.svg" alt="Project Raven" width="420" />
</p>

# Project Raven — Architecture

## Overview
Project Raven is an ML/AI-powered autonomous defense system that transforms reactive security into proactive threat hunting, detecting and mitigating zero-day threats before they reach critical targets. The AI layer is **runtime-switchable** — operators can hot-swap between local and cloud LLM providers without restarting the server.

## Core Components

### 1. **Multi-Provider AI Layer**

The AI layer is a provider-agnostic abstraction that can hot-swap LLM backends at runtime without restarting the server. Pattern inspired by [Hermes Agent](https://github.com/NousResearch/hermes-agent) (`provider:model` shorthand) and [Claude Code](https://github.com/anthropics/claude-code) (in-session `/model` switching).

```
raven/ai/
├── base.py              BaseAIClient (ABC) + AIMessage + AIResponse + SUPPORTED_PROVIDERS
├── factory.py           create_client_from_config() — routes to correct adapter
├── registry.py          ProviderRegistry singleton — thread-safe hot-swap + named profiles
├── model_orchestrator.py  Multi-role orchestrator: FAST / REASON / VISION
├── lmstudio_client.py   Backward-compat shim → raven.ai.providers.lmstudio
└── providers/
    ├── lmstudio.py          LM Studio native v1 API + OpenAI-compat fallback
    ├── openai_compat.py     OpenAI / OpenRouter / Ollama / Nous / OpenCode (single adapter)
    └── anthropic_provider.py  Anthropic native SDK (graceful degradation if not installed)
```

**Supported providers:**

| Provider | Transport | Key |
|---|---|---|
| `lmstudio` | LM Studio native v1 REST | — |
| `openai` | OpenAI-compat | ✅ |
| `openrouter` | OpenAI-compat | ✅ |
| `anthropic` | Anthropic SDK | ✅ |
| `ollama` | OpenAI-compat | — |
| `opencode` | OpenAI-compat | ✅ |
| `nous` | OpenAI-compat | ✅ |

**Runtime switching:**
```bash
# CLI (profile: ~/.raven/profiles/<name>.json, mode 600)
raven provider set openrouter --key sk-or-... --model nous/hermes-2-mixtral-8x7b
raven model set anthropic:claude-3-5-sonnet-20241022
raven provider save work-profile && raven provider load work-profile

# REST (no restart)
POST /ai/provider   {"provider":"openrouter","api_key":"sk-or-..."}
POST /ai/model      {"model":"anthropic:claude-opus-4-5"}
PUT  /ai/provider/profiles/work-profile
```

### 2. **Threat Detection Engine** (ML/AI Core)
- **Anomaly Detection**: Isolation Forest + Autoencoders for behavioral pattern analysis
- **Signature-Based Detection**: Known threat pattern matching
- **Zero-Day Prediction**: Ensemble ML (IsolationForest + RandomForest) for novel threats
- **Behavioral Profiling**: Baseline establishment + deviation flagging

### 3. **Tool Orchestration Layer**
- **SSH Manager**: Secure remote command execution across infrastructure
- **Bash Automation**: Script execution for response actions
- **Metasploit Integration**: Vulnerability scanning and exploitation testing
- **NMAP Integration**: Network discovery and port scanning
- **Nuclei**: Template-based vulnerability scanning
- **Empire C2**: Post-exploitation framework integration
- **Ghidra**: Headless binary analysis via subprocess
- **Shodan**: Internet-facing host intelligence

### 4. **Proactive Threat Hunting Module**
- **Hypothesis Generation**: AI-driven threat hypothesis creation via `BaseAIClient.generate_hypothesis()`
- **Automated Investigation**: Autonomous evidence gathering
- **Kill-Chain Planning**: Incalmo-style declarative planning with MITRE ATT&CK alignment
- **Human-in-the-Loop**: Approval gates before destructive stages

### 5. **Zero-Day Detection System**
- **Behavioral Analysis**: Detect unknown patterns through ML
- **Memory Forensics**: RAM analysis for in-memory attacks
- **Network Telemetry**: Deep packet inspection and flow analysis

### 6. **Automated Mitigation Response**
- **Containment Actions**: Isolate compromised systems
- **Patch Deployment**: Automated vulnerability remediation
- **Configuration Hardening**: Dynamic security rule updates
- **Incident Response**: Coordinated multi-step response workflows

### 7. **Monitoring & Dashboard**
- **Alert Management**: Prioritized and contextualized alerts
- **Metrics Dashboard**: Prometheus-compatible metrics
- **Audit Trail**: Complete logging of all actions

## Data Flow

```
┌─────────────────────────────────────────────────────────┐
│                      Data Sources                        │
│              (Logs, Network, Endpoints)                  │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  Ingestion & Normalization               │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  ML/AI Engine                            │
│   Anomaly Detection · Zero-Day Prediction · Profiling   │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│               Multi-Provider AI Layer                    │
│  ┌────────────────────────────────────────────────────┐ │
│  │              ProviderRegistry (singleton)           │ │
│  │   hot-swap · named profiles · thread-safe          │ │
│  └──────────────────────┬─────────────────────────────┘ │
│         ┌───────────────┼──────────────────┐            │
│    LM Studio      OpenRouter / OpenAI    Anthropic       │
│    Ollama             Nous                 …             │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Threat Hunting                        │
│       Hypothesis · Investigation · Kill-Chain            │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Decision Engine                        │
│              Risk Scoring · Response Plan                │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  Tool Orchestration                      │
│      SSH · Bash · Metasploit · Nmap · Ghidra · Shodan   │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                     Mitigation                          │
│           Containment · Remediation · Hardening         │
└─────────────────────────────────────────────────────────┘
```

## Technology Stack

### Core Framework
- **Language**: Python 3.11+
- **ML Framework**: PyTorch, scikit-learn, TensorFlow
- **API**: FastAPI for REST endpoints
- **CLI**: Typer (`raven provider`, `raven model`)
- **Task Queue**: Celery with Redis
- **Database**: PostgreSQL + TimescaleDB for time-series data

### AI / LLM
- **Local inference**: LM Studio (native v1 API), Ollama (OpenAI-compat)
- **Cloud**: OpenAI, Anthropic (native SDK), OpenRouter (300+ models), Nous Research
- **Abstraction**: `BaseAIClient` ABC — all providers share the same interface
- **Hot-swap**: `ProviderRegistry` singleton — `POST /ai/provider` or `raven provider set`
- **Profiles**: `~/.raven/profiles/<name>.json` (mode 600)

### Security Tools
- **NMAP**: Network scanning and discovery
- **Metasploit**: Vulnerability assessment
- **Nuclei**: Template-based CVE scanning
- **Empire C2**: Post-exploitation framework
- **Ghidra**: Headless binary analysis
- **Shodan**: Internet intelligence API
- **YARA**: Malware pattern matching

### ML/AI Components
- **Anomaly Detection**: Isolation Forest, Autoencoders
- **Classification**: Random Forest, Neural Networks
- **Sequence Analysis**: LSTM, Transformers for log analysis
- **Graph Analysis**: NetworkX for attack graph mapping

### Infrastructure
- **Containerization**: Docker + Kubernetes
- **Monitoring**: Prometheus + Grafana
- **Logging**: ELK Stack (Elasticsearch, Logstash, Kibana)
- **Message Queue**: Apache Kafka for event streaming

## Security Considerations

### Self-Protection
- **Authentication**: Multi-factor auth for all access
- **Encryption**: TLS 1.3 for all communications
- **Audit Logging**: Immutable logs for all actions
- **Rate Limiting**: Prevent abuse of the system itself

### Fail-Safe Mechanisms
- **Manual Override**: Human intervention capability
- **Rollback**: Automatic rollback of harmful actions
- **Sandboxing**: All automated actions in isolated environments
- **Circuit Breakers**: Prevent cascading failures

## Deployment Architecture

### Components
1. **Edge Sensors**: Deployed on protected networks
2. **Analysis Cluster**: Central ML/AI processing
3. **Response Nodes**: Distributed mitigation execution
4. **Management Console**: Human oversight interface

### Scalability
- **Horizontal Scaling**: Add more analysis nodes
- **Data Partitioning**: Sharded by network segments
- **Load Balancing**: Distribute detection workload
- **Caching**: Redis for frequently accessed data

## Success Metrics

### Detection Effectiveness
- **True Positive Rate**: >95%
- **False Positive Rate**: <5%
- **Zero-Day Detection**: Detect novel threats within 24h
- **MTTD (Mean Time to Detect)**: <5 minutes

### Response Efficiency
- **MTTR (Mean Time to Respond)**: <15 minutes
- **Automated Response Rate**: >80%
- **Containment Success**: >90%
- **System Uptime**: >99.9%

## Development Phases

### Phase 1: Core Infrastructure
- Project setup and tool integration
- Basic data ingestion pipeline
- Simple rule-based detection

### Phase 2: ML/AI Integration
- Anomaly detection models
- Behavioral profiling
- Initial threat hunting capabilities

### Phase 3: Advanced Features
- Zero-day prediction
- Automated response workflows
- Proactive hunting automation

### Phase 4: Production Hardening
- Performance optimization
- Security hardening
- Comprehensive testing
