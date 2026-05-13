# Project Raven — Methodology

> **Compositional Defense Pipelines (CDP):** a tool-grounded, multi-provider, safety-gated architecture for autonomous defensive AI agents.

This document is the concise, operator-facing summary of Raven's methodology. For the full academic treatment with formal grammar, theorem, and empirical evaluation, see [`Whitepaper/`](./Whitepaper/README.md).

---

## 1. Core principle — the grounding rule

> Every assertion produced by an LLM must terminate at one of three deterministic evidence sources, or be refused.

The three sources are:

| Source | Symbol | Example |
|--------|--------|---------|
| **Tool oracle** | \(\mathcal{T}\) | ARES-v3 scan, YARA match, radare2 disassembly, Nmap port state |
| **Classical-ML detector** | \(\mathcal{M}\) | IsolationForest anomaly, RandomForest zero-day, autoencoder behavioural drift |
| **Scored LLM hypothesis** | \(\mathcal{L}\) (tagged) | Explicitly `unsourced=true` + confidence score \(s \in [0,1]\) |

The LLM **orchestrates** tools and **summarises** evidence. It does not **assert** without backing.

---

## 2. The pipeline shape

A CDP is a directed acyclic graph from a normalised user prompt to a grounded conclusion:

```
user input
   │
   ▼
G1 Parseltongue obfuscation normaliser   (33 decoders)
   │
   ▼
G2 Jailbreak fingerprint detector        (8 L1B3RT4S families)
   │
   ▼
G3 RBAC                                  (viewer | operator | admin)
   │
   ▼
L  LLM plan                              (multi-provider)
   │
   ▼
T  Tool oracles (parallel)               YARA · radare2 · Ghidra · ARES · …
M  Classical ML detectors                IsolationForest · RandomForest · …
   │
   ▼
L  LLM summary with evidence trace
   │
   ▼
Grounding verifier (Rule G-Bind)
   │
   ▼
G4 Approval gate                         (manual | smart | off)
G5 UNRECOVERABLE_BLOCKLIST              (no override)
   │
   ▼
conclusion c  (with evidence E)
```

---

## 3. The five-layer safety gate

| # | Gate | Role | Override |
|---|------|------|----------|
| G1 | **Parseltongue** | Decode 33 obfuscation techniques before inspection | n/a |
| G2 | **Jailbreak detector** | Fingerprint 8 attack families on normalised input | n/a |
| G3 | **RBAC** | `viewer < operator < admin` enforced per route | n/a |
| G4 | **Approval gate** | Tiered approval for destructive actions (`manual` / `smart` / `off`) | `off` refused in production |
| G5 | **`UNRECOVERABLE_BLOCKLIST`** | Hardline refusal of `rm -rf /`, fork bombs, `mkfs /dev/sd*`, etc. | **No override possible** |

---

## 4. Tool oracles (\(\mathcal{T}\))

All 20 oracles inherit from a single `ToolAdapter` base class returning a uniform `ToolResult` envelope. The current catalogue includes (see [`tools.md`](./tools.md) for the full table):

- **Smart-contract auditing** — ARES-v3 (Solana), Solana-eBPF-for-Ghidra
- **Binary analysis** — Ghidra, radare2, jadx, Frida, Volatility 3
- **Malware signatures** — YARA
- **Reconnaissance** — subfinder, naabu, httpx, nuclei, interactsh, recon-ng, whois, Shodan
- **Exploitation frameworks** — Metasploit, Empire C2, searchsploit
- **Data ops** — CyberChef
- **Network discovery** — Nmap

Every tool exposes `is_available()`, `_run()`, an `install_hint`, and a `tool_name`. The LLM plans tool calls; the executor dispatches them; the verifier confirms evidence before returning a conclusion.

---

## 5. Multi-provider abstraction (\(\mathcal{L}\))

Eight LLM backends behind a single `BaseAIClient` ABC, hot-swapped at runtime by a thread-safe `ProviderRegistry`:

`lmstudio` · `ollama` · `openai` · `anthropic` · `openrouter` · `nous` · `opencode` · `tinker`

**Why this matters:** the LLM provider is no longer a single point of failure for liveness, cost, or policy. A provider outage triggers automatic failover (mean recovery time 8 s — see [`Whitepaper/05-evaluation.md`](./Whitepaper/05-evaluation.md) §5.4).

---

## 6. Continual learning under the rule

The Tinker LoRA loop produces Raven-trained adapters from four sources, all of which are themselves CDP-bound:

| Source | Output |
|--------|--------|
| Audit log (approved actions) | SFT pairs |
| Kill-chain rollouts (approved) | SFT pairs (tool-use) |
| Red-team attempts (G2-triggered) | DPO (chosen, rejected) |
| CyberGym verdicts | RL trajectories |

A new model is promoted only when CyberGym pass-rate improves at \(p < 0.05\) and hardness ≥ baseline.

---

## 7. What CDP gives you

| Property | Guarantee |
|----------|-----------|
| **Auditable findings** | Every claim links to a `ToolResult` or ML verdict |
| **No hallucinated findings** | 0 % false-acceptance on adversarial corpus (§5.2) |
| **Resilient to provider failure** | 8 s mean recovery from outage (§5.4) |
| **Hard-bounded irreversible actions** | 100 % interception even under compromised admin (§5.5) |
| **Continual improvement** | +11 pp CyberGym pass-rate over 3 cycles (§5.6) |

---

## 8. What CDP does *not* give you

- **Tool fidelity is your problem.** ARES recall is 97 %, not 100 %. radare2 can be fooled. YARA rules can be wrong. CDP reduces *LLM hallucination* to *tool soundness*.
- **Pinned tool versions matter.** Operators must audit rule updates and signature databases.
- **Multi-oracle composition raises confidence.** For high-stakes triage, run multiple oracles in parallel (see [Case B in `Whitepaper/06-case-studies.md`](./Whitepaper/06-case-studies.md)).

---

## See also

- Full whitepaper — [`Whitepaper/README.md`](./Whitepaper/README.md)
- Tool catalogue — [`tools.md`](./tools.md)
- Approval gate operator guide — [`approval-and-redteam.md`](./approval-and-redteam.md)
- Training pipeline — [`training.md`](./training.md)
- Architecture deep-dive — [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
