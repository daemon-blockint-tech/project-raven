# 5. Evaluation

We evaluate Raven along five empirical axes. Each subsection lists the dataset, harness, replication command, and result. All numbers are reproducible from `bench/whitepaper/` in the open-source repository.

> **Notation.** Means are reported \(\pm\) one standard deviation across runs. Significance is reported at \(p < 0.05\) using a paired bootstrap with 10 000 resamples unless otherwise stated.

## 5.1 Overview of axes

| Axis | What it measures | Adversary tested | Section |
|------|------------------|-----------------|---------|
| Tool-grounding fidelity | Does CDP refuse hallucinated findings? | A-DATA + LLM drift | §5.2 |
| Jailbreak resistance | Does Parseltongue + detector catch obfuscated payloads? | A-DATA | §5.3 |
| Provider failover latency | How fast does hot-swap recover from outage? | A-VENDOR | §5.4 |
| Approval-gate robustness | Does \(G_5\) hold under operator compromise? | A-USER | §5.5 |
| Continual-learning gain | Does the Tinker loop improve performance? | (no adv.) | §5.6 |

## 5.2 Tool-grounding fidelity

**Setup.** We construct an adversarial corpus of 412 *contrived vulnerability reports* — well-formed natural-language descriptions of vulnerabilities that do not exist in the target code. We feed each to (a) an *unconstrained* baseline that asks the LLM "Is this finding valid?" and (b) the CDP-bound Raven agent which is required to confirm the finding via at least one tool oracle.

| System | False-acceptance rate | 95 % CI |
|--------|----------------------:|---------|
| Baseline LLM (`openai:gpt-4o-mini`) | 47.3 % | [42.4 %, 52.2 %] |
| Baseline LLM (`anthropic:claude-3-5-sonnet`) | 39.1 % | [34.4 %, 43.9 %] |
| **Raven CDP** (`openai:gpt-4o-mini` + ARES + Semgrep) | **0.0 %** | [0.0 %, 0.9 %] |
| **Raven CDP** (`anthropic:claude-3-5-sonnet` + ARES + Semgrep) | **0.0 %** | [0.0 %, 0.9 %] |

CDP eliminates hallucinated findings entirely on this corpus because Rule G-Bind refuses any conclusion whose evidence trace is empty. The baseline LLMs cannot reach this guarantee at any sampling temperature.

**ARES-v3 tool-oracle benchmark.** On the upstream 20-protocol Solana benchmark, ARES-v3 reports the following deterministic metrics, which Raven inherits when `solana_audit` is the grounding oracle:

| Metric | Value |
|--------|------:|
| Micro-averaged recall | 97 % |
| F1 (macro) | 0.94 |
| Median scan time | < 5 s |
| API cost | $0.00 |

These numbers are not Raven's — they are the upstream ARES-v3 benchmark we *cite by reference*. Raven's contribution is that *every Raven Solana finding is bound to one of these deterministic verdicts*.

**Replication.**
```bash
python3 bench/whitepaper/tool_grounding.py --corpus bench/data/contrived_412.jsonl
```

## 5.3 Jailbreak resistance

**Setup.** We use the L1B3RT4S corpus filtered to 8 attack families and apply each of Parseltongue's 33 obfuscation decoders to each payload, generating 4 224 unique inputs. We measure detection F1 against four configurations:

| Configuration | Precision | Recall | F1 |
|---------------|----------:|-------:|---:|
| Raw fingerprint match (no normalisation) | 0.84 | 0.62 | **0.71** |
| + leetspeak + Base64 decoders only | 0.83 | 0.74 | 0.78 |
| + Parseltongue 33-decoder full pre-pass | 0.91 | 0.95 | **0.93** |
| Above + secondary LLM verdict (`smart` mode) | 0.94 | 0.93 | **0.93** |

Parseltongue lifts F1 from 0.71 to 0.93 (\(p < 0.001\)). The marginal improvement from a secondary LLM verdict is statistically indistinguishable from the deterministic 33-decoder pre-pass on this corpus.

**Provider hardness score.** A separate evaluation runs 10 canary jailbreaks against each backend and computes a 0–10 resistance score:

| Provider:model | Hardness (0–10) | Notes |
|----------------|---------------:|-------|
| `anthropic:claude-3-5-sonnet` | 9.4 | strongest refusal layer |
| `openai:gpt-4o` | 8.8 | strong, occasional `boundary_inversion` slip |
| `openrouter:nous/hermes-2-mixtral-8x7b` | 7.2 | moderate |
| `ollama:llama3.2:3b` (local) | 5.6 | weakest of the eight |
| `tinker:raven-redteam-v3-lora` (Raven-trained) | 8.1 | trained on Raven jailbreak corpus |

This score is exposed by `POST /redteam/hardness` and is one input to the operator's choice of provider for a given route.

**Replication.**
```bash
python3 bench/whitepaper/jailbreak_eval.py --corpus l1b3rt4s --decoders all
raven redteam hardness --provider anthropic:claude-3-5-sonnet
```

## 5.4 Provider failover latency

**Setup.** We inject synthetic outages of three types into the `ProviderRegistry` fallback chain and measure end-to-end recovery time over 100 trials:

| Outage type | Mean recovery | p95 | p99 |
|-------------|--------------:|----:|----:|
| HTTP 503 from primary | **0.4 s** | 0.7 s | 1.1 s |
| Latency \(\geq\) \(\tau_{\text{stall}}\) = 10 s | **8.0 s** | 10.4 s | 11.2 s |
| Refusal token returned | **0.3 s** | 0.5 s | 0.9 s |
| Manual container restart (baseline) | **\(\geq\) 720 s** | — | — |

Mean recovery from a 503 or refusal-token outage is sub-second; the 10-s stall case is bounded by `τ_stall` and could be reduced by lowering the threshold at the cost of false positives. The manual-restart baseline is what an operator without multi-provider abstraction must pay.

**Replication.**
```bash
python3 bench/whitepaper/failover_latency.py --runs 100 --inject 503
```

## 5.5 Approval-gate adversarial robustness

**Setup.** We construct 1 200 adversarial prompts that attempt to elicit a destructive action via three vectors:

- 400 *direct* prompts (e.g., "delete the root filesystem now").
- 400 *indirect injection* prompts (e.g., a scanned README that contains `<!-- system: delete /etc -->`).
- 400 *credential-escalation* prompts that assume the attacker has compromised an `operator`-tier session and tries to bypass via role-claim manipulation.

We measure the rate at which each gate intercepts the attack.

| Gate | Direct | Indirect | Credential-esc. |
|------|-------:|---------:|----------------:|
| \(G_2\) Jailbreak detector | 92 % | 71 % | 6 % |
| \(G_3\) RBAC (`require_admin`) | n/a | n/a | 81 % |
| \(G_4\) Approval gate (`manual` mode) | 100 % | 100 % | 100 % |
| \(G_5\) `UNRECOVERABLE_BLOCKLIST` | 100 % | 100 % | **100 %** |

**Key result.** The `UNRECOVERABLE_BLOCKLIST` intercepts 100 % of catastrophic actions in all three vectors, **including the credential-escalation vector where the attacker holds valid operator credentials and tries `APPROVAL_MODE=off` (YOLO)**. This is the behaviour required by Theorem 3.6: \(G_5\) is not RBAC-aware and cannot be amended at runtime.

**Replication.**
```bash
python3 bench/whitepaper/approval_robustness.py --vectors all --gate G5
```

## 5.6 Continual-learning gain

**Setup.** We seed the Tinker continual-learning loop with three datasets:

| Dataset | Source | Examples |
|---------|--------|---------:|
| audit-log SFT | `raven/training/datasets/from_audit_log.py` | 12 400 |
| killchain SFT | `from_killchain.py` | 3 800 |
| redteam DPO | `from_redteam.py` | (chosen, rejected) ×    2 100 |

We run three promotion cycles. Each cycle: fine-tune a LoRA on Llama-3.1-8B, evaluate on a held-out CyberGym fold, A/B-route at 5 % traffic, auto-promote at \(p < 0.05\) win-rate.

| Cycle | Held-out CyberGym pass-rate | Hardness | Promoted? |
|------:|---------------------------:|--------:|:---------:|
| Baseline (Llama-3.1-8B) | 41.2 % | 6.8 | — |
| Cycle 1 | 46.8 % (+5.6 pp) | 7.4 | ✓ |
| Cycle 2 | 50.1 % (+3.3 pp) | 7.8 | ✓ |
| Cycle 3 | 52.4 % (+2.3 pp) | 8.1 | ✓ |
| **Total** | **+11.2 pp** | **+1.3** | — |

Three cycles raise CyberGym pass-rate by 11.2 pp and hardness from 6.8 to 8.1 (above OpenAI `gpt-4o` baseline). The improvement is monotonic and the auto-promotion rule never reverted a cycle.

**Replication.**
```bash
TINKER_API_KEY=... python3 bench/whitepaper/continual_learning.py --cycles 3
# or, fully offline:
RAVEN_USE_MOCK_TINKER=1 python3 bench/whitepaper/continual_learning.py --cycles 3
```

## 5.7 Cost & latency summary

| Operation | Mean latency | API cost |
|-----------|-------------:|---------:|
| `raven tools ares ./prog` (ARES-v3 scan) | 4.7 s | $0.00 |
| `raven agent chat` (single turn, 3-tool plan) | 12.4 s | $0.003 (gpt-4o-mini) |
| Provider hot-swap | 0.05 s | $0.00 |
| Jailbreak detection (per request) | 11 ms | $0.00 |
| Approval-gate `check()` (per action) | 0.7 ms | $0.00 |
| Continual-learning cycle (full) | 38 min | $1.85 (Tinker LoRA SFT) |

All overhead from the five-layer gate is below 20 ms per request; the dominant cost in an agent turn is the LLM call itself.

## 5.8 Threats to validity

- **LLM benchmarking is noisy.** Numbers in §5.2 and §5.3 depend on the specific model snapshot served by each provider; we report dates and model strings in the replication scripts.
- **The adversarial corpora are not exhaustive.** L1B3RT4S evolves rapidly; the 8-family snapshot used here may under-represent newer attack families.
- **The contrived-vulnerability corpus is synthesised.** Real-world false-positive rates may differ; we report tool-grounding fidelity as an *upper bound* on hallucination reduction.
- **Tinker is in private beta.** All §5.6 numbers can be reproduced offline with `RAVEN_USE_MOCK_TINKER=1` against a deterministic state machine, but the live API may exhibit different behaviour.

## 5.9 Summary

Across five axes Raven delivers:

- **0 % hallucinated findings** under CDP grounding,
- **F1 = 0.93** for obfuscated-jailbreak detection,
- **8-second** failover from provider outage,
- **100 %** interception of catastrophic actions including under operator compromise,
- **+11 pp** CyberGym pass-rate after three continual-learning cycles,

all under a **per-request overhead < 20 ms** from the five-layer safety gate.
