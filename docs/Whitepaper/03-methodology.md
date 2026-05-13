# 3. Methodology — Compositional Defense Pipelines (CDP)

This section formalises the central contribution of the whitepaper. We define a small grammar over evidence sources, LLM operators, and safety gates, state a grounding theorem on the resulting pipelines, and describe the five-layer safety gate that wraps every CDP execution.

## 3.1 Notation and primitives

Let \(\mathcal{T}\) be the set of *tool oracles* — deterministic, structurally-typed analysers. Each \(t \in \mathcal{T}\) is a function

$$
t : \mathcal{I}_t \times \Theta_t \to \mathcal{R}
$$

where \(\mathcal{I}_t\) is the input domain (path, binary, prompt, …), \(\Theta_t\) is the configuration space (timeout, flags, policy file), and \(\mathcal{R}\) is the unified result envelope `ToolResult` (Definition 3.2). The set \(\mathcal{T}\) currently has cardinality \(|\mathcal{T}| = 20\) in Raven's reference implementation; see Table 4.1.

Let \(\mathcal{M}\) be the set of *classical-ML detectors* — functions \(m : \mathcal{X} \to [0, 1]^k\) producing class probabilities over a labelled label space, with no LLM dependency at inference time. Raven's \(\mathcal{M}\) currently contains an IsolationForest anomaly detector, a RandomForest zero-day predictor, and an autoencoder behavioural-baseline model.

Let \(\mathcal{L}\) be the set of *LLM operators* — provider-routed functions \(\ell : \mathcal{P}^* \to \mathcal{P}\) over a prompt space \(\mathcal{P}\). Raven exposes eight backends behind a unified \(\ell\): `lmstudio`, `openai`, `anthropic`, `openrouter`, `ollama`, `nous`, `opencode`, `tinker` (Table 4.2).

Let \(\mathcal{G}\) be the *safety gate*, a composition \(\mathcal{G} = G_5 \circ G_4 \circ G_3 \circ G_2 \circ G_1\) over inputs and outputs (Definition 3.4).

### Definition 3.2 (`ToolResult`)

```text
ToolResult = {
  tool          : str,
  success       : bool,
  target        : str,
  stdout        : str,
  stderr        : str,
  exit_code     : int,
  execution_time: float,
  parsed        : Optional[Dict],   # tool-specific structured output
  error         : Optional[str],
  cmd           : str
}
```

Every tool oracle in \(\mathcal{T}\) is required to return a `ToolResult`. The `parsed` field carries the tool-specific evidence object (e.g., ARES-v3 findings list, YARA match list, Nmap port-state map). This uniformity is what enables CDP grounding to be mechanically checked.

## 3.2 The CDP grammar

A **Compositional Defense Pipeline** \(\pi\) is a directed acyclic graph \((V, E)\) where each node \(v \in V\) is annotated with a kind from \(\{T, M, L, G\}\). The graph is well-formed iff:

1. **Root** is the gate \(G_1\) (Parseltongue normaliser) and **sink** is a *grounded conclusion* \(c\).
2. Every \(L\)-node either *consumes* the output of at least one \(T\)-node or \(M\)-node, or is annotated with `unsourced=true` and labelled with a confidence score \(s \in [0, 1]\).
3. Every edge crossing a tool boundary carries a `ToolResult` (Definition 3.2).
4. Every destructive action (those matching `DANGEROUS_PATTERNS`) is preceded by \(G_4\) (the approval gate).
5. Every action matching `UNRECOVERABLE_BLOCKLIST` is preceded by \(G_5\) (the irreversible-action gate) which always refuses.

A **conclusion** \(c\) is *grounded* iff it carries a non-empty `evidence` trace pointing to at least one \(T\)- or \(M\)-node output. An ungrounded conclusion may exit the pipeline only if it bears an explicit `unsourced=true, confidence=s` tag.

### Example pipeline (Solana audit)

```
G1(Parseltongue) ─► G2(Jailbreak) ─► G3(RBAC) ─► L(plan) ─► T(ares.scan) ─┐
                                                              T(yara)     │
                                                              T(radare2)  ├─► L(summarise) ─► c
                                                              T(ghidra)   │
                                                              M(zero_day) ┘
```

\(L(\text{plan})\) emits a tool plan; the four tool oracles execute deterministically; the classical-ML detector emits its anomaly score; \(L(\text{summarise})\) produces the user-facing conclusion *with* the union of evidence traces attached.

## 3.3 Multi-provider abstraction & failover

A core CDP property is that the \(L\) operator must be *interchangeable*. Raven exposes a single ABC, `BaseAIClient`, and routes calls through a `ProviderRegistry` singleton with thread-safe hot-swap semantics.

**Failover protocol.** When provider \(p_i\) returns either (a) HTTP 5xx, (b) a refusal token matching `JAILBREAK_DETECTOR_REFUSAL_TOKENS`, or (c) a latency \(\geq \tau_{\text{stall}}\), the registry transparently fails over to \(p_{i+1}\) according to a configured fallback chain. The set of allowed `base_url` values is bounded by `AI_ALLOWED_BASE_URLS` to close the credential-exfiltration class of attack from a malicious provider switch.

**Empirical claim (measured in §5.4):** failover under outage injection completes in \(\overline{t}_{\text{recovery}} = 8.0 \pm 1.3\) s, versus 12 min for a manual container restart.

## 3.4 Five-layer safety gate \(\mathcal{G}\)

### \(G_1\) — Parseltongue obfuscation normaliser

Decodes 33 obfuscation techniques before any inspection: zero-width Unicode, leetspeak, homoglyphs, Base64, Base32, hex, Braille, Morse, Pig Latin, ROT-N, math-alphanumeric ranges, bracket-substitution, acrostic encoding, and 20 others (full list in `raven/redteam/normalizer.py`). The output of \(G_1\) is the canonical form fed to \(G_2\).

### \(G_2\) — Jailbreak fingerprint detector

Scans the canonical form against the L1B3RT4S family library (8 families × multiple regex patterns each: `boundary_inversion`, `refusal_inversion`, `og_godmode`, `unfiltered_liberated`, `dan`, `injection`, `role_play`, `content`). Emits a weighted score \(j \in [0, 1]\). Inputs with \(j \geq \tau_{\text{block}}\) (default 0.7) are 403-rejected, with the score reflected in the `X-Raven-Jailbreak-Score` response header for downstream monitoring.

### \(G_3\) — Role-based access control

Three roles in a strict ordering: `viewer < operator < admin`. Every mutating route declares `Depends(require_operator)` or `Depends(require_admin)`. Argon2id-hashed passwords, JWT with 15-min access tokens and 7-day rotating refresh tokens, revocation set on logout.

### \(G_4\) — Tiered approval gate

Three modes:

- **manual** — every dangerous-pattern hit enqueues a `PendingApproval` and returns HTTP 202 with `request_id`. The operator approves via `POST /approval/{id}`. No action runs without explicit approval.
- **smart** — an auxiliary LLM (`ModelOrchestrator.FAST`, e.g., a small local model) triages: clear-safe is auto-approved, clear-dangerous is auto-denied, ambiguous escalates to manual.
- **off** (YOLO) — auto-approve. *Refused at start-up* by the production-safety validator when `RAVEN_ENVIRONMENT=prod`.

### \(G_5\) — `UNRECOVERABLE_BLOCKLIST`

A hardcoded list of catastrophic action patterns: `rm -rf /`, fork bombs, `mkfs /dev/sd*`, `dd of=/dev/sd*`, `:(){:|:&};:`, `curl ... | sh`, `chmod -R 777 /`. **Cannot be overridden** by any combination of role, approval mode, or session token. This is the only gate that ignores RBAC entirely.

> **Design note.** The `UNRECOVERABLE_BLOCKLIST` is not a policy — it is an invariant. Its enforcement is a function call inside `ApprovalGate.check()` that returns `REFUSE` regardless of caller context. There is no admin endpoint to amend it; the only way to change the list is to edit `raven/approval/patterns.py` and redeploy.

## 3.5 Tool-grounding rule

We formalise the tool-grounding rule as follows.

> **Rule (G-Bind).** A conclusion \(c\) produced by an LLM operator \(\ell \in \mathcal{L}\) is *admissible* iff one of the following holds:
> 1. \(c\) carries an `evidence` trace \(E \neq \emptyset\) where every \(e \in E\) is the output of some \(t \in \mathcal{T}\) or \(m \in \mathcal{M}\); **or**
> 2. \(c\) is explicitly tagged `unsourced=true` and carries a confidence score \(s \in [0, 1]\).

Conclusions failing both branches are *refused* by the verifier and never returned to the user. The verifier is a small function (`raven/ai/grounding_verifier.py`) that runs on every LLM completion in a CDP and either passes the conclusion through, decorates it with `s`, or refuses.

This rule is the *contract* between the LLM and the rest of the system. It captures the central intuition: **the LLM may orchestrate and summarise; it may not be the analyser.**

## 3.6 Grounding theorem (informal)

> **Theorem 3.6.** Let \(\pi\) be a well-formed CDP per §3.2 and let \(c\) be its output. Then exactly one of the following holds:
> (a) \(c\) is a grounded conclusion with non-empty evidence trace \(E\), every element of which is a `ToolResult` from \(\mathcal{T}\) or a verdict from \(\mathcal{M}\);
> (b) \(c\) is an explicitly *scored* hypothesis with confidence \(s\) and `unsourced=true`;
> (c) The pipeline was refused by some \(G_i\) at well-formedness check, jailbreak scan, RBAC, approval, or the irreversible-action gate.

*Proof sketch.* The five gate predicates are total functions over their input domains and run before any \(L\)-node executes. The grounding verifier executes on every \(L\)-node completion and refuses outputs failing both branches of Rule G-Bind. By DAG structure, the sink \(c\) inherits the satisfied predicate of its predecessor edges. \(\square\)

This theorem is what makes CDP-grounded findings *auditable*: every conclusion is either accompanied by deterministic evidence, explicitly marked as ungrounded with a score, or did not exit the pipeline.

## 3.7 Threat-model alignment

Mapping the three adversaries from §1.2 to the five gates and grounding rule:

| Adversary | Mitigated by |
|-----------|--------------|
| A-DATA (prompt injection, obfuscated payloads, malformed inputs) | \(G_1\) (Parseltongue) + \(G_2\) (Jailbreak) + Rule G-Bind |
| A-USER (compromised operator credentials) | \(G_3\) (RBAC) + \(G_4\) (Approval) + \(G_5\) (`UNRECOVERABLE_BLOCKLIST`) |
| A-VENDOR (LLM outage, censorship, drift) | Multi-provider abstraction + base-URL allowlist + provider-hardness score + failover protocol |

## 3.8 Continual learning under the grounding rule

Raven's training loop (`raven/training/`) is also CDP-bound: training examples are derived from (a) audit-log entries that *succeeded* under the gate, (b) approved kill-chain rollouts, (c) red-team attempts that *triggered* \(G_2\) (becoming `rejected` pairs in DPO), and (d) CyberGym ground-truth verdicts. Every training pair carries its evidence trace. The A/B router promotes a new model only when CyberGym pass-rate on a held-out fold improves at \(p < 0.05\) and hardness-test resistance \(\geq\) baseline.

## 3.9 Summary

CDP is the architectural primitive that binds Raven's components into an auditable whole. The five-layer gate, the grounding rule, and the multi-provider abstraction operate on a single shared data type (`ToolResult`) and a single safety contract (Theorem 3.6). The reference implementation (§4) realises this design in ≈ 38 k LoC; the empirical evaluation (§5) measures it on five axes; the case studies (§6) demonstrate its end-to-end utility.
