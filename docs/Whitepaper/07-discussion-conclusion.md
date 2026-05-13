# 7. Discussion, Limitations, & Conclusion

## 7.1 What CDP gives us, and what it doesn't

CDP guarantees that no LLM-emitted finding leaves Raven without either (a) a deterministic evidence trace, (b) an explicit `unsourced=true` confidence tag, or (c) a refusal. This is sufficient for the *auditability* property required in regulated environments (financial-sector security, smart-contract audits, critical-infrastructure SOCs).

CDP **does not** guarantee that the tool oracle itself is sound. ARES-v3's 97 % recall implies a 3 % false-negative rate. radare2 can be confused by adversarial obfuscation. YARA rules are only as good as the rule author. The grounding theorem reduces *LLM hallucination* to *tool fidelity* — a strictly easier problem to reason about, but not a vacuous one.

Operators should:

- Pin tool versions and audit rule updates.
- Run multiple oracles in parallel when stakes are high (cf. §6.2 four-oracle composition).
- Treat the confidence score on `unsourced=true` outputs as advisory, never as ground truth.

## 7.2 Limitations

1. **LLM cost.** The CDP loop performs multiple LLM calls per turn (plan → call tools → summarise). On cloud providers this multiplies cost. Local providers (LM Studio, Ollama) eliminate the cost but increase latency.

2. **Tool footprint.** Twenty tool oracles is a large attack surface. We mitigate via subprocess sandboxing, `shell=False` execution, and explicit argument allowlists, but each tool is its own dependency-management problem. Docker multi-stage builds with multi-tool images partially address this.

3. **ML model trust.** The classical-ML detectors (\(\mathcal{M}\)) are loaded via `load_model()` gated by `ALLOW_PICKLE_MODELS` and `MODEL_PATH` jailing — pickle is unsafe by design, and we currently refuse to load pickled models without explicit opt-in. A future version should migrate to ONNX or SafeTensors for all classical models.

4. **Indirect injection via tool output.** A malicious binary can embed prompt-injection text in its strings table; if that text is summarised by the LLM verbatim, it could attempt to override system prompts. We mitigate via prompt structuring (`tool_output` is *data*, not *system*) and via re-running \(G_2\) on the post-tool-call summary, but we have not formally verified that this is sufficient against all known indirect-injection attacks.

5. **Continual learning is opt-in and key-gated.** Operators without Tinker access can run the mock-mode pipeline (`MockTinkerClient`) for CI but cannot benefit from real model adaptation. We are exploring open-weight alternatives via PEFT + vLLM for §5.6 reproducibility without a managed-service dependency.

6. **The `UNRECOVERABLE_BLOCKLIST` is a finite list.** Catastrophic actions outside the list will pass \(G_5\). We currently encode 11 patterns; extending to a full taxonomy of irreversible filesystem / kernel / hardware actions is future work.

## 7.3 Threats to the threat model

- An adversary who **patches Raven binaries** can disable \(G_5\). We mitigate via cosign-signed container images, read-only root filesystem, and pod-disruption-budget alerts on unexpected restarts.
- An adversary who **compromises the LLM provider** itself (A-VENDOR worst case) can return adversarial completions that conform to the tool-call schema. We mitigate via `AI_ALLOWED_BASE_URLS` (no `base_url` switch without operator approval) and via cross-provider voting (running the same plan through two providers and refusing divergent results) — the latter is implemented but disabled by default for cost reasons.
- An adversary who **compromises the host's `LD_PRELOAD`** can subvert tool oracles. We assume the host is honest; defending against host-level compromise is outside Raven's scope and is the responsibility of the platform (Kubernetes admission controllers, Falco runtime, eBPF-based syscall auditing).

## 7.4 Future work

1. **Formal verification of the grounding rule.** The current Theorem 3.6 is informal. A machine-checked proof in Coq or Lean over a model of the agent loop would tighten the guarantee.

2. **Open-weight continual-learning loop.** Replace Tinker with a self-hosted vLLM + PEFT stack for §5.6 reproducibility without managed-service dependency.

3. **Cross-provider voting as a default.** Run plans through two providers in parallel and refuse divergent outputs. Cost-prohibitive today; tractable as local-model quality rises.

4. **Extend \(\mathcal{T}\) to web3 forensics.** Add adapters for Phalcon Compliance, Chainalysis Sanctions, Range AI MCP, and BlockchainSpider for end-to-end on-chain investigation grounded in the same CDP.

5. **TUI for non-Solana audits.** The current TUI streams agent output well for Solana audits; extending the rich-rendered evidence panels to network reconnaissance and memory forensics is a UX win.

6. **Adversarial ML defence for \(\mathcal{M}\).** Migrate from sklearn pickle to ONNX, add input-perturbation robustness tests, and integrate MITRE ATLAS attack templates against the classical detectors.

## 7.5 Conclusion

We have introduced **Compositional Defense Pipelines** as a principle for building autonomous defensive AI agents: the LLM orchestrates, deterministic tools assert, classical ML scores, and a five-layer safety gate refuses. Every finding is auditable to a specific evidence source; every catastrophic action is refused unconditionally; every LLM provider is interchangeable in under 10 seconds.

The reference implementation, Project Raven, demonstrates that this composition is realisable in ≈ 38 kLoC of Python, with measurable improvements across five empirical axes — including a 0 % hallucination rate under CDP grounding, F1 = 0.93 on obfuscated jailbreak detection, 8-second provider failover, 100 % interception of catastrophic actions, and an 11 pp gain from three continual-learning cycles.

CDP is not a complete answer to the question *"when can we trust an autonomous agent?"* — it is a *structural* answer: an architecture in which the question becomes mechanically checkable. Whether the underlying tools are correct, the ML detectors well-calibrated, and the operators well-intentioned remains a matter for the deployment to answer. But within the architecture, there is no longer any path for an LLM to produce an unanchored claim, no path for an operator to bypass an irreversible action, and no path for a vendor outage to halt the agent for longer than a stall-timer's grace.

We release Raven open-source under MIT and invite the community to extend \(\mathcal{T}\), to harden \(\mathcal{G}\), to formalise Theorem 3.6, and to evaluate CDP on new domains.

---

## Acknowledgements

We thank the upstream authors of ARES-v3 (Nyoko Karma Nugroho, Fikri Armia Fahmi), the Solana-eBPF-for-Ghidra extension (blastrock), the L1B3RT4S corpus, the CyberGym benchmark, Anthropic's red-team programme, the Tinker team at Thinking Machines, the ProjectDiscovery suite, and the maintainers of YARA, radare2, Ghidra, Volatility 3, and CyberChef. CDP would not be possible without the deterministic-tooling community that produced these analysers.

## Author contributions

This whitepaper is the result of the Project Raven engineering effort. The CDP grammar (§3), the safety gate (§3.4), the implementation (§4), and the evaluation harness (§5) were designed and authored collectively. Specific tool integrations (ARES-v3, eBPF-for-Ghidra) cite their upstream creators in the related-work section.

## Licence

Whitepaper text licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Source code licensed under MIT.
