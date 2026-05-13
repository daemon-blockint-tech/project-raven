# 2. Related Work

We organise related work along four axes that map to Raven's four primary subsystems.

## 2.1 LLM-driven offensive & defensive security agents

**Claude Code** [Anthropic-claude-code-2025] introduces tool-calling agents for software-engineering tasks with structured `Tool` schemas and an interactive sticky-bottom TUI, both of which Raven adopts. However, Claude Code (a) is hard-bound to a single provider, (b) lacks an approval gate, and (c) does not enforce tool grounding — the LLM may freely synthesise findings.

**Anthropic's Zero-Day Programme** [Anthropic-0day-2026] reports that Claude Opus 4.6 can autonomously discover CVE-class vulnerabilities via three techniques: *variant analysis*, *precondition reasoning*, and *algorithm-semantic mining*. Raven re-implements all three in `raven/ml/variant_analyzer.py` and `raven/hunters/hypothesis_generator.py`, and binds them to CDP grounding so that variants must be confirmed by Semgrep / CodeQL / ARES before being reported as findings.

**Incalmo** [Incalmo-2025] proposes a declarative kill-chain planner over MITRE ATT&CK. Raven adopts the declarative-task model in `raven/hunters/kill_chain_planner.py`, but adds HITL approval gates at every destructive stage and rejects planner output that does not reference a tool oracle.

**CyberGym** [CyberGym-2025] provides a labelled benchmark of vulnerability tasks with structured verdicts. Raven consumes CyberGym verdicts both as an evaluation set (§5) and as a continual-learning corpus (`raven/training/datasets/from_cybergym.py`).

**Hermes Agent** [Nous-hermes-agent-2025] introduces `provider:model` shorthand and three approval modes (`manual` / `smart` / `off`), plus the L1B3RT4S jailbreak fingerprint library. Raven inherits the modes and fingerprints, but adds the `UNRECOVERABLE_BLOCKLIST` floor (which Hermes Agent does not have) and the Parseltongue 33-decoder normalisation pre-pass (Hermes Agent normalises a smaller subset).

## 2.2 Multi-provider LLM abstractions

**LangChain** [LangChain-2023] and **LlamaIndex** [LlamaIndex-2023] provide LLM provider abstractions but at the *library* level, requiring application redeploys to switch. Raven's `ProviderRegistry` (§3.3, §4.1) hot-swaps at the running-process level via a thread-safe singleton, exposed by a REST endpoint and a CLI command, allowing operators to change providers **without restart** — a property we measure in §5.4.

**OpenRouter** [OpenRouter-2024] aggregates 300+ models behind one OpenAI-compatible API. Raven uses OpenRouter as one of eight backends, but does *not* lock to it: an operator can fail over from OpenRouter to a local LM Studio model in 8 s.

**Tinker** [TinkingMachines-Tinker-2025] provides managed LoRA fine-tuning over Llama-3.1 and Qwen-2.5 base models. Raven integrates Tinker as a first-class provider so that Raven-trained adapters can be served alongside vendor models, and ships a `MockTinkerClient` that replays a state machine when no API key is available so the entire continual-learning loop is testable offline.

## 2.3 Deterministic security tooling

**ARES-v3** [ARES-v3-2026] is a deterministic static auditor for Solana smart contracts that runs a four-phase pipeline — regex extraction → AST parsing → taint analysis → deterministic judge — and reports 97 % micro-recall and 0.94 F1 across 20 benchmark protocols with zero API cost. Raven integrates ARES-v3 as a tool oracle (`raven/tools/ares.py`), exposes it under CLI (`raven tools ares`), REST (`POST /tools/ares/call`), and as an agent-callable function (`solana_audit`).

**Solana-eBPF-for-Ghidra** [Blastrock-eBPF-Ghidra-2025] is a Ghidra processor extension that enables decompilation of compiled Solana programs (`.so` files compiled to BPF ELF). Raven detects and orchestrates this extension via `raven/tools/ebpf_ghidra.py` and binds it to the existing `GhidraAnalyzer` for end-to-end binary triage.

**ProjectDiscovery suite** (subfinder, naabu, httpx, nuclei, interactsh) [ProjectDiscovery-2024], **YARA** [VirusTotal-YARA], **radare2** [radareorg-r2], **Volatility 3** [VolatilityFoundation-vol3], **Frida** [Frida-2024], **CyberChef** [GCHQ-cyberchef], **searchsploit / Exploit-DB** [Offsec-EDB], and **recon-ng** [Lanmaster-reconng] are integrated as tool oracles under a unified `ToolAdapter` base class (§4.2), turning the LLM into an orchestrator over a heterogeneous deterministic toolset.

## 2.4 Safety gates and approval primitives

**OWASP LLM Top 10** [OWASP-LLM-2025] catalogues prompt injection, insecure output handling, and excessive agency as top risks. Raven's five-layer gate is designed against this taxonomy — Parseltongue and the jailbreak detector address LLM01 (prompt injection); RBAC and the approval gate address LLM02 (insecure output handling) and LLM08 (excessive agency); the `UNRECOVERABLE_BLOCKLIST` enforces a hardline against LLM06 (sensitive information disclosure) at the action level.

**MITRE ATLAS** [MITRE-ATLAS-2024] provides an adversarial-ML threat matrix that we use to enumerate attack surfaces against Raven itself (§3.7).

**Argon2id** [Biryukov-Argon2-2016] is the OWASP-recommended password KDF; Raven uses Argon2id with the 2023 parameter set (t=2, m=19 456 KiB, p=1) for all operator authentication.

## 2.5 Continual learning for security agents

**DPO** [Rafailov-DPO-2024] and **SFT-from-rollouts** [InstructGPT-2022] are the two paradigms Raven uses in its continual-learning loop. The DPO pipeline (`raven/training/datasets/from_redteam.py`) turns jailbreak attempts into (chosen, rejected) pairs; the SFT pipeline (`from_killchain.py`, `from_audit_log.py`) turns approved operator actions into supervised pairs. Both are gated by PII scrubbing and the secret-vault Fernet at-rest encryption (§4.5).

## 2.6 Positioning

The novelty of Raven is not the invention of any single component above. Every constituent — multi-provider routing, approval modes, jailbreak detection, deterministic tooling, continual learning — exists in some form in prior art. The novelty is **the composition rule**: that all five operate inside a CDP whose grounding theorem (§3.6) is mechanically checkable, that all five can be hot-reconfigured without restart, and that all five are evaluated on a single open-source benchmark suite.

To our knowledge no prior published agent integrates **all of**: (a) eight hot-swappable LLM providers, (b) a 33-decoder obfuscation pre-pass, (c) an irreversible-action blocklist with no privilege override, (d) a 20+-tool deterministic oracle layer including a deterministic Solana auditor, (e) a managed-LoRA continual-learning loop with auto-promotion, and (f) a production Helm chart with HPA, NetworkPolicy, and cosign-signed images.
