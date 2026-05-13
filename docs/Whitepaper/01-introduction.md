# 1. Introduction

## 1.1 The trust problem in LLM-driven security

LLM agents are now competitive with — and in some narrow benchmarks superior to — human analysts on tasks ranging from vulnerability discovery [Anthropic-0day-2026; CyberGym-2025] to malware family attribution and incident triage. Yet the deployment of such agents into production security operations centres (SOCs) and high-stakes pipelines (smart-contract audits, critical-infrastructure defense, financial fraud response) is repeatedly blocked by three concrete failures:

1. **Hallucinated grounding.** An LLM, when asked "is this code vulnerable?", will frequently produce a confident, well-formatted finding citing a non-existent CWE class, an incorrect line number, or an invented exploit technique. The output is statistically plausible but evidentially unanchored.

2. **Provider-level single point of failure.** A single LLM vendor (a) imposes per-request cost, (b) rate-limits at unknown thresholds, (c) silently updates the model behind the same endpoint, (d) may unilaterally block prompts that match its safety classifier — including legitimate red-team prompts. An agent hard-wired to one provider inherits all four risks simultaneously.

3. **Approval-bypass via prompt injection.** Defensive agents that invoke shell tools or destructive commands are routinely compromised through indirect prompt injection — text in a scanned document, a Git issue, or an HTTP response — that escalates the agent past its operator's intent.

Existing agentic frameworks address these in isolation. Claude Code [Anthropic-claude-code-2025] introduces structured tool calls but is hard-bound to one provider. Hermes Agent [Nous-hermes-agent-2025] introduces approval modes and obfuscation-resistant jailbreak fingerprinting but does not enforce tool grounding. Incalmo [Incalmo-2025] introduces declarative kill-chain planning but assumes the LLM's plans are sound. ARES-v3 [ARES-v3-2026] introduces deterministic Solana static analysis with 97 % recall but is not embedded in an autonomous reasoning loop.

We argue that these systems each capture a necessary component of a defensible agent, and that their composition under an explicit *grounding rule* and *five-layer safety gate* yields a system whose decisions are reproducibly auditable.

## 1.2 Threat model

Raven assumes three concurrent adversaries:

- **A-DATA** — an attacker who controls inputs the agent processes (e.g., scanned binaries, Git issues, web responses, RPC payloads). A-DATA may attempt indirect prompt injection, obfuscated jailbreak strings, or malformed inputs designed to crash the analyser.
- **A-USER** — a legitimate-but-compromised operator. A-USER may attempt to leverage their credentials to escalate the agent's authority, disable safety primitives, or trigger destructive commands.
- **A-VENDOR** — an LLM provider that becomes unavailable, silently degraded, censored, or compromised. A-VENDOR may return refusal, return adversarial output, or fail entirely.

Raven's three contributions map directly to these threats:

| Adversary | Primary mitigation | Section |
|-----------|--------------------|---------|
| A-DATA | Parseltongue normalisation + jailbreak fingerprint detector + tool grounding rule | §3.2, §3.4 |
| A-USER | RBAC + tiered approval gate + `UNRECOVERABLE_BLOCKLIST` (no override) | §3.5 |
| A-VENDOR | Multi-provider abstraction + hot-swap + base-URL allowlist + provider-hardness score | §3.3 |

## 1.3 Contributions

This whitepaper makes the following contributions:

1. **A formal definition of Compositional Defense Pipelines (CDP)** — a small grammar over evidence sources, LLM operators, and safety gates that constrains the agent's reasoning to auditable forms (§3.1).

2. **A grounding theorem** — we show that any CDP execution either (a) terminates at a deterministic evidence source, (b) is refused by the safety gate, or (c) produces an explicitly *scored* hypothesis with its evidence trace attached (§3.6).

3. **A reference implementation** — ≈ 38 k LoC of Python, 286 unit tests passing, 20+ integrated security tools under a unified `ToolAdapter` interface, eight LLM providers under a unified `BaseAIClient` ABC, and an Argon2id + JWT + RBAC + Approval Gate + Jailbreak Middleware production stack (§4).

4. **Empirical evaluation along five axes** —
   - tool-grounding fidelity (§5.2),
   - jailbreak resistance (§5.3),
   - provider failover latency (§5.4),
   - approval-gate adversarial robustness (§5.5),
   - continual-learning improvement (§5.6).

5. **Two case studies** — (i) end-to-end audit of an Anchor Solana program via ARES-v3 + LLM summarisation, and (ii) malware triage on a compiled Solana `.so` via Ghidra + eBPF processor + radare2 + YARA composition (§6).

## 1.4 Roadmap

§2 surveys related work in LLM-driven security, multi-provider abstractions, and deterministic security tooling. §3 introduces CDP formally and details the five-layer safety gate. §4 describes the reference implementation. §5 presents the empirical evaluation. §6 walks two case studies end-to-end. §7 discusses limitations, future work, and concludes.

## 1.5 Reproducibility

All experiments in §5 and §6 are reproducible from the open-source repository:

```bash
git clone https://github.com/<owner>/project-raven
cd project-raven
python3 -m pytest tests/ -v                     # 286 tests, ≤ 30 s
docker compose up -d                            # full stack: API, ML, Postgres, Redis
raven tools ares ./bench/sample-anchor-prog     # ARES-v3 audit
raven tui                                       # interactive TUI
```

Replication scripts for each table and figure live in `bench/whitepaper/` and `tests/whitepaper/`.
