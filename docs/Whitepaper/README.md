# Project Raven Whitepaper

> **Raven: Compositional Defense Pipelines — A Tool-Grounded, Multi-Provider AI Architecture for Autonomous Adversarial Defense**

*Working draft · v0.1 · May 2026*

---

## Table of Contents

| # | Section | File |
|---|---------|------|
| 0 | Abstract | [`00-abstract.md`](./00-abstract.md) |
| 1 | Introduction | [`01-introduction.md`](./01-introduction.md) |
| 2 | Related Work | [`02-related-work.md`](./02-related-work.md) |
| 3 | **Methodology — Compositional Defense Pipelines (CDP)** | [`03-methodology.md`](./03-methodology.md) |
| 4 | Implementation | [`04-implementation.md`](./04-implementation.md) |
| 5 | Evaluation | [`05-evaluation.md`](./05-evaluation.md) |
| 6 | Case Studies | [`06-case-studies.md`](./06-case-studies.md) |
| 7 | Discussion & Conclusion | [`07-discussion-conclusion.md`](./07-discussion-conclusion.md) |
| R | References | [`references.md`](./references.md) |

## Core Contribution

We introduce **Compositional Defense Pipelines (CDP)**: a formal architecture for autonomous defensive agents in which every assertion produced by a large language model (LLM) is *grounded* in one of three deterministic evidence layers:

1. A **tool oracle** — subprocess-invoked deterministic analyser (e.g., ARES-v3, YARA, radare2, Ghidra, Nmap) returning structured `ToolResult`.
2. A **classical ML detector** — IsolationForest, RandomForest, or autoencoder verdicts trained on labelled corpora.
3. A **scored LLM hypothesis** — explicitly tagged with a confidence score derived from cross-validation against (1) and (2).

This grounding rule, combined with a five-layer safety gate (Parseltongue → Jailbreak → RBAC → Approval → Unrecoverable Blocklist), produces an autonomous defensive system whose decisions are *auditable*, *reproducible*, and *bounded by hard refusals* that no operator privilege escalation can override.

## Key Empirical Claims

| Claim | Measurement | Reference |
|-------|-------------|-----------|
| ARES-v3 tool grounding achieves 97% recall on Solana vulnerability classes | Public benchmark, 20 protocols | §5.2 |
| Parseltongue normalisation lifts jailbreak detection F1 from 0.71 → 0.93 | 8 L1B3RT4S attack families × 33 decoders | §5.3 |
| Multi-provider hot-swap reduces mean recovery time from provider outage from 12 min → 8 s | Synthetic outage injection | §5.4 |
| Approval gate `UNRECOVERABLE_BLOCKLIST` prevents 100% of catastrophic actions across 1,200 adversarial prompts | Red-team corpus | §5.5 |
| Continual-learning loop (Tinker LoRA) raises CyberGym pass-rate by 11 pp after 3 promotion cycles | A/B router at 5% traffic | §5.6 |

## Citation

```bibtex
@techreport{raven2026cdp,
  title  = {Raven: Compositional Defense Pipelines for Autonomous Adversarial Defense},
  author = {Nugroho, Rade and {Project Raven Contributors}},
  year   = {2026},
  institution = {Project Raven},
  type   = {Technical Whitepaper},
  url    = {https://github.com/<owner>/project-raven/tree/main/docs/Whitepaper}
}
```

## How to read this whitepaper

- **Practitioners** — read §0, §3, §6, §7.
- **Reviewers / academics** — read in order, citation graph in [`references.md`](./references.md).
- **Operators** — read §4 alongside [`docs/tools.md`](../tools.md) and [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
