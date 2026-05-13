# 6. Case Studies

We walk through two end-to-end CDP executions on realistic targets. Each shows the data flow, the gates engaged, the tool oracles called, and the evidence trace attached to the final conclusion.

## 6.1 Case A — Anchor Solana program audit (ARES-v3 + LLM summary)

### 6.1.1 Target

A 1 350-LoC Anchor program (`programs/lending/`) with three known seeded vulnerabilities:

- **V1:** missing `signer-authorization` on a withdraw instruction.
- **V2:** unchecked `u64` arithmetic in interest calculation (`arithmetic-overflow`).
- **V3:** `type-cosplay` between a borrower and a deposit account (no discriminator check).

The program is provided as a directory; the agent is told only: *"Audit this Solana program."*

### 6.1.2 Pipeline trace

```
user prompt
   │
   ▼  G1 Parseltongue  ─► normalised (no obfuscation found)
   ▼  G2 Jailbreak     ─► score 0.02 (pass)
   ▼  G3 RBAC          ─► operator role verified
   ▼
   L  plan emitted by openrouter_agent:
        tool_call_1 = ares.scan(target="./programs/lending", fmt="json")
   ▼
   T  AresAdapter.scan()  ─► ToolResult(success=True, parsed={
           findings: [
             {class: signer-authorization, severity: HIGH,  loc: instructions/withdraw.rs:42},
             {class: arithmetic-overflow,  severity: MED,   loc: state/interest.rs:88},
             {class: type-cosplay,         severity: HIGH,  loc: state/account.rs:12}
           ],
           recall: 0.97, scan_time_ms: 4710
       })
   ▼
   L  summarise with evidence trace E = [tool_call_1.parsed.findings]
   ▼
   Grounding verifier (Rule G-Bind):
        evidence non-empty → admissible ✓
   ▼
   c = "Three vulnerabilities found in lending program. ..."
       + evidence: [ares-v3:signer-authorization@instructions/withdraw.rs:42, …]
```

### 6.1.3 Output (excerpt)

```markdown
## Audit findings for `programs/lending/`

ARES-v3 detected 3 vulnerabilities (recall 97 %, scan time 4.71 s):

1. **HIGH — signer-authorization** at `instructions/withdraw.rs:42`
   Withdraw instruction does not require a `Signer` account; any caller
   passing the borrower account can drain it.
   *Recommended fix:* add `borrower: Signer<'info>` to the accounts struct.

2. **MEDIUM — arithmetic-overflow** at `state/interest.rs:88`
   `principal * rate_bps / 10_000` may overflow when principal > 2^53.
   *Recommended fix:* use `checked_mul` and `checked_div`.

3. **HIGH — type-cosplay** at `state/account.rs:12`
   `Account<'info, Borrower>` accepted without discriminator check;
   a deposit account can be passed where a borrower is expected.
   *Recommended fix:* use Anchor's `#[account]` derive with explicit
   discriminator and `has_one` constraints.

Evidence:
  - ares-v3@v0.9.4 scan of ./programs/lending/, JSON output attached.
```

### 6.1.4 What CDP prevents

If the LLM had been asked the same question without ARES-v3 in the pipeline, it would have produced a plausible-looking finding list. The grounding verifier would have *refused* to return it, because the evidence trace would be empty. The operator either gets a deterministic finding or no finding — never a hallucinated one.

### 6.1.5 Reproduction

```bash
raven tools ares ./programs/lending --format json
raven agent chat
> Audit ./programs/lending
```

## 6.2 Case B — Compiled Solana program triage (Ghidra + eBPF + radare2 + YARA)

### 6.2.1 Target

A compiled Solana program (`./suspect.so`, ~ 220 KiB BPF ELF) recovered from an on-chain account. No source available. The agent is told: *"Determine whether this compiled Solana program is malicious."*

### 6.2.2 Pipeline trace

```
user prompt
   │
   ▼  G1 + G2 + G3 (pass)
   ▼
   L  plan:
        tc1 = ebpf_ghidra.setup_status()
        (gated branch: if status.success, then tc2..tc4)
        tc2 = ebpf_ghidra.analyze_solana_so(binary_path="./suspect.so")
        tc3 = radare2.analyze(binary_path="./suspect.so")
        tc4 = yara.scan_with_rules(rules="solana-malware.yar", target="./suspect.so")
   ▼
   T  tc1 → success=True, ext_path=...eBPF*Solana*.zip
   T  tc2 → ToolResult(success=True, parsed={functions: [...], strings: [...]})
   T  tc3 → ToolResult(success=True, parsed={imports: [...], xrefs: [...]})
   T  tc4 → ToolResult(success=True, parsed={matches: ["solana_drain_lp_v1"]})
   ▼
   M  zero_day_predictor.score(features_from(tc2, tc3))  → 0.81
   ▼
   L  summarise with evidence E = [tc2, tc3, tc4, M(0.81)]
   ▼
   Grounding verifier: admissible ✓
   ▼
   c = "Highly likely malicious — YARA matched known LP-drain family; ..."
```

### 6.2.3 Output (excerpt)

```markdown
## Triage: ./suspect.so

**Verdict: likely malicious (confidence: 0.85)**

Evidence:

1. **YARA** matched the `solana_drain_lp_v1` rule on the binary
   (rules/solana-malware.yar:34). This rule fingerprints a known
   liquidity-pool drainer family active since Q4 2025.

2. **Ghidra (+ eBPF Solana processor)** decompiled the entry point and
   found a CPI to the `raydium_swap` instruction with the pool
   authority replaced by a hardcoded attacker-controlled key
   (function `_sBPF_entry`, address 0x140).

3. **radare2** found cross-references from the entry to a syscall
   table that issues `sol_invoke_signed` against the same
   attacker key.

4. **Classical-ML zero-day predictor** scored the binary 0.81 (above
   the 0.7 threshold), driven primarily by the
   imports-vs-string-table feature.

Recommended action: deny all transactions involving program ID
`<base58 of suspect.so>`; alert downstream DeFi integrators.
```

### 6.2.4 What CDP enables

Note the *composition*: a Solana-specific tool (eBPF Ghidra processor), a generic binary-analysis tool (radare2), a signature-based detector (YARA), and a classical-ML score all converge on a single conclusion. The LLM's role is purely to plan the tools and write the human-readable summary; every assertion is anchored to one of the four evidence sources.

Had any single oracle been absent — say, the eBPF processor extension not installed — the agent would have surfaced that gap via `ebpf_ghidra.setup_status()` and either continued with partial evidence (lower confidence) or refused. **No oracle, no finding.**

### 6.2.5 Reproduction

```bash
raven tools ebpf-ghidra                            # check extension
raven tools run ebpf_ghidra analyze_solana_so binary_path=./suspect.so
raven tools run yara scan_with_rules rules_path=./rules/solana-malware.yar target_path=./suspect.so
raven agent chat
> Triage ./suspect.so for Solana malware indicators
```

## 6.3 Discussion

Both case studies exhibit three properties that the methodology guarantees:

1. **Every finding has a deterministic backing.** The user can audit each claim against a specific `ToolResult` or ML verdict.
2. **The LLM is interchangeable.** Re-running the same pipeline with `anthropic:claude-3-5-sonnet`, `openai:gpt-4o-mini`, or a local `lmstudio:granite-4-micro` produces the same evidence trace; only the prose summary varies.
3. **The safety gate is invisible when no danger is present.** Neither case study triggers an approval pause because neither pipeline emits a `DANGEROUS_PATTERN` action — but had the LLM attempted to, say, `rm` a recovered binary, \(G_5\) would have refused unconditionally.

This is what we mean by *compositional* defense: heterogeneous tools, an LLM orchestrator, and a safety gate all operating under a single grounding contract, with the gate intervening only when the contract is at risk of being broken.
