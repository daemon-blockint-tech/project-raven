"""ARES-v3 adapter — Deterministic Static Audit for Solana Smart Contracts.

Wraps the ``ares`` CLI binary from:
  https://github.com/daemon-blockint-tech/ARES-v3

Install:
  git clone https://github.com/daemon-blockint-tech/ARES-v3
  cd ARES-v3
  cargo install --path crates/ares-cli

ARES detects 12 Solana vulnerability classes via a 4-phase pipeline:
  regex extraction → AST parsing → taint analysis → deterministic judge
  97% micro-averaged recall, 0.94 F1, sub-5-second scans, zero API cost.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult

log = logging.getLogger(__name__)

# Canonical vulnerability class catalogue (ARES-v3 specification)
VULN_CLASSES: List[str] = [
    "type-cosplay",
    "ownership-check",
    "has-one-constraint",
    "seeds-constraint",
    "signer-authorization",
    "arbitrary-cpi",
    "initialization-frontrunning",
    "reentrancy-risk",
    "duplicate-mutable-accounts",
    "arithmetic-overflow",
    "close-account",
    "account-reloading",
]


class AresAdapter(ToolAdapter):
    """Subprocess adapter for the ARES-v3 Solana static auditor."""

    binary = os.environ.get("ARES_BINARY", "ares")
    tool_name = "ares-v3"
    install_hint = (
        "git clone https://github.com/daemon-blockint-tech/ARES-v3 && "
        "cd ARES-v3 && cargo install --path crates/ares-cli"
    )

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config or {})
        self._timeout = int(
            (config or {}).get("ares_timeout")
            or os.environ.get("ARES_TIMEOUT", "120")
        )
        self._policy = (
            (config or {}).get("ares_policy_file")
            or os.environ.get("ARES_POLICY_FILE", "")
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        fmt: str = "json",
        output: str = "",
        policy: str = "",
        use_llm: bool = False,
    ) -> ToolResult:
        """Run a deterministic ARES audit on a Solana program source directory.

        Args:
            target:   Path to the Solana program directory (Anchor / Solitaire).
            fmt:      Output format — ``json`` (default), ``md``, ``html``.
            output:   Optional path to write the report file.
            policy:   Optional ``ares.toml`` policy config path.
            use_llm:  Enable LLM-as-Judge enrichment (requires API key config).

        Returns:
            :class:`ToolResult` with ``parsed`` set to the vulnerability dict.
        """
        if not self.is_available():
            return ToolResult(
                tool=self.tool_name,
                success=False,
                target=target,
                error=f"ares binary not found. {self.install_hint}",
            )

        cmd: List[str] = [self.binary, "scan", "--target", target, "--format", fmt]

        effective_policy = policy or self._policy
        if effective_policy:
            cmd += ["--policy", effective_policy]

        if output:
            cmd += ["--output", output]

        if use_llm:
            cmd.append("--llm")

        result = self._run(cmd, target=target, timeout=self._timeout)

        if result.success and fmt == "json":
            result.parsed = self._parse_json_output(result.stdout)
        elif result.success:
            result.parsed = {"raw": result.stdout, "format": fmt}

        return result

    def benchmark(self, ground_truth: str = "") -> ToolResult:
        """Run the ARES benchmark suite against the bundled ground truth.

        Args:
            ground_truth: Optional path to a custom ``ground_truth.json``.

        Returns:
            :class:`ToolResult` with benchmark scores in ``parsed``.
        """
        if not self.is_available():
            return ToolResult(
                tool=self.tool_name,
                success=False,
                error=f"ares binary not found. {self.install_hint}",
            )

        cmd = [self.binary, "benchmark", "--format", "json"]
        if ground_truth:
            cmd += ["--ground-truth", ground_truth]

        result = self._run(cmd, target="benchmark", timeout=300)
        if result.success:
            result.parsed = self._parse_json_output(result.stdout)
        return result

    def list_classes(self) -> ToolResult:
        """Return the canonical list of vulnerability classes ARES detects."""
        return ToolResult(
            tool=self.tool_name,
            success=True,
            parsed={"vulnerability_classes": VULN_CLASSES, "count": len(VULN_CLASSES)},
        )

    def setup_llm(self, provider: str = "openai", api_key: str = "") -> ToolResult:
        """Configure ARES LLM-as-Judge (persists to ~/.ares/config.toml)."""
        if not self.is_available():
            return ToolResult(
                tool=self.tool_name,
                success=False,
                error=f"ares binary not found. {self.install_hint}",
            )

        cmd = [self.binary, "llm", "setup", "--provider", provider]
        if api_key:
            cmd += ["--api-key", api_key]
        return self._run(cmd, target="llm-setup", timeout=30)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_json_output(self, raw: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse ARES JSON report output."""
        raw = raw.strip()
        if not raw:
            return None
        # ARES may emit leading log lines before the JSON blob.
        # Walk from the end to find the outermost JSON object.
        for i, ch in enumerate(raw):
            if ch == "{":
                try:
                    return json.loads(raw[i:])
                except json.JSONDecodeError:
                    pass
        log.warning("ares: could not parse JSON output; returning raw string")
        return {"raw": raw}
