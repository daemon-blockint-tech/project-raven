"""radare2 / r2pipe integration with optional r2ghidra plugin.

Two paths:
  * **r2pipe** (preferred) — Python bindings around r2 process, used as a
    structured query interface (call ``analyze()``, ``functions()``,
    ``decompile()``).
  * **CLI fallback** — ``r2 -c "<cmd>" -q <binary>`` for one-shot queries.

When the r2ghidra plugin is installed, ``decompile()`` will use Ghidra's
decompiler via the ``pdg`` r2 command for higher-fidelity output.
"""

from __future__ import annotations

import json
import logging
import shutil
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult, is_safe_arg

log = logging.getLogger(__name__)


class Radare2Adapter(ToolAdapter):
    binary = "r2"
    install_hint = (
        "https://github.com/radareorg/radare2 (system) + "
        "pip install r2pipe + r2pm -ci r2ghidra-dec (optional)"
    )

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._r2pipe: Any = None
        try:
            import r2pipe as _r2pipe  # type: ignore
            self._r2pipe = _r2pipe
        except ImportError:
            self._r2pipe = None
        self._has_r2ghidra = shutil.which("r2ghidra") is not None

    def is_available(self) -> bool:
        return self._r2pipe is not None or super().is_available()

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------

    def analyze(self, binary_path: str) -> ToolResult:
        """Open the binary, run analysis (aaaa), return symbol counts."""
        if not is_safe_arg(binary_path):
            return ToolResult(tool=self.tool_name, success=False, target=binary_path,
                              error="invalid binary path")
        if self._r2pipe is not None:
            return self._analyze_pipe(binary_path)
        return self._analyze_cli(binary_path)

    def functions(self, binary_path: str) -> ToolResult:
        if self._r2pipe is None:
            return self._cli(binary_path, "aflj")
        r2 = self._r2pipe.open(binary_path)
        try:
            r2.cmd("aaa")
            fns = r2.cmdj("aflj") or []
        finally:
            r2.quit()
        return ToolResult(tool=self.tool_name, success=True, target=binary_path,
                          parsed=fns)

    def decompile(self, binary_path: str, function: str = "main") -> ToolResult:
        """Decompile a function via r2ghidra (``pdg``) if available, else
        r2's built-in pseudo-decompiler (``pdc``)."""
        if not is_safe_arg(binary_path) or not is_safe_arg(function):
            return ToolResult(tool=self.tool_name, success=False,
                              target=binary_path, error="unsafe input")
        cmd = "pdg" if self._has_r2ghidra else "pdc"
        if self._r2pipe is None:
            return self._cli(binary_path, f"aaa;s sym.{function};{cmd}")
        r2 = self._r2pipe.open(binary_path)
        try:
            r2.cmd("aaa")
            r2.cmd(f"s sym.{function}")
            text = r2.cmd(cmd)
        finally:
            r2.quit()
        return ToolResult(tool=self.tool_name, success=True,
                          target=f"{binary_path}#{function}",
                          stdout=text or "",
                          parsed={"decompiler": "r2ghidra" if self._has_r2ghidra else "pdc",
                                  "function": function})

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _analyze_pipe(self, path: str) -> ToolResult:
        import time
        start = time.perf_counter()
        try:
            r2 = self._r2pipe.open(path)
            r2.cmd("aaa")
            info = r2.cmdj("ij") or {}
            fns = r2.cmdj("aflj") or []
            r2.quit()
        except Exception as exc:
            self._record_metric(success=False)
            return ToolResult(tool=self.tool_name, success=False, target=path,
                              error=f"r2pipe error: {exc}",
                              execution_time=time.perf_counter() - start)
        self._record_metric(success=True)
        return ToolResult(
            tool=self.tool_name, success=True, target=path,
            execution_time=time.perf_counter() - start,
            parsed={
                "function_count": len(fns),
                "arch": (info.get("bin") or {}).get("arch"),
                "bits": (info.get("bin") or {}).get("bits"),
                "has_r2ghidra": self._has_r2ghidra,
            },
        )

    def _analyze_cli(self, path: str) -> ToolResult:
        return self._cli(path, "aaa; aflj")

    def _cli(self, path: str, command: str) -> ToolResult:
        if not is_safe_arg(path):
            return ToolResult(tool=self.tool_name, success=False, target=path,
                              error="unsafe path")
        # r2 commands often contain semicolons; we pass via -c and accept the
        # adapter's safety check only on the path itself.
        import subprocess
        import time
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                [self.binary, "-q", "-c", command, path],
                capture_output=True, timeout=self.timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            self._record_metric(success=False)
            return ToolResult(tool=self.tool_name, success=False, target=path,
                              error="timed out",
                              execution_time=time.perf_counter() - start)
        self._record_metric(success=proc.returncode == 0)
        return ToolResult(
            tool=self.tool_name, success=proc.returncode == 0, target=path,
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=proc.stderr.decode("utf-8", errors="replace"),
            exit_code=proc.returncode,
            execution_time=time.perf_counter() - start,
            cmd=f"{self.binary} -q -c {command!r} {path}",
        )
