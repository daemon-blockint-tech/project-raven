"""Unified subprocess adapter base for Raven's external security tools.

Every tool integration (httpx, subfinder, naabu, yara, jadx, radare2, frida,
volatility, searchsploit, recon-ng, cyberchef, …) inherits from
:class:`ToolAdapter`. The base handles:

  * availability detection (``which``)
  * argument shell-safety (rejects unsanitised metacharacters)
  * timeout + structured result type
  * audit-log breadcrumb + Prometheus counter
  * graceful degradation when the binary is missing

Inspired by ProjectDiscovery's ``pd-agent`` (subprocess + result upload)
and the agentic-malware-analysis project (per-sample case dir + helper
scripts pattern).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Common result type
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Uniform result envelope returned by every adapter."""

    tool: str
    success: bool
    target: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    execution_time: float = 0.0
    parsed: Any = None              # tool-specific structured output
    error: Optional[str] = None
    cmd: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "success": self.success,
            "target": self.target,
            "exit_code": self.exit_code,
            "execution_time": round(self.execution_time, 3),
            "parsed": self.parsed,
            "error": self.error,
            "cmd": self.cmd,
            "stdout_preview": self.stdout[:2000],
            "stderr_preview": self.stderr[:1000],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Safe-arg pattern: alnum, dot, slash, colon, dash, underscore, comma, equals,
# at, plus, percent, tilde, brackets, hash, and a few network glob chars.
_SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9._/:\-,=@+%~\[\]#?*]+$")


def is_safe_arg(arg: str) -> bool:
    """Reject shell metacharacters before we ever hand strings to subprocess."""
    if not arg:
        return False
    return _SAFE_ARG_RE.match(arg) is not None


def which(binary: str) -> Optional[str]:
    """Return absolute path of ``binary`` if on PATH, else None."""
    return shutil.which(binary)


# ---------------------------------------------------------------------------
# Base adapter
# ---------------------------------------------------------------------------

class ToolAdapter:
    """Abstract subprocess adapter.

    Subclass and set ``binary`` + ``tool_name``. The base provides:

      * :meth:`is_available` — ``which`` check
      * :meth:`_run` — sanitised subprocess.run() with timeout + result
        wrapping and Prometheus metric increment
      * :meth:`required_binary_msg` — operator-friendly install hint
    """

    binary: str = ""              # override
    tool_name: str = ""            # override; defaults to binary
    install_hint: str = ""

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config: Dict[str, Any] = config or {}
        self.timeout: int = int(self.config.get(f"{self.binary}_timeout", 120))
        if not self.tool_name:
            self.tool_name = self.binary

    # ---- availability ----------------------------------------------

    def is_available(self) -> bool:
        return which(self.binary) is not None

    def required_binary_msg(self) -> str:
        base = f"{self.tool_name} binary not found on PATH (looked for {self.binary!r})."
        if self.install_hint:
            base += f" Install: {self.install_hint}"
        return base

    # ---- subprocess --------------------------------------------------

    def _run(
        self,
        args: Sequence[str],
        *,
        timeout: Optional[int] = None,
        stdin_data: Optional[bytes] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        target: str = "",
    ) -> ToolResult:
        """Run subprocess with strict-arg validation + Prometheus metric."""
        # Reject unsanitised args before they ever reach the syscall.
        unsafe = [a for a in args[1:] if not is_safe_arg(str(a))]
        if unsafe:
            return ToolResult(
                tool=self.tool_name,
                success=False,
                target=target,
                error=f"refused unsafe argument: {unsafe[0]!r}",
                cmd=" ".join(args),
            )

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                list(args),
                input=stdin_data,
                capture_output=True,
                timeout=timeout or self.timeout,
                cwd=cwd,
                env=env,
                check=False,
            )
            exec_time = time.perf_counter() - start
            self._record_metric(success=proc.returncode == 0)
            return ToolResult(
                tool=self.tool_name,
                success=proc.returncode == 0,
                target=target,
                stdout=proc.stdout.decode("utf-8", errors="replace"),
                stderr=proc.stderr.decode("utf-8", errors="replace"),
                exit_code=proc.returncode,
                execution_time=exec_time,
                cmd=" ".join(args),
            )
        except subprocess.TimeoutExpired:
            self._record_metric(success=False)
            return ToolResult(
                tool=self.tool_name,
                success=False,
                target=target,
                error=f"timed out after {timeout or self.timeout}s",
                execution_time=time.perf_counter() - start,
                cmd=" ".join(args),
            )
        except FileNotFoundError as exc:
            self._record_metric(success=False)
            return ToolResult(
                tool=self.tool_name,
                success=False,
                target=target,
                error=self.required_binary_msg(),
                cmd=" ".join(args),
            )
        except Exception as exc:
            self._record_metric(success=False)
            return ToolResult(
                tool=self.tool_name,
                success=False,
                target=target,
                error=f"{type(exc).__name__}: {exc}",
                execution_time=time.perf_counter() - start,
                cmd=" ".join(args),
            )

    def _record_metric(self, success: bool) -> None:
        try:
            from raven.observability.metrics import TOOL_INVOCATIONS
            TOOL_INVOCATIONS.labels(
                tool=self.tool_name,
                outcome="success" if success else "failure",
            ).inc()
        except Exception:
            pass
