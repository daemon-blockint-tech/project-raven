"""YARA scanner.

Two paths:

  * **Python module** — when `yara-python` is installed (preferred): no
    subprocess, fastest, returns rich match metadata.
  * **CLI fallback** — calls the ``yara`` binary as a subprocess.

Inspired by [VirusTotal/yara](https://github.com/VirusTotal/yara) and the
[agentic-malware-analysis](https://github.com/mrphrazer/agentic-malware-analysis)
project (which bundles Yara-Rules/rules).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult, is_safe_arg

log = logging.getLogger(__name__)


class YaraScanner(ToolAdapter):
    binary = "yara"
    install_hint = "apt install yara  /  brew install yara  /  pip install yara-python"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._py_yara: Any = None
        try:
            import yara as _yara  # type: ignore
            self._py_yara = _yara
        except ImportError:
            self._py_yara = None

    def is_available(self) -> bool:
        return self._py_yara is not None or super().is_available()

    # ------------------------------------------------------------------
    # Python-module path
    # ------------------------------------------------------------------

    def scan_with_rules(
        self,
        rules_path: str,
        target_path: str,
        timeout_seconds: int = 30,
    ) -> ToolResult:
        """Compile ``rules_path`` and scan ``target_path``. Uses yara-python
        when available, otherwise falls back to the CLI."""
        if not os.path.isfile(target_path):
            return ToolResult(tool=self.tool_name, success=False, target=target_path,
                              error="target file not found")
        if not os.path.exists(rules_path):
            return ToolResult(tool=self.tool_name, success=False, target=target_path,
                              error="rules path not found")

        if self._py_yara is not None:
            return self._scan_python(rules_path, target_path, timeout_seconds)
        return self._scan_cli(rules_path, target_path, timeout_seconds)

    def _scan_python(self, rules_path: str, target_path: str, timeout: int) -> ToolResult:
        import time as _time
        start = _time.perf_counter()
        try:
            if os.path.isdir(rules_path):
                # Pre-compile every .yar under the directory
                filepaths = {}
                for root, _, files in os.walk(rules_path):
                    for fn in files:
                        if fn.endswith((".yar", ".yara")):
                            filepaths[os.path.splitext(fn)[0]] = os.path.join(root, fn)
                rules = self._py_yara.compile(filepaths=filepaths)
            else:
                rules = self._py_yara.compile(filepath=rules_path)
            matches = rules.match(target_path, timeout=timeout)
        except Exception as exc:
            self._record_metric(success=False)
            return ToolResult(
                tool=self.tool_name, success=False, target=target_path,
                error=f"yara compile/match failed: {exc}",
                execution_time=_time.perf_counter() - start,
            )
        self._record_metric(success=True)
        parsed = [
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": list(m.tags),
                "meta": dict(m.meta),
                "strings_count": len(getattr(m, "strings", []) or []),
            }
            for m in matches
        ]
        return ToolResult(
            tool=self.tool_name,
            success=True,
            target=target_path,
            execution_time=_time.perf_counter() - start,
            parsed=parsed,
        )

    def _scan_cli(self, rules_path: str, target_path: str, timeout: int) -> ToolResult:
        if not is_safe_arg(rules_path) or not is_safe_arg(target_path):
            return ToolResult(tool=self.tool_name, success=False, target=target_path,
                              error="path failed safety check")
        args = [self.binary, "-g", "-m", "-w", rules_path, target_path]
        result = self._run(args, timeout=timeout, target=target_path)
        # parse: each match line is "<rulename> [tags] [meta] <file>"
        parsed: List[Dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            parsed.append({"rule": parts[0] if parts else line, "raw": line})
        result.parsed = parsed
        return result
