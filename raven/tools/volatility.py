"""Volatility 3 — memory forensics.

Wraps the ``vol`` CLI / ``volatility3`` Python package. Used by the
incident-response / forensics flows when an operator hands Raven a memory
image.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult, is_safe_arg


# A conservative allowlist of common plugins. Operators can extend via the
# constructor's config dict.
DEFAULT_PLUGINS = [
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
    "windows.malfind.Malfind",
    "windows.dlllist.DllList",
    "linux.bash.Bash",
    "linux.pslist.PsList",
    "linux.malfind.Malfind",
    "mac.pslist.PsList",
]


class VolatilityAdapter(ToolAdapter):
    binary = "vol"
    tool_name = "volatility3"
    install_hint = "pip install volatility3"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self.allowed_plugins = set(self.config.get("vol_allowed_plugins", DEFAULT_PLUGINS))

    def run_plugin(
        self,
        memory_image: str,
        plugin: str,
        extra_args: Optional[List[str]] = None,
    ) -> ToolResult:
        """Run a Volatility plugin against a memory image."""
        if not os.path.isfile(memory_image):
            return ToolResult(tool=self.tool_name, success=False, target=memory_image,
                              error="memory image not found")
        if not is_safe_arg(memory_image):
            return ToolResult(tool=self.tool_name, success=False, target=memory_image,
                              error="unsafe image path")
        if plugin not in self.allowed_plugins:
            return ToolResult(tool=self.tool_name, success=False, target=memory_image,
                              error=f"plugin not in allowlist: {plugin!r}")
        args = [self.binary, "-f", memory_image, "-r", "json", plugin]
        for arg in (extra_args or []):
            if not is_safe_arg(arg):
                return ToolResult(tool=self.tool_name, success=False, target=memory_image,
                                  error=f"unsafe plugin arg: {arg}")
            args.append(arg)
        result = self._run(args, target=memory_image)
        result.parsed = self._parse(result.stdout)
        return result

    def list_plugins(self) -> ToolResult:
        return self._run([self.binary, "--help"])

    @staticmethod
    def _parse(text: str) -> Any:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw_preview": text[:2000]}
