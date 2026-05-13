"""Recon-ng module runner.

Recon-ng is a full interactive OSINT framework. For agent-driven use, we
invoke it in batch mode through a generated resource file so a single shot
runs ``modules load <mod> → options set <…> → run``.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult, is_safe_arg


# Recon-ng workspace must match ``[A-Za-z0-9_-]{1,32}`` to avoid filesystem
# surprises.
import re
_WS_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class ReconNgAdapter(ToolAdapter):
    binary = "recon-ng"
    install_hint = (
        "git clone https://salsa.debian.org/pkg-security-team/recon-ng.git "
        "/opt/recon-ng && pip install -r /opt/recon-ng/REQUIREMENTS"
    )

    def run_module(
        self,
        module: str,
        options: Dict[str, str],
        workspace: str = "raven",
    ) -> ToolResult:
        """Run a recon-ng module in batch mode.

        Example:
            adapter.run_module(
                "recon/domains-hosts/hackertarget",
                {"SOURCE": "example.com"},
            )
        """
        if not _WS_RE.match(workspace):
            return ToolResult(tool=self.tool_name, success=False,
                              target=workspace, error="invalid workspace name")
        if not is_safe_arg(module.replace("/", "_")):
            return ToolResult(tool=self.tool_name, success=False,
                              target=module, error="invalid module path")
        for k, v in options.items():
            if not is_safe_arg(k) or not is_safe_arg(v):
                return ToolResult(tool=self.tool_name, success=False,
                                  target=module,
                                  error=f"invalid option: {k}={v}")

        # Build resource script
        lines = [
            f"workspaces load {workspace}",
            f"modules load {module}",
        ]
        for k, v in options.items():
            lines.append(f"options set {k} {v}")
        lines.append("run")
        lines.append("exit")
        script = "\n".join(lines) + "\n"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rc", delete=False, prefix="raven_reconng_"
        ) as f:
            f.write(script)
            rc_path = f.name

        try:
            args = [self.binary, "--no-version", "--no-marketplace", "-r", rc_path]
            return self._run(args, target=module)
        finally:
            try:
                os.unlink(rc_path)
            except OSError:
                pass
