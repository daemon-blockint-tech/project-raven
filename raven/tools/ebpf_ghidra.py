"""Solana eBPF-for-Ghidra integration helper.

This module extends the existing :class:`GhidraAnalyzer` with support for the
Solana eBPF processor extension:
  https://github.com/blastrock/Solana-eBPF-for-Ghidra

The extension must be installed separately (it is a Ghidra Java plugin, not a
subprocess binary).  This adapter:

  1. Detects whether the extension is installed in ``$GHIDRA_INSTALL_DIR``.
  2. Provides ``analyze_solana_so(path)`` — headless analysis of compiled
     Solana ``.so`` programs using the eBPF processor language.
  3. Surfaces install instructions when the extension is missing.

Install extension:
  Option A — Gradle build:
    git clone https://github.com/blastrock/Solana-eBPF-for-Ghidra
    cd Solana-eBPF-for-Ghidra
    GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle
    # Then in Ghidra: File → Install Extensions → select the built .zip

  Option B — pre-built release:
    Download from https://github.com/blastrock/Solana-eBPF-for-Ghidra/releases
    In Ghidra: File → Install Extensions → select downloaded .zip
"""

from __future__ import annotations

import glob
import logging
import os
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult

log = logging.getLogger(__name__)

# Ghidra language ID for Solana eBPF (defined by the extension's .ldefs)
SOLANA_EBPF_LANGUAGE = "eBPF:LE:64:Solana"

# Extension name patterns to detect installation
_EXTENSION_GLOB_PATTERNS = [
    "Extensions/Ghidra/*eBPF*Solana*.zip",
    "Extensions/Ghidra/*eBPFSolana*",
    "Extensions/Ghidra/*Solana-eBPF*",
    "Ghidra/Extensions/*eBPF*",
]

INSTALL_HINT = (
    "Install Solana-eBPF-for-Ghidra:\n"
    "  git clone https://github.com/blastrock/Solana-eBPF-for-Ghidra\n"
    "  cd Solana-eBPF-for-Ghidra\n"
    "  GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle\n"
    "  Then in Ghidra: File → Install Extensions → select the .zip"
)


class EBPFGhidraSetup(ToolAdapter):
    """Helper that detects and validates the Solana eBPF Ghidra extension.

    This is not a standalone binary adapter — the 'binary' check is for
    ``analyzeHeadless`` (Ghidra's headless analyzer), which must be present.
    The eBPF extension is a separate install step.
    """

    binary = os.environ.get(
        "GHIDRA_ANALYZEHEADLESS",
        os.path.join(
            os.environ.get("GHIDRA_INSTALL_DIR", "")
            or os.environ.get("GHIDRA_HOME", ""),
            "support",
            "analyzeHeadless",
        ),
    )
    tool_name = "solana-ebpf-ghidra"
    install_hint = INSTALL_HINT

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config or {})
        cfg = config or {}
        self._ghidra_dir: str = (
            cfg.get("ghidra_install_dir")
            or os.environ.get("GHIDRA_INSTALL_DIR", "")
            or os.environ.get("GHIDRA_HOME", "")
        )
        self._ghidra_scripts: str = cfg.get("ghidra_scripts_dir", "")

    # ------------------------------------------------------------------
    # Extension detection
    # ------------------------------------------------------------------

    def extension_installed(self) -> bool:
        """Return True if the eBPF-for-Ghidra extension .zip/dir is found."""
        if not self._ghidra_dir:
            return False
        for pat in _EXTENSION_GLOB_PATTERNS:
            full = os.path.join(self._ghidra_dir, pat)
            if glob.glob(full):
                return True
        return False

    def extension_path(self) -> Optional[str]:
        """Return the first matching extension path, or None."""
        if not self._ghidra_dir:
            return None
        for pat in _EXTENSION_GLOB_PATTERNS:
            full = os.path.join(self._ghidra_dir, pat)
            matches = glob.glob(full)
            if matches:
                return matches[0]
        return None

    def setup_status(self) -> ToolResult:
        """Return a ToolResult describing installation status of both
        Ghidra (analyzeHeadless) and the eBPF extension."""
        ghidra_ok = self.is_available()
        ext_ok = self.extension_installed()
        ext_path = self.extension_path()

        parsed = {
            "analyzeHeadless": ghidra_ok,
            "analyzeHeadless_path": self.binary if ghidra_ok else None,
            "ebpf_extension_installed": ext_ok,
            "ebpf_extension_path": ext_path,
            "solana_language_id": SOLANA_EBPF_LANGUAGE,
            "ghidra_install_dir": self._ghidra_dir or None,
        }

        if not ghidra_ok:
            return ToolResult(
                tool=self.tool_name,
                success=False,
                error=(
                    "Ghidra analyzeHeadless not found. Set GHIDRA_INSTALL_DIR "
                    "or GHIDRA_HOME, or install via: brew install --cask ghidra"
                ),
                parsed=parsed,
            )

        if not ext_ok:
            return ToolResult(
                tool=self.tool_name,
                success=False,
                error=f"eBPF-for-Ghidra extension not installed.\n{INSTALL_HINT}",
                parsed=parsed,
            )

        return ToolResult(
            tool=self.tool_name,
            success=True,
            parsed=parsed,
        )

    # ------------------------------------------------------------------
    # Solana .so analysis
    # ------------------------------------------------------------------

    def analyze_solana_so(
        self,
        binary_path: str,
        project_dir: str = "/tmp/raven_ghidra_projects",
        export_funcs: bool = True,
        timeout: int = 300,
    ) -> ToolResult:
        """Decompile a compiled Solana program (.so) using analyzeHeadless
        with the eBPF Solana processor language.

        Args:
            binary_path:  Path to the compiled ``.so`` Solana program.
            project_dir:  Temp directory for Ghidra project files.
            export_funcs: If True, pass ``ExportFunctions`` post-script.
            timeout:      Max seconds for analysis.

        Returns:
            :class:`ToolResult` with ``parsed`` containing decompiled output.
        """
        status = self.setup_status()
        if not status.success:
            return status

        import os as _os
        _os.makedirs(project_dir, exist_ok=True)
        prog_name = _os.path.splitext(_os.path.basename(binary_path))[0]

        cmd: List[str] = [
            self.binary,
            project_dir, f"raven_{prog_name}",
            "-import", binary_path,
            "-processor", SOLANA_EBPF_LANGUAGE,
            "-overwrite",
        ]

        if export_funcs and self._ghidra_scripts:
            cmd += ["-postScript", "ExportFunctions.java"]

        return self._run(cmd, target=binary_path, timeout=timeout)

    def is_available(self) -> bool:
        """Available when analyzeHeadless binary is on PATH or at configured path."""
        import shutil as _shutil
        # Direct path (absolute)
        if self.binary and _os_path_isfile(self.binary):
            return True
        # Fallback: check PATH
        return bool(_shutil.which("analyzeHeadless"))


def _os_path_isfile(p: str) -> bool:
    import os as _os
    try:
        return _os.path.isfile(p)
    except Exception:
        return False
