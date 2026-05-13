"""Ghidra binary analysis integration (Apache 2.0, NSA/Ghidra)

Uses Ghidra's ``analyzeHeadless`` CLI (subprocess) with the ghidra-headless
skill's Java export scripts to perform automated reverse engineering:
  - Function discovery with call graph (ExportFunctions.java → JSON)
  - String extraction (ExportStrings.java → JSON)
  - Symbol/import table (ExportSymbols.java → JSON)
  - Decompilation to C pseudocode (ExportDecompiled.java → .c file)
  - Interesting patterns (ExportAll.java → _interesting.txt)
  - Suspicious call detection (risky libc/WinAPI patterns, post-processed)

Requirements:
  - Ghidra installed: ``brew install --cask ghidra``  (macOS)
    or download from https://github.com/NationalSecurityAgency/ghidra/releases
  - JDK 17+ in PATH
  - Set GHIDRA_INSTALL_DIR (or GHIDRA_HOME) to the Ghidra root directory
  - ghidra-headless skill scripts in GHIDRA_SCRIPTS_DIR (auto-detected)

No new pip dependencies — uses only stdlib subprocess + json.

If Ghidra is not available, all methods return GhidraResult(success=False)
without raising exceptions so the kill-chain planner degrades gracefully.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import json
import os
import subprocess
import tempfile
import time


# ---------------------------------------------------------------------------
# Skill script directory (ghidra-headless)
# ---------------------------------------------------------------------------

_SKILL_SCRIPTS_DIR = os.path.join(
    os.path.expanduser("~"),
    ".agents", "skills", "ghidra-headless", "scripts", "ghidra_scripts",
)

# Common Ghidra installation paths (macOS brew, Linux, Windows)
_GHIDRA_SEARCH_PATHS = [
    os.environ.get("GHIDRA_HOME", ""),
    os.environ.get("GHIDRA_INSTALL_DIR", ""),
    "/opt/ghidra",
    "/usr/local/share/ghidra",
    os.path.expanduser("~/ghidra"),
    # brew cask on macOS installs to /Applications
    "/Applications/ghidra",
]


# ---------------------------------------------------------------------------
# Suspicious API patterns worth flagging during triage
# ---------------------------------------------------------------------------

_RISKY_CALLS: frozenset = frozenset({
    # Buffer overflow / memory unsafety
    "strcpy", "strcat", "sprintf", "gets", "scanf", "vsprintf",
    # Command / code execution
    "system", "exec", "execve", "execvp", "popen", "ShellExecute",
    "WinExec", "CreateProcessA", "CreateProcessW",
    # Heap management (use-after-free / double-free risk)
    "malloc", "free", "realloc", "calloc",
    # Process injection (Windows)
    "CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx",
    "WriteProcessMemory", "NtCreateThreadEx",
    # Network
    "WSAStartup", "connect", "send", "recv", "socket",
    "URLDownloadToFile", "InternetOpen",
    # Persistence
    "CreateFile", "WriteFile", "RegSetValue", "RegCreateKey",
})


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SuspiciousFunction:
    name: str
    address: str
    risky_calls: List[str]


@dataclass
class GhidraResult:
    """Structured output of a Ghidra analyzeHeadless run."""
    success: bool
    binary_path: str
    architecture: str = ""
    function_count: int = 0
    functions: List[Dict[str, Any]] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    suspicious: List[Dict[str, Any]] = field(default_factory=list)
    decompiled: Dict[str, str] = field(default_factory=dict)
    interesting: str = ""
    error: str = ""
    execution_time: float = 0.0
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class GhidraAnalyzer:
    """Automated binary analysis via Ghidra analyzeHeadless subprocess.

    Calls analyzeHeadless with ExportFunctions + ExportStrings + ExportSymbols
    + ExportDecompiled scripts from the ghidra-headless skill. Parses their
    JSON/text output and returns a structured ``GhidraResult``.

    Instantiation never raises — availability is checked lazily on first
    call to ``analyze()``.
    """

    def __init__(self, config: Dict[str, Any]):
        self.install_dir: str = (
            config.get("ghidra_install_dir")
            or os.environ.get("GHIDRA_INSTALL_DIR")
            or os.environ.get("GHIDRA_HOME")
            or self._find_ghidra()
        )
        self.project_dir: str = config.get(
            "ghidra_project_dir",
            os.path.join(os.path.expanduser("~"), ".raven", "ghidra_projects"),
        )
        self.timeout: int = int(config.get("ghidra_timeout", 300))
        self.scripts_dir: str = config.get("ghidra_scripts_dir", _SKILL_SCRIPTS_DIR)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, binary_path: str) -> GhidraResult:
        """Run Ghidra headless analysis on *binary_path*."""
        start = time.time()
        binary_path = os.path.realpath(binary_path)

        if not os.path.isfile(binary_path):
            return GhidraResult(
                success=False,
                binary_path=binary_path,
                error=f"Binary not found: {binary_path}",
            )

        headless = self._headless_binary()
        if not headless:
            return GhidraResult(
                success=False,
                binary_path=binary_path,
                error=(
                    "analyzeHeadless not found. Install Ghidra and set "
                    "GHIDRA_INSTALL_DIR, or run: brew install --cask ghidra"
                ),
            )

        if not os.path.isdir(self.scripts_dir):
            return GhidraResult(
                success=False,
                binary_path=binary_path,
                error=(
                    f"Ghidra script dir not found: {self.scripts_dir}. "
                    "Install the ghidra-headless skill."
                ),
            )

        try:
            return self._run_headless(binary_path, headless, start)
        except Exception as exc:
            return GhidraResult(
                success=False,
                binary_path=binary_path,
                error=str(exc),
                execution_time=round(time.time() - start, 3),
            )

    # ------------------------------------------------------------------
    # Internal: headless binary resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _find_ghidra() -> str:
        """Search common paths for a Ghidra installation."""
        for base in _GHIDRA_SEARCH_PATHS:
            if not base:
                continue
            candidate = os.path.join(base, "support", "analyzeHeadless")
            if os.path.isfile(candidate):
                return base
        return ""

    def _headless_binary(self) -> str:
        """Return path to analyzeHeadless, or empty string if not found."""
        if not self.install_dir:
            return ""
        candidate = os.path.join(self.install_dir, "support", "analyzeHeadless")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
        return ""

    # ------------------------------------------------------------------
    # Internal: subprocess execution
    # ------------------------------------------------------------------

    def _run_headless(
        self, binary_path: str, headless: str, start: float
    ) -> GhidraResult:
        binary_name = os.path.basename(binary_path).replace(".", "_")
        project_name = f"raven_{binary_name}_{os.getpid()}"

        with tempfile.TemporaryDirectory(prefix="raven_ghidra_") as output_dir:
            cmd = [
                headless,
                output_dir,          # project location (temp)
                project_name,
                "-import", binary_path,
                "-scriptPath", self.scripts_dir,
                "-postScript", "ExportFunctions.java",
                "-postScript", "ExportStrings.java",
                "-postScript", "ExportSymbols.java",
                "-postScript", "ExportDecompiled.java",
                "-deleteProject",
                "-analysisTimeoutPerFile", str(self.timeout),
                "-log", os.path.join(output_dir, "ghidra.log"),
            ]

            env = {**os.environ, "GHIDRA_OUTPUT_DIR": output_dir}

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 60,
                env=env,
            )

            if proc.returncode not in (0, 1):
                log_snippet = (proc.stderr or proc.stdout or "")[-500:]
                return GhidraResult(
                    success=False,
                    binary_path=binary_path,
                    error=f"analyzeHeadless exited {proc.returncode}: {log_snippet}",
                    execution_time=round(time.time() - start, 3),
                )

            functions_data = self._load_json(output_dir, binary_name, "_functions.json")
            strings_data   = self._load_json(output_dir, binary_name, "_strings.json")
            symbols_data   = self._load_json(output_dir, binary_name, "_symbols.json")
            decompiled_c   = self._load_text(output_dir, binary_name, "_decompiled.c")

            functions  = functions_data.get("functions", [])
            architecture = functions_data.get("architecture", "unknown")
            strings    = [s.get("value", "") for s in strings_data.get("strings", [])]
            imports    = [
                sym.get("name", "")
                for sym in symbols_data.get("symbols", [])
                if sym.get("type") in ("Function", "ExternalFunction")
                and sym.get("isExternal", False)
            ]
            suspicious = self._flag_suspicious(functions)
            decompiled = self._extract_decompiled_snippets(
                decompiled_c, [s.name for s in suspicious]
            )

        return GhidraResult(
            success=True,
            binary_path=binary_path,
            architecture=architecture,
            function_count=len(functions),
            functions=functions,
            strings=[s for s in strings if s][:200],
            imports=imports[:100],
            suspicious=[s.__dict__ for s in suspicious],
            decompiled=decompiled,
            execution_time=round(time.time() - start, 3),
        )

    # ------------------------------------------------------------------
    # Internal: output parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _load_json(output_dir: str, binary_name: str, suffix: str) -> Dict[str, Any]:
        path = os.path.join(output_dir, binary_name + suffix)
        if not os.path.isfile(path):
            return {}
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}

    @staticmethod
    def _load_text(output_dir: str, binary_name: str, suffix: str) -> str:
        path = os.path.join(output_dir, binary_name + suffix)
        if not os.path.isfile(path):
            return ""
        try:
            with open(path) as f:
                return f.read()
        except Exception:
            return ""

    def _flag_suspicious(
        self, functions: List[Dict[str, Any]]
    ) -> List[SuspiciousFunction]:
        """Flag functions whose names or called functions match risky API patterns.

        Checks both the function name itself (for imported symbols) and its
        ``calls`` list (callers of risky functions get flagged too).
        """
        suspicious: List[SuspiciousFunction] = []
        for func in functions:
            name = func.get("name", "")
            calls: List[str] = func.get("calls", [])
            risky: List[str] = []

            if name in _RISKY_CALLS:
                risky.append(name)
            for called in calls:
                if called in _RISKY_CALLS:
                    risky.append(called)

            if risky:
                suspicious.append(
                    SuspiciousFunction(
                        name=name,
                        address=func.get("address", ""),
                        risky_calls=list(dict.fromkeys(risky)),
                    )
                )
        return suspicious

    @staticmethod
    def _extract_decompiled_snippets(
        decompiled_c: str,
        func_names: List[str],
        max_lines: int = 60,
    ) -> Dict[str, str]:
        """Extract decompiled C blocks for functions in *func_names*."""
        if not decompiled_c or not func_names:
            return {}
        snippets: Dict[str, str] = {}
        lines = decompiled_c.splitlines()
        for name in func_names:
            # Find the function definition line
            start_idx: Optional[int] = None
            for i, line in enumerate(lines):
                if name in line and "{" in line:
                    start_idx = i
                    break
            if start_idx is None:
                continue
            # Collect up to max_lines or closing brace
            block: List[str] = []
            depth = 0
            for line in lines[start_idx: start_idx + max_lines]:
                block.append(line)
                depth += line.count("{") - line.count("}")
                if depth <= 0 and len(block) > 1:
                    break
            snippets[name] = "\n".join(block)
        return snippets
