"""Nuclei vulnerability scanner integration (MIT license, ProjectDiscovery)

Requires the `nuclei` binary in PATH and optionally a templates directory.
No additional pip dependencies — subprocess only.
"""

from typing import List, Dict, Any
from dataclasses import dataclass
import subprocess
import json
import os
import time


@dataclass
class NucleiResult:
    """Result of a Nuclei scan"""

    success: bool
    target: str
    findings: List[Dict[str, Any]]
    execution_time: float
    timestamp: float


class NucleiScanner:
    """Wrap the Nuclei CLI for template-based vulnerability scanning.

    Outputs one JSON object per line (-json flag); each finding is parsed
    and returned as a structured list consumable by EnvironmentState.
    """

    def __init__(self, config: Dict[str, Any]):
        self.binary = config.get("nuclei_binary", "nuclei")
        self.templates_dir = config.get("nuclei_templates", "")
        self.timeout = int(config.get("nuclei_timeout", 300))

    def _binary_available(self) -> bool:
        return bool(
            subprocess.run(["which", self.binary], capture_output=True).returncode == 0
        )

    def scan(
        self,
        target: str,
        severity: str = "medium,high,critical",
        tags: str = "",
    ) -> NucleiResult:
        """Run nuclei against *target*.

        Args:
            target:   IP, hostname, or URL.
            severity: Comma-separated nuclei severity filter.
            tags:     Comma-separated template tags (e.g. "cve,rce").
        """
        start = time.time()

        if not self._binary_available():
            return NucleiResult(
                success=False,
                target=target,
                findings=[],
                execution_time=0.0,
                timestamp=start,
            )

        cmd = [
            self.binary,
            "-target",
            target,
            "-severity",
            severity,
            "-json",
            "-silent",
            "-timeout",
            str(self.timeout),
        ]
        if self.templates_dir:
            cmd += ["-t", os.path.realpath(self.templates_dir)]
        if tags:
            cmd += ["-tags", tags]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30,
            )
            findings: List[Dict[str, Any]] = []
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return NucleiResult(
                success=True,
                target=target,
                findings=findings,
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )
        except subprocess.TimeoutExpired:
            return NucleiResult(
                success=False,
                target=target,
                findings=[],
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )
        except Exception as e:
            return NucleiResult(
                success=False,
                target=target,
                findings=[{"error": str(e)}],
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )

    def scan_cves(self, target: str) -> NucleiResult:
        """Scan using CVE templates only."""
        return self.scan(target, tags="cve")

    def scan_exposures(self, target: str) -> NucleiResult:
        """Scan for misconfigurations and exposures."""
        return self.scan(target, tags="exposure,config,misconfig")
